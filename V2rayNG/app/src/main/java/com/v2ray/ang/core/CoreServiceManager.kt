package com.v2ray.ang.core

import android.app.Activity
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.content.ContextCompat
import com.v2ray.ang.AppConfig
import com.v2ray.ang.contracts.IDialerService
import com.v2ray.ang.contracts.ServiceControl
import com.v2ray.ang.dto.ConnectionTestResult
import com.v2ray.ang.dto.OutboundTrafficStat
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.BrowserDialerMode
import com.v2ray.ang.extension.delay
import com.v2ray.ang.extension.isNotNullEmpty
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.NotificationManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import com.v2ray.ang.helper.MessageHelper
import com.v2ray.ang.service.DialerNativeService
import com.v2ray.ang.service.DialerWebviewService
import com.v2ray.ang.service.NetworkMonitor
import com.v2ray.ang.service.RealPingWorkerService
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.ProcessFinder
import java.lang.ref.SoftReference
import java.net.InetSocketAddress

object CoreServiceManager {

    private val coreController: CoreController = CoreNativeManager.newCoreController(CoreCallback())
    private val mMsgReceive = ReceiveMessageHandler()
    private var currentConfig: ProfileItem? = null
    private var processFinder: XrayProcessFinder? = null
    private var browserDialer: IDialerService? = null
    private var networkMonitor: NetworkMonitor? = null
    private val connectionTestScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var isReloading = false

    /** Tun descriptor the core was started with, null in the proxy only and root run modes. */
    private var currentVpnInterface: ParcelFileDescriptor? = null

    var serviceControl: SoftReference<ServiceControl>? = null
        set(value) {
            field = value
            val service = value?.get()?.getService()
            CoreNativeManager.initCoreEnv(service)
            if (service != null && processFinder == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                processFinder = XrayProcessFinder(service)
                coreController.registerProcessFinder(processFinder)
            }
        }

    /**
     * Checks if the V2Ray service is running.
     * @return True if the service is running, false otherwise.
     */
    fun isRunning() = coreController.isRunning

    /**
     * Gets the name of the currently running server.
     * @return The name of the running server.
     */
    fun getRunningServerName() = currentConfig?.remarks.orEmpty()

    /**
     * Refer to the official documentation for [registerReceiver](https://developer.android.com/reference/androidx/core/content/ContextCompat#registerReceiver(android.content.Context,android.content.BroadcastReceiver,android.content.IntentFilter,int):
     * `registerReceiver(Context, BroadcastReceiver, IntentFilter, int)`.
     * Starts the V2Ray core service.
     */
    fun startCoreLoop(vpnInterface: ParcelFileDescriptor?): Boolean {
        if (isRunning()) {
            LogUtil.w(AppConfig.TAG, "StartCore-Manager: Core already running")
            return false
        }

        val service = getService()
        if (service == null) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Service is null")
            return false
        }

        try {
            doStartCoreLoop(service, vpnInterface)
            return true
        } catch (e: Exception) {
            val message = e.message?.takeUnless { it.isBlank() } ?: e.javaClass.simpleName
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: $message", e)
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_FAILURE, message)
            NotificationManager.cancelNotification()
            return false
        }
    }

    @Throws(Exception::class)
    private fun doStartCoreLoop(service: Service, vpnInterface: ParcelFileDescriptor?) {
        val mFilter = IntentFilter(AppConfig.BROADCAST_ACTION_SERVICE)
        mFilter.addAction(Intent.ACTION_SCREEN_ON)
        mFilter.addAction(Intent.ACTION_SCREEN_OFF)
        mFilter.addAction(Intent.ACTION_USER_PRESENT)
        ContextCompat.registerReceiver(service, mMsgReceive, mFilter, Utils.receiverFlags())

        currentVpnInterface = vpnInterface
        launchCore(service, vpnInterface)
        startNetworkMonitor(service)
    }

    @Throws(Exception::class)
    private fun launchCore(service: Service, vpnInterface: ParcelFileDescriptor?, isReload: Boolean = false) {
        val guid = MmkvManager.getSelectServer() ?: error("No server selected")
        val config = MmkvManager.decodeServerConfig(guid) ?: error("Failed to decode server config")

        LogUtil.i(AppConfig.TAG, "StartCore-Manager: Starting core loop for ${config.remarks}")
        val result = CoreConfigManager.getV2rayConfig(service, guid)
        LogUtil.d(AppConfig.TAG, result.content)
        if (!result.status) {
            error(result.errorMessage.ifBlank { "Failed to get V2Ray config" })
        }

        currentConfig = config
        var tunFd = vpnInterface?.fd ?: 0
        val dialerMode = BrowserDialerMode.from(config.browserDialerMode)
        val dialerAddr = if (dialerMode != null) {
            "127.0.0.1:${Utils.findRandomFreePort()}"
        } else {
            ""
        }
        if (SettingsManager.isUsingHevTun()) {
            tunFd = 0
        }

        NotificationManager.showNotification(currentConfig)
        if (dialerAddr.isNotNullEmpty()) {
            CoreNativeManager.reconcileBrowserDialer(dialerAddr)
        }
        coreController.startLoop(result.content, tunFd)

        if (!isRunning()) {
            error("Core failed to start")
        }

        if (browserDialer != null) {
            browserDialer!!.stop()
            browserDialer = null
        }
        when (dialerMode) {
            BrowserDialerMode.OKHTTP -> {
                browserDialer = DialerNativeService()
                browserDialer!!.start(service, dialerAddr)
            }

            BrowserDialerMode.WEBVIEW -> {
                browserDialer = DialerWebviewService()
                browserDialer!!.start(service, dialerAddr)
            }

            else -> {}
        }

        if (!isReload) {
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_SUCCESS, "")
        }
        NotificationManager.startSpeedNotification()

        if (MmkvManager.isAutoFailoverEnabled()) {
            startAutoFailoverMonitor()
        }
        LogUtil.i(AppConfig.TAG, "StartCore-Manager: Core started successfully")
    }

    /**
     * Stops the V2Ray core service.
     * Unregisters broadcast receivers, stops notifications, and shuts down plugins.
     * @return True if the core was stopped successfully, false otherwise.
     */
    fun stopCoreLoop(): Boolean {
        connectionTestScope.coroutineContext.cancelChildren()
        val service = getService() ?: return false

        networkMonitor?.unregister()
        networkMonitor = null
        currentVpnInterface = null

        // During an automatic switch the core restarts in place (see
        // switchToAutoFailoverCandidate), so keep the monitor alive then.
        if (!autoFailoverSwitching) {
            stopAutoFailoverMonitor()
        }

        if (isRunning()) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    coreController.stopLoop()
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to stop V2Ray loop", e)
                }
            }
        }

        // Close existing browser dialer
        CoreNativeManager.reconcileBrowserDialer("")
        if (browserDialer != null) {
            browserDialer!!.stop()
            browserDialer = null
        }

        MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_STOP_SUCCESS, "")
        NotificationManager.cancelNotification()

        try {
            service.unregisterReceiver(mMsgReceive)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to unregister receiver", e)
        }

        return true
    }

    /**
     * Subscribes to upstream network changes for whichever run mode is active.
     * All three services share this manager, so the tunnel recovers from a handover in proxy only
     * and root mode as well, not just behind the VPN interface.
     */
    private fun startNetworkMonitor(service: Service) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return
        if (networkMonitor != null) return

        val connectivity = service.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        networkMonitor = NetworkMonitor(
            connectivity = connectivity,
            onUnderlyingNetworksChanged = { networks -> serviceControl?.get()?.setUnderlyingNetworks(networks) },
            onHandover = { reloadCore() },
        ).also { it.register() }
    }

    /**
     * Restarts the core in place after the upstream network changed: the service, the notification
     * and the VPN interface all stay up, so nothing of this is visible.
     *
     * The config is rebuilt on purpose, outbound server domains are resolved while building it and
     * an address resolved on a network that is gone can be unusable on the new one.
     *
     * @return True if the core is running again.
     */
    private fun reloadCore(): Boolean {
        if (isReloading) return false
        val service = getService() ?: return false
        if (!isRunning()) return false

        return try {
            val tunFd = currentVpnInterface

            isReloading = true
            connectionTestScope.coroutineContext.cancelChildren()
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Core reload start...")

            coreController.stopLoop()
            launchCore(service, tunFd, isReload = true)

            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Core reload finished")
            true
        } catch (e: Exception) {
            val message = e.message?.takeUnless { it.isBlank() } ?: e.javaClass.simpleName
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to reload core: $message", e)
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_STATE_START_FAILURE, message)
            false
        } finally {
            isReloading = false
        }
    }

    // ------------------------------------------------------------
    // Auto Failover (ported from the 2.2.6 custom fork)
    //
    // Service-level monitor: the UI is not involved, so closing the
    // app does not stop monitoring while the core stays alive.
    // A switch restarts the core loop in place (the same pattern as
    // reloadCore): the service and the VPN interface stay up, only
    // the selected server changes. The old fork's full service
    // teardown wait is gone with it: this core no longer exposes
    // stop-completion signals, and an in-place restart does not
    // need them.
    // ------------------------------------------------------------

    private const val AUTO_FAILOVER_INTERVAL_MS = 15_000L
    private const val AUTO_FAILOVER_FAILURE_THRESHOLD = 3
    private const val AUTO_FAILOVER_DEGRADATION_THRESHOLD = 3

    // Switch only when the candidate is meaningfully better.
    private const val AUTO_FAILOVER_MIN_DELAY_IMPROVEMENT_MS = 30L
    private const val AUTO_FAILOVER_MIN_DELAY_IMPROVEMENT_RATIO = 0.20

    // Prevent rapid server hopping.
    private const val AUTO_FAILOVER_COOLDOWN_MS = 60_000L

    // Conservative severe-latency threshold.
    private const val AUTO_FAILOVER_SEVERE_DELAY_MS = 1200L

    private var autoFailoverJob: Job? = null
    private var autoFailoverCheckRunning = false
    private var autoFailoverSwitching = false

    private var autoFailoverConsecutiveFailures = 0
    private var autoFailoverConsecutiveBadDelays = 0
    private var autoFailoverLastSwitchAt = 0L

    fun enableAutoFailover() {
        MmkvManager.setAutoFailoverEnabled(true)
        startAutoFailoverMonitor()
    }

    fun disableAutoFailover() {
        MmkvManager.setAutoFailoverEnabled(false)
        stopAutoFailoverMonitor()
        autoFailoverConsecutiveFailures = 0
        autoFailoverConsecutiveBadDelays = 0
    }

    /**
     * Starts the service-level Auto Failover monitor.
     *
     * The Activity/ViewModel is not involved, so closing the UI does not
     * stop monitoring while the core service remains alive.
     */
    private fun startAutoFailoverMonitor() {
        if (!MmkvManager.isAutoFailoverEnabled()) {
            return
        }

        if (autoFailoverJob?.isActive == true) {
            return
        }

        autoFailoverJob = CoroutineScope(Dispatchers.IO).launch {
            LogUtil.i(
                AppConfig.TAG,
                "AutoFailover: monitor started"
            )

            while (
                isActive &&
                coreController.isRunning &&
                MmkvManager.isAutoFailoverEnabled()
            ) {
                try {
                    performAutoFailoverHealthCheck()
                } catch (e: Exception) {
                    LogUtil.e(
                        AppConfig.TAG,
                        "AutoFailover: health check failed",
                        e
                    )
                }

                delay(AUTO_FAILOVER_INTERVAL_MS)
            }

            LogUtil.i(
                AppConfig.TAG,
                "AutoFailover: monitor stopped"
            )
        }
    }

    private fun stopAutoFailoverMonitor() {
        autoFailoverJob?.cancel()
        autoFailoverJob = null

        autoFailoverCheckRunning = false
        autoFailoverConsecutiveFailures = 0
        autoFailoverConsecutiveBadDelays = 0
    }

    /**
     * Measures the active connection through the running core.
     */
    private suspend fun measureCurrentConnection(): Long {
        var time = -1L

        try {
            time = coreController.measureDelay(
                SettingsManager.getDelayTestUrl()
            )
        } catch (e: Exception) {
            LogUtil.d(
                AppConfig.TAG,
                "AutoFailover: primary health check failed: ${e.message}"
            )
        }

        if (time < 0L) {
            try {
                time = coreController.measureDelay(
                    SettingsManager.getDelayTestUrl(true)
                )
            } catch (e: Exception) {
                LogUtil.d(
                    AppConfig.TAG,
                    "AutoFailover: fallback health check failed: ${e.message}"
                )
            }
        }

        return time
    }

    private suspend fun performAutoFailoverHealthCheck() {
        if (
            autoFailoverCheckRunning ||
            autoFailoverSwitching ||
            !coreController.isRunning ||
            !MmkvManager.isAutoFailoverEnabled()
        ) {
            return
        }

        autoFailoverCheckRunning = true

        try {
            val now = System.currentTimeMillis()

            if (
                now - autoFailoverLastSwitchAt <
                AUTO_FAILOVER_COOLDOWN_MS
            ) {
                return
            }

            val delay = measureCurrentConnection()

            if (delay < 0L) {
                autoFailoverConsecutiveFailures++
                autoFailoverConsecutiveBadDelays = 0

                LogUtil.w(
                    AppConfig.TAG,
                    "AutoFailover: connection failure " +
                        "$autoFailoverConsecutiveFailures/" +
                        "$AUTO_FAILOVER_FAILURE_THRESHOLD"
                )

                if (
                    autoFailoverConsecutiveFailures >=
                    AUTO_FAILOVER_FAILURE_THRESHOLD
                ) {
                    evaluateAutoFailoverCandidates()
                }

                return
            }

            autoFailoverConsecutiveFailures = 0

            if (delay >= AUTO_FAILOVER_SEVERE_DELAY_MS) {
                autoFailoverConsecutiveBadDelays++

                LogUtil.w(
                    AppConfig.TAG,
                    "AutoFailover: severe latency ${delay}ms " +
                        "($autoFailoverConsecutiveBadDelays/" +
                        "$AUTO_FAILOVER_DEGRADATION_THRESHOLD)"
                )

                if (
                    autoFailoverConsecutiveBadDelays >=
                    AUTO_FAILOVER_DEGRADATION_THRESHOLD
                ) {
                    evaluateAutoFailoverCandidates()
                }
            } else {
                autoFailoverConsecutiveBadDelays = 0
            }
        } finally {
            autoFailoverCheckRunning = false
        }
    }

    /**
     * Tests all other configured servers with the application's existing
     * RealPingWorkerService.
     */
    private suspend fun evaluateAutoFailoverCandidates() {
        if (
            autoFailoverSwitching ||
            !MmkvManager.isAutoFailoverEnabled() ||
            !coreController.isRunning
        ) {
            return
        }

        val currentGuid = MmkvManager.getSelectServer()
            ?: return

        val allGuids = MmkvManager
            .decodeAllServerList()
            .distinct()
            .filter {
                it.isNotBlank() && it != currentGuid
            }

        if (allGuids.isEmpty()) {
            LogUtil.w(
                AppConfig.TAG,
                "AutoFailover: no alternative servers"
            )
            return
        }

        LogUtil.i(
            AppConfig.TAG,
            "AutoFailover: testing ${allGuids.size} alternatives"
        )

        MmkvManager.clearAllTestDelayResults(allGuids)

        val bestResult = CompletableDeferred<Pair<String, Long>?>()

        val context = getService()?.applicationContext
        if (context == null) {
            return
        }

        val worker = RealPingWorkerService(
            context,
            allGuids
        ) { event ->
            when (event) {
                is RealPingEvent.Result -> {
                    // RealPingWorkerService itself does not persist results.
                    MmkvManager.encodeServerTestDelayMillis(
                        event.guid,
                        event.delayMillis
                    )
                }

                is RealPingEvent.Finish -> {
                    if (!bestResult.isCompleted) {
                        val best = allGuids
                            .mapNotNull { guid ->
                                val delay =
                                    MmkvManager
                                        .decodeServerAffiliationInfo(guid)
                                        ?.testDelayMillis
                                        ?: 0L

                                if (delay > 0L) {
                                    guid to delay
                                } else {
                                    null
                                }
                            }
                            .minByOrNull { it.second }

                        bestResult.complete(best)
                    }
                }

                is RealPingEvent.Progress -> {
                    // No UI dependency.
                }
            }
        }

        try {
            worker.start()

            val result = bestResult.await()

            if (result == null) {
                LogUtil.w(
                    AppConfig.TAG,
                    "AutoFailover: no working candidate found"
                )

                autoFailoverConsecutiveFailures = 0
                autoFailoverConsecutiveBadDelays = 0
                return
            }

            val candidateGuid = result.first
            val candidateDelay = result.second

            // One fresh measurement of the current connection immediately
            // before deciding whether a switch is actually justified.
            val currentDelay = measureCurrentConnection()

            if (currentDelay >= 0L) {
                val absoluteBetter =
                    currentDelay - candidateDelay >=
                        AUTO_FAILOVER_MIN_DELAY_IMPROVEMENT_MS

                val ratioBetter =
                    candidateDelay <=
                        currentDelay *
                        (1.0 - AUTO_FAILOVER_MIN_DELAY_IMPROVEMENT_RATIO)

                if (!absoluteBetter && !ratioBetter) {
                    LogUtil.i(
                        AppConfig.TAG,
                        "AutoFailover: candidate not meaningfully better " +
                            "(current=${currentDelay}ms, " +
                            "candidate=${candidateDelay}ms)"
                    )

                    autoFailoverConsecutiveFailures = 0
                    autoFailoverConsecutiveBadDelays = 0
                    return
                }
            }

            switchToAutoFailoverCandidate(
                candidateGuid,
                candidateDelay
            )
        } finally {
            worker.cancel()
        }
    }

    /**
     * Performs the actual automatic switch.
     *
     * Unlike the old fork, this does not tear the whole service down:
     * it restarts the core loop in place (the reloadCore pattern), so
     * the service and the VPN interface stay up. If starting the
     * candidate fails, the previous server is restored.
     */
    private suspend fun switchToAutoFailoverCandidate(
        candidateGuid: String,
        candidateDelay: Long
    ) {
        if (
            autoFailoverSwitching ||
            !MmkvManager.isAutoFailoverEnabled() ||
            isReloading
        ) {
            return
        }

        if (candidateGuid == MmkvManager.getSelectServer()) {
            return
        }

        val service = getService() ?: return
        val previousGuid = MmkvManager.getSelectServer()

        autoFailoverSwitching = true

        try {
            LogUtil.i(
                AppConfig.TAG,
                "AutoFailover: switching to $candidateGuid " +
                    "(${candidateDelay}ms)"
            )

            autoFailoverConsecutiveFailures = 0
            autoFailoverConsecutiveBadDelays = 0
            autoFailoverLastSwitchAt = System.currentTimeMillis()

            MmkvManager.setSelectServer(candidateGuid)

            try {
                coreController.stopLoop()
                launchCore(service, currentVpnInterface, isReload = true)
            } catch (e: Exception) {
                LogUtil.e(
                    AppConfig.TAG,
                    "AutoFailover: failed to start candidate, restoring previous server",
                    e
                )
                if (previousGuid != null) {
                    MmkvManager.setSelectServer(previousGuid)
                    try {
                        if (coreController.isRunning) {
                            coreController.stopLoop()
                        }
                        launchCore(service, currentVpnInterface, isReload = true)
                    } catch (e2: Exception) {
                        LogUtil.e(
                            AppConfig.TAG,
                            "AutoFailover: failed to restore previous server",
                            e2
                        )
                    }
                }
            }
        } finally {
            autoFailoverSwitching = false
        }
    }

    /**
     * Queries and resets all outbound traffic counters in one core call.
     * Go side format: tag,direction,value;tag,direction,value;
     */
    fun queryAllOutboundTrafficStats(): List<OutboundTrafficStat> {
        // The stats manager is gone once the core stops, querying it then reaches into freed state.
        if (!isRunning()) return emptyList()

        val payload = coreController.queryAllOutboundTrafficStats()

        val result = ArrayList<OutboundTrafficStat>()

        payload.split(';').forEach { entry ->
            if (entry.isBlank()) return@forEach

            val parts = entry.split(',', limit = 3)
            if (parts.size != 3) return@forEach

            val value = parts[2].toLongOrNull() ?: return@forEach

            result.add(
                OutboundTrafficStat(
                    tag = parts[0],
                    direction = parts[1],
                    value = value,
                )
            )
        }
//        LogUtil.d(AppConfig.TAG, "Queried outbound traffic stats: $result")
        return result
    }

    /**
     * Measures the connection delay for the current V2Ray configuration.
     * Tests with primary URL first, then falls back to alternative URL if needed.
     * Also fetches remote IP information if the delay test was successful.
     */
    private fun measureV2rayDelay(requestId: String) {
        val service = getService() ?: return
        if (!isRunning() || isReloading) {
            MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
            return
        }

        connectionTestScope.coroutineContext.cancelChildren()
        connectionTestScope.launch {
            var time = -1L
            var errorStr = ""

            try {
                time = coreController.measureDelay(SettingsManager.getDelayTestUrl())
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to measure delay", e)
                errorStr = e.message?.substringAfter("\":").orEmpty()
            }
            if (time == -1L) {
                ensureActive()
                try {
                    time = coreController.measureDelay(SettingsManager.getDelayTestUrl(true))
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to measure delay", e)
                    errorStr = e.message?.substringAfter("\":").orEmpty()
                }
            }

            ensureActive()
            val endpoint = if (time >= 0) SpeedtestManager.getRemoteIPInfo() else null
            val result = ConnectionTestResult(
                delayMillis = time,
                errorMessage = errorStr,
                country = endpoint?.country,
                ipAddress = endpoint?.ipAddress,
            )
            withContext(Dispatchers.Main.immediate) {
                if (isRunning()) {
                    MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_RESULT, result, requestId)
                } else {
                    MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
                }
            }
        }.invokeOnCompletion { cause ->
            if (cause is CancellationException) {
                MessageHelper.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
            }
        }
    }

    /**
     * Gets the current service instance.
     * @return The current service instance, or null if not available.
     */
    private fun getService(): Service? {
        return serviceControl?.get()?.getService()
    }

    /**
     * Core callback handler implementation for handling V2Ray core events.
     * Handles startup, shutdown, socket protection, and status emission.
     */
    private class CoreCallback : CoreCallbackHandler {
        /**
         * Called when V2Ray core starts up.
         * @return 0 for success, any other value for failure.
         */
        override fun startup(): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: CoreCallback startup")
            return 0
        }

        /**
         * Called when V2Ray core shuts down.
         * @return 0 for success, any other value for failure.
         */
        override fun shutdown(): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: CoreCallback shutdown")
            return 0
        }

        /**
         * Called when V2Ray core emits status information.
         * @param l Status code.
         * @param s Status message.
         * @return Always returns 0.
         */
        override fun onEmitStatus(l: Long, s: String?): Long {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: CoreCallback onEmitStatus $s")
            return 0
        }
    }

    /**
     * Process finder implementation for Xray core.
     * Uses ConnectivityManager to find the owning UID of a connection based on network parameters.
     */
    private class XrayProcessFinder(context: Context) : ProcessFinder {
        private val cm: ConnectivityManager? = context.getSystemService(ConnectivityManager::class.java)

        override fun findProcessByConnection(network: String, srcIP: String, srcPort: Long, destIP: String, destPort: Long): Long {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1L
            if (cm == null) return -1L
            val proto = when (network) {
                "tcp" -> OsConstants.IPPROTO_TCP
                "udp" -> OsConstants.IPPROTO_UDP
                else -> return -1L
            }

            if (destIP.isBlank() || destPort == 0L) {
                LogUtil.d(AppConfig.TAG, "ProcessFinder: Find $network connection from $srcIP:$srcPort to :$destPort, (no dest)")
                return -1L
            }

            return try {
                val uid = cm.getConnectionOwnerUid(
                    proto,
                    InetSocketAddress(srcIP, srcPort.toInt()),
                    InetSocketAddress(destIP, destPort.toInt())
                ).toLong()
                LogUtil.d(AppConfig.TAG, "ProcessFinder: Find $network connection from $srcIP:$srcPort to $destIP:$destPort, uid=$uid")
                //LogUtil.d(AppConfig.TAG, "ProcessFinder: Find $network connection from $srcIP:$srcPort to $destIP:$destPort, uid=$uid,${PackageUidResolver.uidToPackageName(uid.toString())}")

                uid
            } catch (_: Exception) {
                -1L
            }
        }
    }

    /**
     * Broadcast receiver for handling messages sent to the service.
     * Handles registration, service control, and screen events.
     */
    private class ReceiveMessageHandler : BroadcastReceiver() {
        /**
         * Handles received broadcast messages.
         * Processes service control messages and screen state changes.
         * @param ctx The context in which the receiver is running.
         * @param intent The intent being received.
         */
        override fun onReceive(ctx: Context?, intent: Intent?) {
            val serviceControl = serviceControl?.get() ?: return
            when (intent?.getIntExtra("key", 0)) {
                AppConfig.MSG_REGISTER_CLIENT -> {
                    if (isRunning()) {
                        MessageHelper.sendMsg2UI(serviceControl.getService(), AppConfig.MSG_STATE_RUNNING, "")
                    } else {
                        MessageHelper.sendMsg2UI(serviceControl.getService(), AppConfig.MSG_STATE_NOT_RUNNING, "")
                    }
                }

                AppConfig.MSG_UNREGISTER_CLIENT -> {
                    // nothing to do
                }

                AppConfig.MSG_STATE_START -> {
                    // nothing to do
                }

                AppConfig.MSG_STATE_STOP -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Stop service")
                    serviceControl.stopService()
                }

                AppConfig.MSG_STATE_RESTART -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Restart service")
                    // The UI and daemon run in separate processes, so acknowledge the active
                    // daemon before stopping it instead of relying on possibly stale UI state.
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK

                    val pendingResult = goAsync()
                    CoroutineScope(Dispatchers.Default).launch {
                        try {
                            serviceControl.stopService()
                            delay(500L)
                            LauncherManager.startService(serviceControl.getService())
                        } finally {
                            pendingResult.finish()
                        }
                    }
                }

                AppConfig.MSG_MEASURE_DELAY -> {
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK
                    measureV2rayDelay(intent.getStringExtra("content").orEmpty())
                }
            }

            when (intent?.action) {
                Intent.ACTION_SCREEN_OFF -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Screen off")
                    NotificationManager.stopSpeedNotification()
                }

                Intent.ACTION_SCREEN_ON -> {
                    LogUtil.i(AppConfig.TAG, "StartCore-Manager: Screen on")
                    NotificationManager.startSpeedNotification()
                }
            }
        }
    }
}
