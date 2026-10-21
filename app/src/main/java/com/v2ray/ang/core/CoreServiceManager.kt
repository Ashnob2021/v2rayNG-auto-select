package com.v2ray.ang.core

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
import com.v2ray.ang.R
import com.v2ray.ang.contracts.ServiceControl
import com.v2ray.ang.dto.OutboundTrafficStat
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.extension.isComplexType
import com.v2ray.ang.extension.toast
import com.v2ray.ang.extension.toastError
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.NotificationManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import com.v2ray.ang.root.RootManager
import com.v2ray.ang.service.CoreProxyOnlyService
import com.v2ray.ang.service.CoreRootService
import com.v2ray.ang.service.CoreVpnService
import com.v2ray.ang.service.DialerNativeService
import com.v2ray.ang.service.RealPingWorkerService
import com.v2ray.ang.service.DialerWebviewService
import com.v2ray.ang.service.IDialerService
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.MessageUtil
import com.v2ray.ang.util.Utils
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
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
    var serviceControl: SoftReference<ServiceControl>? = null
        set(value) {
            field = value
            val service = value?.get()?.getService()
            // The core environment must be initialized when the main
            // service binds, otherwise the core cannot locate the
            // geodata files (geosite.dat / geoip.dat) and building the
            // config fails. initCoreEnv is idempotent.
            CoreNativeManager.initCoreEnv(service)
            if (service != null && processFinder == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                processFinder = XrayProcessFinder(service)
                coreController.registerProcessFinder(processFinder)
            }
        }
    private const val TRAFFIC_STATS_INTERVAL_MS = 3000L

    private var trafficStatsJob: Job? = null
    private var latestTrafficStats: List<OutboundTrafficStat> = emptyList()

    // ------------------------------------------------------------
    // Auto Failover
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
    private const val AUTO_FAILOVER_STOP_TIMEOUT_MS = 7_000L

    private var autoFailoverJob: Job? = null
    private var autoFailoverCheckRunning = false
    private var autoFailoverSwitching = false

    private var autoFailoverConsecutiveFailures = 0
    private var autoFailoverConsecutiveBadDelays = 0
    private var autoFailoverLastSwitchAt = 0L

    /**
     * Completes only after coreController.stopLoop() has actually returned.
     */
    private var coreStopCompletion: CompletableDeferred<Unit>? = null

    /**
     * Completes after the Android service itself has finished its teardown.
     *
     * For VPN mode this is important because VpnService may still own the
     * TUN interface even after the V2Ray core has stopped.
     */
    private var serviceStopCompletion: CompletableDeferred<Unit>? = null

fun startVServiceFromToggle(context: Context): Boolean {
        if (MmkvManager.getSelectServer().isNullOrEmpty()) {
            context.toast(R.string.app_tile_first_use)
            return false
        }
        try {
            startContextService(context)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: ${e.message}", e)
            context.toast(e.message ?: e.javaClass.simpleName)
            return false
        }
        return true
    }

    /**
     * Starts the V2Ray service.
     * @param context The context from which the service is started.
     * @param guid The GUID of the server configuration to use (optional).
     */
    fun startVService(context: Context, guid: String? = null) {

        val startBlock: () -> Unit = {
            LogUtil.i(
                AppConfig.TAG,
                "StartCore-Manager: startVService from " +
                    "${context::class.java.simpleName}"
            )

            if (guid != null) {
                MmkvManager.setSelectServer(guid)
            }

            try {
                startContextService(context)
            } catch (e: Exception) {

                LogUtil.e(
                    AppConfig.TAG,
                    "StartCore-Manager: ${e.message}",
                    e
                )
                context.toast(e.message ?: e.javaClass.simpleName)
            }
        }

        if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
            startBlock()
        } else {
            kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.Main) {
                startBlock()
            }
        }
    }

    /**
     * Stops the V2Ray service.
     * @param context The context from which the service is stopped.
     */
    fun stopVService(context: Context) {
        /*
         * Create the Deferred BEFORE sending the asynchronous broadcast.
         * Otherwise Auto Failover could race with the Service and miss the
         * beginning of the actual teardown.
         */
        prepareStopCompletions()

        //context.toast(R.string.toast_services_stop)
        MessageUtil.sendMsg2Service(context, AppConfig.MSG_STATE_STOP, "")
    }

    /**
     * Checks if the V2Ray service is running.
     * @return True if the service is running, false otherwise.
     */
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

    fun getLatestTrafficStats(): List<OutboundTrafficStat> {
        return latestTrafficStats
    }

    fun isRunning() = coreController.isRunning

    /**
     * Gets the name of the currently running server.
     * @return The name of the running server.
     */
    fun getRunningServerName() = currentConfig?.remarks.orEmpty()

    /**
     * Starts the context service for V2Ray.
     * Chooses between VPN service or Proxy-only service based on user settings.
     * @param context The context from which the service is started.
     * @throws IllegalStateException if the core is already running, no server is selected,
     *   server config cannot be decoded, or server configuration is invalid.
     * @throws Exception if the foreground service fails to start.
     */
    @Throws(Exception::class)
    private fun startContextService(context: Context) {

        if (coreController.isRunning) {
            LogUtil.w(AppConfig.TAG, "StartCore-Manager: Core already running")
            return
        }

        val guid = MmkvManager.getSelectServer()
            ?: run {
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: No server selected")
                error(context.getString(R.string.app_tile_first_use))
            }

        val config = MmkvManager.decodeServerConfig(guid)
            ?: run {
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to decode server config")
                error(context.getString(R.string.toast_config_file_invalid))
            }

        if (!config.configType.isComplexType()
            && !Utils.isValidUrl(config.server)
            && !Utils.isPureIpAddress(config.server.orEmpty())
        ) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Invalid server configuration")
            error(context.getString(R.string.toast_config_file_invalid))
        }

        // refresh socks port when enabled dynamic socks port
        SettingsManager.refreshRuntimeSocksPort()

//        val result = V2rayConfigUtil.getV2rayConfig(context, guid)
//        if (!result.status) error(result.errorMessage.ifBlank { "Failed to get V2Ray config" })

        if (config.insecure == true) {
            context.toastError(R.string.toast_allow_insecure_deprecated)
        }

        if (MmkvManager.decodeSettingsBool(AppConfig.PREF_PROXY_SHARING)) {
            context.toast(R.string.toast_warning_pref_proxysharing_short)
        } else {
            context.toast(R.string.toast_services_start)
        }

        val isRootMode = SettingsManager.isRootMode()
        if (isRootMode && !RootManager.isRootAvailable()) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: root mode requires root but none available")
            error(context.getString(R.string.toast_root_required))
        }

        val intent = if (isRootMode) {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Starting Root service")
            Intent(context.applicationContext, CoreRootService::class.java)
        } else if (SettingsManager.isVpnMode()) {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Starting VPN service")
            Intent(context.applicationContext, CoreVpnService::class.java)
        } else {
            LogUtil.i(AppConfig.TAG, "StartCore-Manager: Starting Proxy service")
            Intent(context.applicationContext, CoreProxyOnlyService::class.java)
        }


        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (e: SecurityException) {
            LogUtil.e(
                AppConfig.TAG,
                "StartCore-Manager: Missing permission to start foreground service",
                e
            )
            throw IllegalStateException(e.message ?: e.javaClass.simpleName, e)
        } catch (e: RuntimeException) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                e.javaClass.name == "android.app.ForegroundServiceStartNotAllowedException"
            ) {
                LogUtil.e(
                    AppConfig.TAG,
                    "StartCore-Manager: Foreground service start not allowed",
                    e
                )
                throw IllegalStateException(e.message ?: e.javaClass.simpleName, e)
            }
            throw e
        }
    }

    /**
     * Refer to the official documentation for [registerReceiver](https://developer.android.com/reference/androidx/core/content/ContextCompat#registerReceiver(android.content.Context,android.content.BroadcastReceiver,android.content.IntentFilter,int):
     * `registerReceiver(Context, BroadcastReceiver, IntentFilter, int)`.
     * Starts the V2Ray core service.
     */
    fun startCoreLoop(vpnInterface: ParcelFileDescriptor?): Boolean {
        if (coreController.isRunning) {
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
            MessageUtil.sendMsg2UI(service, AppConfig.MSG_STATE_START_FAILURE, message)
            NotificationManager.cancelNotification()
            return false
        }
    }

    @Throws(Exception::class)
    private fun doStartCoreLoop(service: Service, vpnInterface: ParcelFileDescriptor?) {
        val guid = MmkvManager.getSelectServer() ?: error("No server selected")
        val config = MmkvManager.decodeServerConfig(guid) ?: error("Failed to decode server config")

        LogUtil.i(AppConfig.TAG, "StartCore-Manager: Starting core loop for ${config.remarks}")
        val result = CoreConfigManager.getV2rayConfig(service, guid)
        LogUtil.d(AppConfig.TAG, result.content)
        if (!result.status) {
            error(result.errorMessage.ifBlank { "Failed to get V2Ray config" })
        }

        val mFilter = IntentFilter(AppConfig.BROADCAST_ACTION_SERVICE)
        mFilter.addAction(Intent.ACTION_SCREEN_ON)
        mFilter.addAction(Intent.ACTION_SCREEN_OFF)
        mFilter.addAction(Intent.ACTION_USER_PRESENT)
        ContextCompat.registerReceiver(service, mMsgReceive, mFilter, Utils.receiverFlags())

        currentConfig = config
        var tunFd = vpnInterface?.fd ?: 0
        val dialerAddr = if (currentConfig?.browserDialerMode.isNullOrEmpty()) {
            ""
        } else {
            "127.0.0.1:${Utils.findRandomFreePort()}"
        }
        if (SettingsManager.isUsingHevTun()) {
            tunFd = 0
        }

        NotificationManager.showNotification(currentConfig)
        CoreNativeManager.reconcileBrowserDialer(dialerAddr)
        coreController.startLoop(result.content, tunFd)

        if (!coreController.isRunning) {
            error("Core failed to start")
        }

        startTrafficStatsCollector()

        if (browserDialer != null) {
            browserDialer!!.stop()
            browserDialer = null
        }
        if (config.browserDialerMode == "OkHttp") {
            browserDialer = DialerNativeService()
            browserDialer!!.start(service, dialerAddr)
        } else if (config.browserDialerMode == "WebView") {
            browserDialer = DialerWebviewService()
            browserDialer!!.start(service, dialerAddr)
        }

        MessageUtil.sendMsg2UI(service, AppConfig.MSG_STATE_START_SUCCESS, "")
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
    private fun stopTrafficStatsCollector() {
        // During an automatic switch, keep the failover coroutine alive
        // long enough to wait for the old core to stop and start the new one.
        if (!autoFailoverSwitching) {
            stopAutoFailoverMonitor()
        }

        trafficStatsJob?.cancel()
        trafficStatsJob = null

        if (coreController.isRunning) {
            try {
                collectTrafficStats()
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "Final traffic stats collection failed", e)
            }
        }
    }

    /**
     * Prepares completion signals BEFORE sending the asynchronous stop
     * command. This removes the race where the stop broadcast could be
     * processed before Auto Failover obtains the Deferred.
     */
    @Synchronized
    fun prepareStopCompletions() {
        if (coreStopCompletion == null || coreStopCompletion!!.isCompleted) {
            coreStopCompletion = CompletableDeferred()
        }

        if (serviceStopCompletion == null || serviceStopCompletion!!.isCompleted) {
            serviceStopCompletion = CompletableDeferred()
        }
    }

    /**
     * Returns the completion signal for the current core stop operation.
     */
    fun getCoreStopCompletion(): CompletableDeferred<Unit> {
        return coreStopCompletion
            ?: CompletableDeferred<Unit>().also { it.complete(Unit) }
    }

    /**
     * Returns the completion signal for the current Android service teardown.
     */
    fun getServiceStopCompletion(): CompletableDeferred<Unit> {
        return serviceStopCompletion
            ?: CompletableDeferred<Unit>().also { it.complete(Unit) }
    }

    private fun beginCoreStop(): CompletableDeferred<Unit> {
        val existing = coreStopCompletion

        if (existing != null && !existing.isCompleted) {
            return existing
        }

        return CompletableDeferred<Unit>().also {
            coreStopCompletion = it
        }
    }

    /**
     * Called by the concrete Service after its own teardown has completed.
     *
     * We also wait for the actual core stop so this signal can never fire
     * before the native core is fully stopped.
     */
    fun signalServiceStopComplete() {
        val serviceCompletion = serviceStopCompletion ?: return
        val coreCompletion = getCoreStopCompletion()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                coreCompletion.await()
            } catch (_: Exception) {
                // Still allow service-stop completion to be released.
            }

            serviceCompletion.complete(Unit)

            LogUtil.i(
                AppConfig.TAG,
                "StartCore-Manager: Service teardown completed"
            )
        }
    }

    fun stopCoreLoop(): Boolean {
        stopTrafficStatsCollector()

        val service = getService() ?: return false
        val stopCompletion = beginCoreStop()

        if (coreController.isRunning) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    coreController.stopLoop()
                } catch (e: Exception) {
                    LogUtil.e(
                        AppConfig.TAG,
                        "StartCore-Manager: Failed to stop V2Ray loop",
                        e
                    )
                } finally {
                    stopCompletion.complete(Unit)

                    LogUtil.i(
                        AppConfig.TAG,
                        "StartCore-Manager: Core stop operation completed"
                    )
                }
            }
        } else {
            stopCompletion.complete(Unit)
        }

        // Close existing browser dialer
        CoreNativeManager.reconcileBrowserDialer("")
        if (browserDialer != null) {
            browserDialer!!.stop()
            browserDialer = null
        }

        MessageUtil.sendMsg2UI(service, AppConfig.MSG_STATE_STOP_SUCCESS, "")
        NotificationManager.cancelNotification()

        try {
            service.unregisterReceiver(mMsgReceive)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to unregister receiver", e)
        }

        return true
    }

    /**
     * Queries and resets all outbound traffic counters in one core call.
     * Go side format: tag,direction,value;tag,direction,value;
     */
    fun queryAllOutboundTrafficStats(): List<OutboundTrafficStat> {
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

        return result
    }

    private fun startTrafficStatsCollector() {
        if (trafficStatsJob?.isActive == true) return

        trafficStatsJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive && coreController.isRunning) {
                try {
                    collectTrafficStats()
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "Traffic stats collection failed", e)
                }

                delay(TRAFFIC_STATS_INTERVAL_MS)
            }
        }
    }

    private fun collectTrafficStats() {
        val guid = MmkvManager.getSelectServer() ?: return

        val stats = queryAllOutboundTrafficStats()

        var upload = 0L
        var download = 0L

        stats.forEach { stat ->
            when {
                stat.tag == AppConfig.TAG_DIRECT ||
                    stat.tag.startsWith(AppConfig.TAG_PROXY) -> {

                    when (stat.direction) {
                        AppConfig.UPLINK -> upload += stat.value
                        AppConfig.DOWNLINK -> download += stat.value
                    }
                }
            }
        }

        if (upload > 0L || download > 0L) {
            MmkvManager.addTrafficStats(guid, upload, download)
        }

        latestTrafficStats = stats
    }

    /**
     * Measures the connection delay for the current V2Ray configuration.
     * Tests with primary URL first, then falls back to alternative URL if needed.
     * Also fetches remote IP information if the delay test was successful.
     */
    
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
     * autoFailoverSwitching prevents stopCoreLoop() from cancelling the
     * coroutine that is responsible for waiting for the old core and
     * starting the new one.
     */
    private suspend fun switchToAutoFailoverCandidate(
        candidateGuid: String,
        candidateDelay: Long
    ) {
        if (
            autoFailoverSwitching ||
            !MmkvManager.isAutoFailoverEnabled()
        ) {
            return
        }

        if (candidateGuid == MmkvManager.getSelectServer()) {
            return
        }

        val service = getService() ?: return
        val context = service.applicationContext

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

            /*
             * Stop the old service and wait for BOTH:
             *
             * 1. The native core to finish stopping.
             * 2. The Android service to finish its teardown.
             *
             * This is especially important in VPN mode, where the old
             * VpnService may still own the TUN interface.
             */
            stopVService(context)

            val coreStop = getCoreStopCompletion()
            val serviceStop = getServiceStopCompletion()

            try {
                kotlinx.coroutines.withTimeout(
                    AUTO_FAILOVER_STOP_TIMEOUT_MS
                ) {
                    coreStop.await()
                    serviceStop.await()
                }
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                LogUtil.e(
                    AppConfig.TAG,
                    "AutoFailover: timed out waiting for old service teardown",
                    e
                )
                return
            }

            if (coreController.isRunning) {
                LogUtil.e(
                    AppConfig.TAG,
                    "AutoFailover: current core is still running"
                )
                return
            }

            // Automatic selection must keep Auto Failover enabled.
            MmkvManager.setSelectServer(candidateGuid)

            LogUtil.i(
                AppConfig.TAG,
                "AutoFailover: starting candidate after confirmed teardown: " +
                    candidateGuid
            )

            startVService(
                context,
                candidateGuid
            )
        } finally {
            autoFailoverSwitching = false
        }
    }

private fun measureV2rayDelay() {
        if (coreController.isRunning == false) {
            return
        }

        CoroutineScope(Dispatchers.IO).launch {
            val service = getService() ?: return@launch
            var time = -1L
            var errorStr = ""

            try {
                time = coreController.measureDelay(SettingsManager.getDelayTestUrl())
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to measure delay", e)
                errorStr = e.message?.substringAfter("\":") ?: "empty message"
            }
            if (time == -1L) {
                try {
                    time = coreController.measureDelay(SettingsManager.getDelayTestUrl(true))
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to measure delay", e)
                    errorStr = e.message?.substringAfter("\":") ?: "empty message"
                }
            }

            val result = if (time >= 0) {
                service.getString(R.string.connection_test_available, time)
            } else {
                service.getString(R.string.connection_test_error, errorStr)
            }
            MessageUtil.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_SUCCESS, result)

            // Only fetch IP info if the delay test was successful
            if (time >= 0) {
                SpeedtestManager.getRemoteIPInfo()?.let { ip ->
                    MessageUtil.sendMsg2UI(service, AppConfig.MSG_MEASURE_DELAY_SUCCESS, "$result\n$ip")
                }
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
            return 0
        }

        /**
         * Called when V2Ray core shuts down.
         * @return 0 for success, any other value for failure.
         */
        override fun shutdown(): Long {
            val serviceControl = serviceControl?.get() ?: return -1
            return try {
                serviceControl.stopService()
                0
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "StartCore-Manager: Failed to stop service", e)
                -1
            }
        }

        /**
         * Called when V2Ray core emits status information.
         * @param l Status code.
         * @param s Status message.
         * @return Always returns 0.
         */
        override fun onEmitStatus(l: Long, s: String?): Long {
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
                    if (coreController.isRunning) {
                        MessageUtil.sendMsg2UI(serviceControl.getService(), AppConfig.MSG_STATE_RUNNING, "")
                    } else {
                        MessageUtil.sendMsg2UI(serviceControl.getService(), AppConfig.MSG_STATE_NOT_RUNNING, "")
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
                    serviceControl.stopService()
                    Thread.sleep(500L)
                    startVService(serviceControl.getService())
                }

                AppConfig.MSG_MEASURE_DELAY -> {
                    measureV2rayDelay()
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
