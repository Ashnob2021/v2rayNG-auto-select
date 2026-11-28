package com.v2ray.ang.ui.dnsdiagnose

import android.app.Application
import androidx.lifecycle.viewModelScope
import com.v2ray.ang.R
import com.v2ray.ang.core.CoreConfigManager
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.ui.base.BaseViewModel
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import com.v2ray.ang.util.alterSniCase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DnsDiagnoseViewModel(application: Application) : BaseViewModel(application) {

    private val _uiState = MutableStateFlow(DnsDiagnoseUiState())
    val uiState: StateFlow<DnsDiagnoseUiState> = _uiState.asStateFlow()

    private var startedGuid: String? = null
    private var currentProfile: ProfileItem? = null
    private var probeJob: Job? = null

    fun start(guid: String) {
        if (startedGuid == guid) return
        startedGuid = guid
        viewModelScope.launch(Dispatchers.IO) {
            val profile = MmkvManager.decodeServerConfig(guid)
            if (profile == null) {
                _uiState.update { it.copy(phase = DnsDiagnosePhase.NO_PROFILE) }
                return@launch
            }
            val domain = profile.server?.trim().orEmpty()
            if (!Utils.isDomainName(domain)) {
                _uiState.update {
                    it.copy(phase = DnsDiagnosePhase.NO_DOMAIN, remarks = profile.remarks)
                }
                return@launch
            }
            currentProfile = profile
            _uiState.update {
                it.copy(
                    phase = DnsDiagnosePhase.READY,
                    guid = guid,
                    remarks = profile.remarks,
                    domain = domain,
                    flagOn = profile.directDohEnabled,
                    sniCaseMixed = profile.sniCaseMixed,
                )
            }
            runProbes()
            if (profile.directDohEnabled) {
                val verified = verifyAppliedFix()
                _uiState.update { it.copy(fixVerified = verified) }
            }
        }
    }

    fun onAction(action: DnsDiagnoseAction) {
        when (action) {
            DnsDiagnoseAction.Retest -> runProbes()
            DnsDiagnoseAction.ApplyFix -> applyFix()
            DnsDiagnoseAction.RevertFix -> revertFix()
            DnsDiagnoseAction.ApplySniFix -> applySniFix()
            DnsDiagnoseAction.RevertSniFix -> revertSniFix()
            DnsDiagnoseAction.TestCore -> runCoreTest()
        }
    }

    private fun runProbes() {
        val domain = _uiState.value.domain
        if (domain.isEmpty()) return
        probeJob?.cancel()
        probeJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update {
                it.copy(probing = true, rows = emptyList(), verdict = null, tcp = null, tls = emptyList(), sniVerdict = null, sniFixOffered = false, tlsSkipped = null, ws = null, wsVerdict = null)
            }
            var results = DnsProbe.probeDomain(domain, app)
            var evaluation = evaluateVerdict(results)
            if (evaluation.needsRetry) {
                // DNS can be flaky: one retry before concluding.
                results = DnsProbe.probeDomain(domain, app)
                evaluation = evaluateVerdict(results)
            }
            _uiState.update {
                it.copy(
                    rows = results,
                    verdict = evaluation.verdict,
                )
            }
            val connection = runConnectionProbes(results)
            val storedSni = currentProfile?.let { storedSniForProbe(it, _uiState.value.domain) }
            val caseSni = connection?.tls?.firstOrNull { it.variant == TlsProbeVariant.CASE_SNI }
            _uiState.update {
                it.copy(
                    probing = false,
                    tcp = connection?.tcp,
                    tls = connection?.tls.orEmpty(),
                    sniVerdict = connection?.sniVerdict,
                    tlsSkipped = connection?.tlsSkipped,
                    ws = connection?.ws,
                    wsVerdict = connection?.wsVerdict,
                    sniFixOffered = shouldOfferSniFix(connection?.sniVerdict, caseSni, storedSni),
                )
            }
        }
    }

    private fun applyFix() {
        val profile = currentProfile ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // Remember which endpoint answered on this network: the
                // generated config writes it first, so the core does not
                // burn ~5 s per dead endpoint before reaching it.
                val preferred = preferredDohAddress(_uiState.value.rows)
                val updated = profile.copy(directDohEnabled = true, directDohPreferred = preferred)
                MmkvManager.encodeServerConfig(_uiState.value.guid, updated)
                currentProfile = updated
                val verified = verifyAppliedFix()
                withContext(Dispatchers.Main) {
                    _uiState.update {
                        it.copy(flagOn = true, fixVerified = verified)
                    }
                    toastSuccess(R.string.dns_diagnose_applied)
                }
            } catch (e: Exception) {
                LogUtil.e("DnsDiagnose", "applyFix failed: ${e.message}")
                withContext(Dispatchers.Main) {
                    toast(R.string.toast_failure)
                }
            }
        }
    }

    private fun revertFix() {
        val profile = currentProfile ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val updated = profile.copy(directDohEnabled = false, directDohPreferred = null)
                MmkvManager.encodeServerConfig(_uiState.value.guid, updated)
                currentProfile = updated
                withContext(Dispatchers.Main) {
                    _uiState.update { it.copy(flagOn = false, fixVerified = false) }
                    toast(R.string.dns_diagnose_reverted)
                }
            } catch (e: Exception) {
                LogUtil.e("DnsDiagnose", "revertFix failed: ${e.message}")
                withContext(Dispatchers.Main) {
                    toast(R.string.toast_failure)
                }
            }
        }
    }

    /**
     * Mixed-case SNI fix: sends the SNI with its letter case changed, so
     * a case-sensitive SNI filter no longer matches it. The stored SNI is
     * untouched — the flag only changes what the connection sends. After
     * applying or reverting, the probes re-run so the Real SNI row shows
     * the SNI that is actually in effect; the core test is the final
     * proof the real connection works with it.
     */
    private fun applySniFix() {
        val profile = currentProfile ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val updated = profile.copy(sniCaseMixed = true)
                MmkvManager.encodeServerConfig(_uiState.value.guid, updated)
                currentProfile = updated
                withContext(Dispatchers.Main) {
                    _uiState.update { it.copy(sniCaseMixed = true) }
                    toast(R.string.sni_fix_applied)
                }
                runProbes()
            } catch (e: Exception) {
                LogUtil.e("DnsDiagnose", "applySniFix failed: ${e.message}")
                withContext(Dispatchers.Main) {
                    toast(R.string.toast_failure)
                }
            }
        }
    }

    private fun revertSniFix() {
        val profile = currentProfile ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val updated = profile.copy(sniCaseMixed = false)
                MmkvManager.encodeServerConfig(_uiState.value.guid, updated)
                currentProfile = updated
                withContext(Dispatchers.Main) {
                    _uiState.update { it.copy(sniCaseMixed = false) }
                    toast(R.string.dns_diagnose_reverted)
                }
                runProbes()
            } catch (e: Exception) {
                LogUtil.e("DnsDiagnose", "revertSniFix failed: ${e.message}")
                withContext(Dispatchers.Main) {
                    toast(R.string.toast_failure)
                }
            }
        }
    }

    /** The SNI the probe tests, before any fix is applied: the
     *  profile's SNI when it is a domain name, else the server domain.
     *  The fix offer is decided from this stored SNI, not from the
     *  SNI the probe actually sent (which is the altered form when
     *  the fix is already on). */
    private fun storedSniForProbe(profile: ProfileItem, domain: String): String =
        profile.sni?.trim()?.takeIf { Utils.isDomainName(it) } ?: domain

    /**
     * TCP, then SNI/TLS, against the IP the DNS stage trusted. Runs only
     * when the DNS stage produced an IP to dial and the profile has a
     * port. TLS handshakes run only for TLS configs. For REALITY the
     * plain-TLS probe is skipped: it is not a REALITY handshake, so it
     * would report "TLS is blocked" for a server that works fine over
     * REALITY. For anything else the TCP result alone is reported.
     */
    private suspend fun runConnectionProbes(
        results: List<DnsProbeResult>,
    ): ConnectionProbeResult? {
        val profile = currentProfile ?: return null
        val ip = pickProbeIp(results) ?: return null
        val port = profile.serverPort?.trim()?.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val domain = _uiState.value.domain
        if (domain.isEmpty()) return null
        return when (tlsProbeMode(profile.security)) {
            TlsProbeMode.TLS -> {
                val storedSni = storedSniForProbe(profile, domain)
                // When the mixed-case SNI fix is on, the probe tests the
                // SNI the connection actually sends, not the stored one.
                val realSni = if (profile.sniCaseMixed) alterSniCase(storedSni) ?: storedSni else storedSni
                val alpn = profile.alpn?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
                // Skip the case-variant handshake when the fix is on:
                // it would only re-test the stored SNI, which is the
                // form already known to be blocked.
                val connection = TlsProbe.probeConnection(ip, port, realSni, alpn, includeCaseVariant = !profile.sniCaseMixed)
                // WebSocket transport probe: only for WS profiles, and
                // only when the real-SNI handshake completed — otherwise
                // the TLS stage already explains the failure and the
                // upgrade cannot run. The WS Host/path come from the
                // profile, falling back to the domain and "/" when blank.
                val ws = if (isWsTransport(profile.network) &&
                    connection.tls.firstOrNull { it.variant == TlsProbeVariant.REAL_SNI }?.outcome == TlsOutcome.HANDSHAKE_OK
                ) {
                    val wsHost = profile.host?.trim().takeIf { it.isNotEmpty() } ?: domain
                    val wsPath = profile.path?.trim().takeIf { it.isNotEmpty() } ?: "/"
                    WsProbe.probeWebSocket(ip, port, realSni, wsHost, wsPath)
                } else {
                    null
                }
                connection.copy(ws = ws, wsVerdict = evaluateWsVerdict(ws))
            }
            TlsProbeMode.REALITY -> {
                val tcp = TlsProbe.probeTcp(ip, port)
                ConnectionProbeResult(tcp, emptyList(), SniVerdictKind.SKIPPED, TlsSkippedReason.REALITY)
            }
            TlsProbeMode.NONE -> {
                val tcp = TlsProbe.probeTcp(ip, port)
                ConnectionProbeResult(tcp, emptyList(), SniVerdictKind.SKIPPED, TlsSkippedReason.NOT_TLS)
            }
        }
    }

    /**
     * Core test: a real connection through the Xray core, reusing the
     * app's own delay-test machinery (speed-test config +
     * [CoreNativeManager.measureOutboundDelay]). The speed-test config
     * clears the inbounds, so this can run while another config is
     * connected, and it uses the profile's fingerprint, ALPN and
     * transport settings — the things the phone-stack probes cannot
     * reproduce. Runs on IO: the measurement is a blocking JNI call.
     */
    private fun runCoreTest() {
        val guid = _uiState.value.guid
        if (guid.isEmpty() || _uiState.value.coreTest == CoreTestState.Testing) return
        viewModelScope.launch(Dispatchers.IO) {
            _uiState.update { it.copy(coreTest = CoreTestState.Testing) }
            val state = try {
                CoreNativeManager.initCoreEnv(app)
                val result = CoreConfigManager.getV2rayConfig4Speedtest(app, guid)
                if (!result.status) {
                    CoreTestState.Failed
                } else {
                    coreTestStateFromDelay(
                        CoreNativeManager.measureOutboundDelay(
                            result.content,
                            SettingsManager.getDelayTestUrl()
                        )
                    )
                }
            } catch (e: Exception) {
                LogUtil.e("DnsDiagnose", "core test failed: ${e.message}")
                CoreTestState.Failed
            }
            _uiState.update { it.copy(coreTest = state) }
        }
    }

    /**
     * Verify the fix against the generated runtime config, not the probe
     * rows: the probes resolve through DoH directly, whether or not the
     * fix was ever applied, so they cannot prove the fix is in effect.
     * Re-testing measures the network, which stays hijacked — the network
     * verdict does not flip to healthy.
     */
    private suspend fun verifyAppliedFix(): Boolean {
        return try {
            val guid = _uiState.value.guid
            if (guid.isEmpty()) return false
            val result = withContext(Dispatchers.IO) { CoreConfigManager.getV2rayConfig(app, guid) }
            if (!result.status) return false
            isDirectDohAppliedInConfig(result.content, _uiState.value.domain)
        } catch (e: Exception) {
            LogUtil.e("DnsDiagnose", "verifyAppliedFix failed: ${e.message}")
            false
        }
    }
}
