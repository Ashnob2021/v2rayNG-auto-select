package com.v2ray.ang.ui.dnsdiagnose

import android.app.Application
import androidx.lifecycle.viewModelScope
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.ui.base.BaseViewModel
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
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
                    flagOn = profile.directDohEnabled
                )
            }
            runProbes()
        }
    }

    fun onAction(action: DnsDiagnoseAction) {
        when (action) {
            DnsDiagnoseAction.Retest -> runProbes()
            DnsDiagnoseAction.ApplyFix -> applyFix()
            DnsDiagnoseAction.RevertFix -> revertFix()
        }
    }

    private fun runProbes() {
        val domain = _uiState.value.domain
        if (domain.isEmpty()) return
        probeJob?.cancel()
        probeJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update {
                it.copy(probing = true, rows = emptyList(), verdict = null, fixVerified = false)
            }
            var results = DnsProbe.probeDomain(domain, app)
            var evaluation = evaluateVerdict(results)
            if (evaluation.needsRetry) {
                // DNS can be flaky: one retry before concluding.
                results = DnsProbe.probeDomain(domain, app)
                evaluation = evaluateVerdict(results)
            }
            val flagOn = _uiState.value.flagOn
            _uiState.update {
                it.copy(
                    probing = false,
                    rows = results,
                    verdict = evaluation.verdict,
                    fixVerified = isFixVerified(flagOn, results)
                )
            }
        }
    }

    private fun applyFix() {
        val profile = currentProfile ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val updated = profile.copy(directDohEnabled = true)
                MmkvManager.encodeServerConfig(_uiState.value.guid, updated)
                currentProfile = updated
                withContext(Dispatchers.Main) {
                    _uiState.update {
                        it.copy(flagOn = true, fixVerified = isFixVerified(true, it.rows))
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
                val updated = profile.copy(directDohEnabled = false)
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
     * The fix is verified when the flag is on and the direct DoH row
     * (1.1.1.1, the same endpoint the fix uses) resolves the domain.
     *
     * Note: re-testing measures the network, which stays hijacked — the
     * network verdict does not flip to healthy. This line only confirms
     * the fix's own mechanism works.
     */
    private fun isFixVerified(flagOn: Boolean, results: List<DnsProbeResult>): Boolean {
        if (!flagOn) return false
        val doh = results.firstOrNull { it.resolver == DnsResolver.DOH_1_1_1_1 }
        return doh?.ips != null && doh.ips.isNotEmpty()
    }
}
