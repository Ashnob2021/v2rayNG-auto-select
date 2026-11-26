package com.v2ray.ang.ui.dnsdiagnose

import android.app.Application
import androidx.lifecycle.viewModelScope
import com.v2ray.ang.R
import com.v2ray.ang.core.CoreConfigManager
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
        }
    }

    private fun runProbes() {
        val domain = _uiState.value.domain
        if (domain.isEmpty()) return
        probeJob?.cancel()
        probeJob = viewModelScope.launch(Dispatchers.IO) {
            _uiState.update {
                it.copy(probing = true, rows = emptyList(), verdict = null)
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
                    probing = false,
                    rows = results,
                    verdict = evaluation.verdict,
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
