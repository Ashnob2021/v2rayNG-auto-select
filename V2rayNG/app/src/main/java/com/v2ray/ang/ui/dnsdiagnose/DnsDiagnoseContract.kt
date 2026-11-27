package com.v2ray.ang.ui.dnsdiagnose

enum class DnsDiagnosePhase {
    LOADING,
    NO_PROFILE,
    NO_DOMAIN,
    READY,
}

data class DnsDiagnoseUiState(
    val guid: String = "",
    val remarks: String = "",
    val domain: String = "",
    val flagOn: Boolean = false,
    val sniCaseMixed: Boolean = false,
    val phase: DnsDiagnosePhase = DnsDiagnosePhase.LOADING,
    val probing: Boolean = false,
    val rows: List<DnsProbeResult> = emptyList(),
    val verdict: DnsVerdict? = null,
    val fixVerified: Boolean = false,
    val tcp: TcpProbeResult? = null,
    val tls: List<TlsProbeResult> = emptyList(),
    val sniVerdict: SniVerdictKind? = null,
    val tlsSkipped: TlsSkippedReason? = null,
    val coreTest: CoreTestState = CoreTestState.Idle,
)

sealed interface DnsDiagnoseAction {
    data object Retest : DnsDiagnoseAction
    data object ApplyFix : DnsDiagnoseAction
    data object RevertFix : DnsDiagnoseAction
    data object ApplySniFix : DnsDiagnoseAction
    data object RevertSniFix : DnsDiagnoseAction
    data object TestCore : DnsDiagnoseAction
}
