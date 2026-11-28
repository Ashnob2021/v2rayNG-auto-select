package com.v2ray.ang.ui.dnsdiagnose

/**
 * State of the core test: a real connection through the Xray core, the
 * same way the app itself connects. The probes can only test the
 * phone's TLS handshake, which differs from the core's (fingerprint),
 * so a probe verdict never proves the config itself works — or fails.
 * The core test is the final proof.
 *
 * Honest limit: the test runs the speed-test config
 * ([com.v2ray.ang.core.CoreConfigManager.getV2rayConfig4Speedtest]),
 * which clears the inbounds so it can run alongside a connected core
 * and strips the DNS section. The measurement itself runs in a shared
 * instance that never loads the config's DNS section at all, so the
 * direct-DoH entries cannot take effect there; instead, when the fix
 * is on and the probe found a DoH answer, the speed-test config dials
 * that trusted IP directly as the outbound's server address. DNS
 * itself is covered by the DNS stage and the fix verification above;
 * this test proves the TLS and transport path through the core.
 */
sealed interface CoreTestState {
    data object Idle : CoreTestState
    data object Testing : CoreTestState
    data class Success(val delayMs: Long) : CoreTestState
    data object Failed : CoreTestState
}

/** Pure mapping of a measured delay to a test state; covered by unit tests. */
fun coreTestStateFromDelay(delayMs: Long): CoreTestState {
    return if (delayMs >= 0) CoreTestState.Success(delayMs) else CoreTestState.Failed
}
