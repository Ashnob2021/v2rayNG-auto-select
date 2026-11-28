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
 * and strips the DNS section — so it does not exercise the direct-DoH
 * fix. DNS is covered by the DNS stage and the fix verification above;
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
