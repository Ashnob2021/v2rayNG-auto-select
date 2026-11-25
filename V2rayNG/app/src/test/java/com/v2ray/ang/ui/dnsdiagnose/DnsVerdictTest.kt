package com.v2ray.ang.ui.dnsdiagnose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnsVerdictTest {

    private fun ok(resolver: DnsResolver, vararg ips: String) =
        DnsProbeResult(resolver, ips.toList(), 42L, null)

    private fun failed(resolver: DnsResolver, error: ProbeError) =
        DnsProbeResult(resolver, null, null, error)

    @Test
    fun `all resolvers agree is healthy`() {
        val results = listOf(
            ok(DnsResolver.SYSTEM, "93.184.216.34"),
            ok(DnsResolver.DOH_1_1_1_1, "93.184.216.34"),
            ok(DnsResolver.DOH_8_8_8_8, "93.184.216.34"),
            ok(DnsResolver.DOH_CLOUDFLARE, "93.184.216.34"),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.HEALTHY, evaluation.verdict.kind)
        assertFalse(evaluation.needsRetry)
    }

    @Test
    fun `partial overlap is healthy for round robin`() {
        val results = listOf(
            ok(DnsResolver.SYSTEM, "93.184.216.34", "93.184.216.35"),
            ok(DnsResolver.DOH_1_1_1_1, "93.184.216.35"),
            ok(DnsResolver.DOH_8_8_8_8, "93.184.216.34"),
            ok(DnsResolver.DOH_CLOUDFLARE, "93.184.216.34"),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.HEALTHY, evaluation.verdict.kind)
        assertFalse(evaluation.needsRetry)
    }

    @Test
    fun `private system ip is hijacked without retry`() {
        val results = listOf(
            ok(DnsResolver.SYSTEM, "10.10.34.35"),
            ok(DnsResolver.DOH_1_1_1_1, "93.184.216.34"),
            ok(DnsResolver.DOH_8_8_8_8, "93.184.216.34"),
            ok(DnsResolver.DOH_CLOUDFLARE, "93.184.216.34"),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.HIJACKED, evaluation.verdict.kind)
        assertFalse(evaluation.needsRetry)
        assertEquals(listOf("10.10.34.35"), evaluation.verdict.systemIps)
        assertEquals(listOf("93.184.216.34"), evaluation.verdict.dohIps)
    }

    @Test
    fun `disjoint public ips request one retry`() {
        val results = listOf(
            ok(DnsResolver.SYSTEM, "1.2.3.4"),
            ok(DnsResolver.DOH_1_1_1_1, "5.6.7.8"),
            ok(DnsResolver.DOH_8_8_8_8, "5.6.7.8"),
            ok(DnsResolver.DOH_CLOUDFLARE, "5.6.7.8"),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.HIJACKED, evaluation.verdict.kind)
        assertTrue(evaluation.needsRetry)
    }

    @Test
    fun `all fail is unresolvable`() {
        val results = listOf(
            failed(DnsResolver.SYSTEM, ProbeError.TIMEOUT),
            failed(DnsResolver.DOH_1_1_1_1, ProbeError.NETWORK),
            failed(DnsResolver.DOH_8_8_8_8, ProbeError.NETWORK),
            failed(DnsResolver.DOH_CLOUDFLARE, ProbeError.NETWORK),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.UNRESOLVABLE, evaluation.verdict.kind)
        assertFalse(evaluation.needsRetry)
    }

    @Test
    fun `system fails but doh works`() {
        val results = listOf(
            failed(DnsResolver.SYSTEM, ProbeError.NO_ANSWER),
            ok(DnsResolver.DOH_1_1_1_1, "93.184.216.34"),
            ok(DnsResolver.DOH_8_8_8_8, "93.184.216.34"),
            failed(DnsResolver.DOH_CLOUDFLARE, ProbeError.NETWORK),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.SYSTEM_DNS_FAILED, evaluation.verdict.kind)
        assertFalse(evaluation.needsRetry)
    }

    @Test
    fun `system works but doh all fail`() {
        val results = listOf(
            ok(DnsResolver.SYSTEM, "93.184.216.34"),
            failed(DnsResolver.DOH_1_1_1_1, ProbeError.NETWORK),
            failed(DnsResolver.DOH_8_8_8_8, ProbeError.TIMEOUT),
            failed(DnsResolver.DOH_CLOUDFLARE, ProbeError.NETWORK),
        )
        val evaluation = evaluateVerdict(results)
        assertEquals(DnsVerdictKind.DOH_UNREACHABLE, evaluation.verdict.kind)
        assertFalse(evaluation.needsRetry)
    }

    @Test
    fun `bogon detection covers private ranges`() {
        assertTrue(isBogonIp("10.0.0.1"))
        assertTrue(isBogonIp("172.16.0.1"))
        assertTrue(isBogonIp("172.31.255.255"))
        assertTrue(isBogonIp("192.168.1.1"))
        assertTrue(isBogonIp("127.0.0.1"))
        assertTrue(isBogonIp("0.0.0.0"))
        assertTrue(isBogonIp("169.254.1.1"))
        assertTrue(isBogonIp("100.64.0.1"))
        assertTrue(isBogonIp("::1"))
        assertTrue(isBogonIp("fe80::1"))
        assertTrue(isBogonIp("fc00::1"))
        assertFalse(isBogonIp("93.184.216.34"))
        assertFalse(isBogonIp("8.8.8.8"))
        assertFalse(isBogonIp("172.32.0.1"))
        assertFalse(isBogonIp("100.128.0.1"))
    }
}
