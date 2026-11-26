package com.v2ray.ang.ui.dnsdiagnose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.ConnectException
import java.net.SocketException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

class TlsProbeTest {

    private fun tls(variant: TlsProbeVariant, outcome: TlsOutcome) =
        TlsProbeResult(variant, "example.com", listOf("http/1.1"), outcome, 42L, "TLSv1.3", "http/1.1", null)

    private fun dns(resolver: DnsResolver, vararg ips: String) =
        DnsProbeResult(resolver, ips.toList(), 42L, null)

    private fun dnsFailed(resolver: DnsResolver) =
        DnsProbeResult(resolver, null, null, ProbeError.TIMEOUT)

    @Test
    fun `real sni handshake ok means sni is not blocked`() {
        assertEquals(
            SniVerdictKind.NOT_BLOCKED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.HANDSHAKE_OK),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
            )
        )
    }

    @Test
    fun `real sni handshake failed after serverhello means sni reached the server`() {
        assertTrue(reachedServer(tls(TlsProbeVariant.REAL_SNI, TlsOutcome.HANDSHAKE_FAILED)))
        assertEquals(
            SniVerdictKind.NOT_BLOCKED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.HANDSHAKE_FAILED),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
            )
        )
    }

    @Test
    fun `real sni timeout but harmless sni ok means sni is filtered`() {
        assertEquals(
            SniVerdictKind.FILTERED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.HANDSHAKE_OK),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
            )
        )
    }

    @Test
    fun `real sni reset but no sni ok means sni is filtered`() {
        assertEquals(
            SniVerdictKind.FILTERED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.RESET),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.HANDSHAKE_OK),
            )
        )
    }

    @Test
    fun `all sni variants failing means tls is blocked`() {
        assertEquals(
            SniVerdictKind.TLS_BLOCKED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.RESET),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
            )
        )
    }

    @Test
    fun `no real sni result means skipped`() {
        assertEquals(SniVerdictKind.SKIPPED, evaluateSniVerdict(null, null, null))
    }

    @Test
    fun `timeout and reset do not count as reaching the server`() {
        assertFalse(reachedServer(tls(TlsProbeVariant.REAL_SNI, TlsOutcome.TIMEOUT)))
        assertFalse(reachedServer(tls(TlsProbeVariant.REAL_SNI, TlsOutcome.RESET)))
        assertFalse(reachedServer(tls(TlsProbeVariant.REAL_SNI, TlsOutcome.NETWORK)))
    }

    @Test
    fun `doh ip is preferred over system ip`() {
        val results = listOf(
            dns(DnsResolver.SYSTEM, "10.10.34.35"),
            dns(DnsResolver.DOH_1_1_1_1, "91.198.77.180"),
            dns(DnsResolver.DOH_8_8_8_8, "91.198.77.180"),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        val verdict = DnsVerdict(DnsVerdictKind.FILTERED, listOf("10.10.34.35"), listOf("91.198.77.180"))
        assertEquals("91.198.77.180", pickProbeIp(results, verdict))
    }

    @Test
    fun `system ip is used only when dns looks healthy`() {
        val results = listOf(
            dns(DnsResolver.SYSTEM, "93.184.216.34"),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        val verdict = DnsVerdict(DnsVerdictKind.HEALTHY, listOf("93.184.216.34"), listOf("93.184.216.34"))
        assertEquals("93.184.216.34", pickProbeIp(results, verdict))
    }

    @Test
    fun `poisoned system ip is never dialled when doh has no answer`() {
        val results = listOf(
            dns(DnsResolver.SYSTEM, "10.10.34.35"),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        val verdict = DnsVerdict(DnsVerdictKind.FILTERED, listOf("10.10.34.35"), emptyList())
        assertNull(pickProbeIp(results, verdict))
    }

    @Test
    fun `no ip at all means no probe ip`() {
        val results = listOf(
            dnsFailed(DnsResolver.SYSTEM),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        assertNull(pickProbeIp(results, DnsVerdict(DnsVerdictKind.UNRESOLVABLE)))
    }

    @Test
    fun `tls probe mode follows the security type`() {
        assertEquals(TlsProbeMode.TLS, tlsProbeMode("tls"))
        assertEquals(TlsProbeMode.TLS, tlsProbeMode("TLS"))
        assertEquals(TlsProbeMode.REALITY, tlsProbeMode("reality"))
        assertEquals(TlsProbeMode.REALITY, tlsProbeMode("REALITY"))
        assertEquals(TlsProbeMode.NONE, tlsProbeMode("none"))
        assertEquals(TlsProbeMode.NONE, tlsProbeMode(""))
        assertEquals(TlsProbeMode.NONE, tlsProbeMode(null))
    }

    @Test
    fun `tcp exception classification`() {
        assertEquals(TcpOutcome.TIMEOUT, classifyTcpException(SocketTimeoutException()))
        assertEquals(TcpOutcome.REFUSED, classifyTcpException(ConnectException("Connection refused")))
        assertEquals(TcpOutcome.NETWORK, classifyTcpException(ConnectException("Connection failed")))
        assertEquals(TcpOutcome.RESET, classifyTcpException(SocketException("Connection reset")))
        assertEquals(TcpOutcome.NETWORK, classifyTcpException(IOException("boom")))
    }

    @Test
    fun `tls exception classification`() {
        assertEquals(TlsOutcome.TIMEOUT, classifyTlsException(SocketTimeoutException()))
        assertEquals(TlsOutcome.HANDSHAKE_FAILED, classifyTlsException(SSLHandshakeException("Received fatal alert")))
        assertEquals(TlsOutcome.HANDSHAKE_FAILED, classifyTlsException(SSLException("Unsupported extension")))
        assertEquals(TlsOutcome.RESET, classifyTlsException(SSLException("Connection reset by peer")))
        assertEquals(TlsOutcome.NETWORK, classifyTlsException(IOException("boom")))
    }
}
