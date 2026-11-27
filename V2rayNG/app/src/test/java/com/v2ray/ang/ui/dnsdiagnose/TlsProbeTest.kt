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
    fun `all handshakes failing with network error means inconclusive not tls blocked`() {
        assertEquals(
            SniVerdictKind.INCONCLUSIVE,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.NETWORK),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.NETWORK),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.NETWORK),
            )
        )
    }

    @Test
    fun `mixed network and timeout failures stay tls blocked`() {
        assertEquals(
            SniVerdictKind.TLS_BLOCKED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.NETWORK),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
            )
        )
    }

    @Test
    fun `network failures with a reset stay tls blocked`() {
        assertEquals(
            SniVerdictKind.TLS_BLOCKED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.NETWORK),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.NETWORK),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.RESET),
            )
        )
    }

    @Test
    fun `all lowercase sni gets first letter of each label capitalized`() {
        assertEquals("Yrui0hd835j2.Pages.Dev", alterSniCase("yrui0hd835j2.pages.dev"))
    }

    @Test
    fun `mixed case sni is lowercased`() {
        assertEquals("pr2x23nrdweakz7tkrna.pages.dev", alterSniCase("pR2X23nrDWeakz7TKRNA.pAges.Dev"))
    }

    @Test
    fun `null sni stays null`() {
        assertNull(alterSniCase(null))
    }

    @Test
    fun `case variant reaching while real sni fails means case sensitive filtering`() {
        assertEquals(
            SniVerdictKind.CASE_SENSITIVE,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.CASE_SNI, TlsOutcome.HANDSHAKE_OK),
            )
        )
    }

    @Test
    fun `case variant reaching beats filtered when harmless sni also reaches`() {
        assertEquals(
            SniVerdictKind.CASE_SENSITIVE,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.HANDSHAKE_OK),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.CASE_SNI, TlsOutcome.HANDSHAKE_FAILED),
            )
        )
    }

    @Test
    fun `case variant failing while harmless sni reaches stays filtered`() {
        assertEquals(
            SniVerdictKind.FILTERED,
            evaluateSniVerdict(
                tls(TlsProbeVariant.REAL_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.HARMLESS_SNI, TlsOutcome.HANDSHAKE_OK),
                tls(TlsProbeVariant.NO_SNI, TlsOutcome.TIMEOUT),
                tls(TlsProbeVariant.CASE_SNI, TlsOutcome.TIMEOUT),
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
        assertEquals("91.198.77.180", pickProbeIp(results))
    }

    @Test
    fun `public system ip is used even when no doh endpoint answered`() {
        val results = listOf(
            dns(DnsResolver.SYSTEM, "104.17.148.22", "104.17.147.22"),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_1_0_0_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_8_8_4_4),
            dnsFailed(DnsResolver.DOH_9_9_9_9),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        assertEquals("104.17.148.22", pickProbeIp(results))
    }

    @Test
    fun `poisoned system ip is never dialled when doh has no answer`() {
        val results = listOf(
            dns(DnsResolver.SYSTEM, "10.10.34.35"),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        assertNull(pickProbeIp(results))
    }

    @Test
    fun `bogon system ip is never dialled when doh has no answer`() {
        val results = listOf(
            dns(DnsResolver.SYSTEM, "192.168.0.1"),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        assertNull(pickProbeIp(results))
    }

    @Test
    fun `no ip at all means no probe ip`() {
        val results = listOf(
            dnsFailed(DnsResolver.SYSTEM),
            dnsFailed(DnsResolver.DOH_1_1_1_1),
            dnsFailed(DnsResolver.DOH_8_8_8_8),
            dnsFailed(DnsResolver.DOH_CLOUDFLARE),
        )
        assertNull(pickProbeIp(results))
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
