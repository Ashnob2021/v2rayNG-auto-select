package com.v2ray.ang.ui.dnsdiagnose

import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.v2ray.ang.util.alterSniCase
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * TCP, SNI and TLS probes for one server, run after the DNS stage.
 *
 * The probes dial the IP the DNS stage trusted: a DoH answer when one
 * exists, otherwise the system resolver's answer when it is a plausible
 * public address. A bogon — including the filtering sinkhole
 * 10.10.34.34/35 — is never dialled. The probes stop at the TLS
 * handshake: no application data is ever sent. A plain [Socket] first proves the
 * IP:port is reachable at all; then three TLS handshakes vary only the
 * SNI — the profile's real SNI, a harmless SNI, and no SNI — so a
 * difference between them isolates SNI filtering from a general TLS
 * block.
 *
 * Honest limits, recorded here so the UI does not over-claim:
 * - The handshakes use the phone's TLS stack, so they cannot reproduce
 *   the profile's fingerprint (chrome / randomized): fingerprint stays a
 *   fix to try, not something this probe measures.
 * - For REALITY configs the real SNI is the front domain, and a plain
 *   TLS handshake is not a REALITY handshake: reaching the server here
 *   proves the TLS layer and the SNI are not blocked, not that REALITY
 *   itself works. REALITY validation (public key / short id) is a later
 *   stage.
 */
object TlsProbe {

    const val HARMLESS_SNI = "example.com"
    private const val CONNECT_TIMEOUT_MS = 5000
    private const val HANDSHAKE_TIMEOUT_MS = 5000

    suspend fun probeConnection(
        ip: String,
        port: Int,
        realSni: String?,
        alpn: List<String>,
    ): ConnectionProbeResult {
        val tcp = probeTcp(ip, port)
        if (tcp.outcome != TcpOutcome.CONNECTED) {
            return ConnectionProbeResult(tcp, emptyList(), SniVerdictKind.SKIPPED)
        }
        val tls = listOf(
            probeTls(ip, port, TlsProbeVariant.REAL_SNI, realSni, alpn),
            probeTls(ip, port, TlsProbeVariant.HARMLESS_SNI, HARMLESS_SNI, alpn),
            probeTls(ip, port, TlsProbeVariant.NO_SNI, null, alpn),
            probeTls(ip, port, TlsProbeVariant.CASE_SNI, alterSniCase(realSni), alpn),
        )
        val verdict = evaluateSniVerdict(tls[0], tls[1], tls[2], tls[3])
        return ConnectionProbeResult(tcp, tls, verdict)
    }

    suspend fun probeTcp(ip: String, port: Int): TcpProbeResult = withContext(Dispatchers.IO) {
        try {
            Socket().use { socket ->
                val start = SystemClock.elapsedRealtime()
                socket.connect(InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS)
                TcpProbeResult(ip, port, TcpOutcome.CONNECTED, SystemClock.elapsedRealtime() - start)
            }
        } catch (e: Exception) {
            TcpProbeResult(ip, port, classifyTcpException(e), null)
        }
    }

    suspend fun probeTls(
        ip: String,
        port: Int,
        variant: TlsProbeVariant,
        sni: String?,
        alpn: List<String>,
    ): TlsProbeResult = withContext(Dispatchers.IO) {
        val start = SystemClock.elapsedRealtime()
        val plain = Socket()
        try {
            plain.connect(InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS)
            plain.soTimeout = HANDSHAKE_TIMEOUT_MS
            val ssl = trustAllContext().socketFactory.createSocket(plain, ip, port, true) as SSLSocket
            ssl.use {
                val params = it.sslParameters
                params.serverNames = if (sni != null) listOf(SNIHostName(sni)) else emptyList()
                if (alpn.isNotEmpty()) {
                    params.applicationProtocols = alpn.toTypedArray()
                }
                it.sslParameters = params
                it.startHandshake()
                val latency = SystemClock.elapsedRealtime() - start
                TlsProbeResult(
                    variant = variant,
                    sni = sni,
                    alpn = alpn,
                    outcome = TlsOutcome.HANDSHAKE_OK,
                    latencyMs = latency,
                    tlsVersion = it.session.protocol,
                    negotiatedAlpn = it.applicationProtocol.takeIf { protocol -> protocol.isNotBlank() },
                    peerCertSubject = peerCertSubject(it),
                )
            }
        } catch (e: Exception) {
            try {
                plain.close()
            } catch (_: Exception) {
            }
            TlsProbeResult(
                variant = variant,
                sni = sni,
                alpn = alpn,
                outcome = classifyTlsException(e),
                latencyMs = null,
                tlsVersion = null,
                negotiatedAlpn = null,
                peerCertSubject = null,
            )
        }
    }

    private fun peerCertSubject(socket: SSLSocket): String? {
        return try {
            val cert = socket.session.peerCertificates.firstOrNull() as? X509Certificate
            cert?.subjectX500Principal?.name
        } catch (e: SSLPeerUnverifiedException) {
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun trustAllContext(): SSLContext {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        return SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAll), SecureRandom())
        }
    }
}

enum class TcpOutcome {
    CONNECTED,
    TIMEOUT,
    REFUSED,
    RESET,
    NETWORK,
}

data class TcpProbeResult(
    val ip: String,
    val port: Int,
    val outcome: TcpOutcome,
    val latencyMs: Long?,
)

enum class TlsProbeVariant {
    REAL_SNI,
    HARMLESS_SNI,
    NO_SNI,
    /** The real SNI with its letter case changed, to test whether the
     *  SNI filter matches case-sensitively. */
    CASE_SNI,
}

enum class TlsOutcome {
    /** The handshake completed; the TLS layer and the SNI reached the server. */
    HANDSHAKE_OK,

    /** A ServerHello arrived but the handshake then failed (alert, or a
     *  server such as REALITY that does not complete a plain TLS
     *  handshake): the SNI reached the server, the TLS layer did not. */
    HANDSHAKE_FAILED,
    TIMEOUT,
    RESET,
    NETWORK,
}

data class TlsProbeResult(
    val variant: TlsProbeVariant,
    val sni: String?,
    val alpn: List<String>,
    val outcome: TlsOutcome,
    val latencyMs: Long?,
    val tlsVersion: String?,
    val negotiatedAlpn: String?,
    val peerCertSubject: String?,
)

data class ConnectionProbeResult(
    val tcp: TcpProbeResult,
    val tls: List<TlsProbeResult>,
    val sniVerdict: SniVerdictKind,
    val tlsSkipped: TlsSkippedReason? = null,
)

enum class SniVerdictKind {
    NOT_BLOCKED,
    FILTERED,
    TLS_BLOCKED,
    SKIPPED,
    /** Every handshake failed immediately with a network error, so the
     *  probe itself could not run: this says nothing about whether TLS
     *  is blocked. A config can still connect — its handshake (fingerprint)
     *  differs from the phone stack's, which is what failed here. */
    INCONCLUSIVE,
    /** The real SNI is blocked, but the same SNI with different letter
     *  case reaches the server: the SNI filter matches case-sensitively,
     *  so changing the SNI case (or fragmenting the ClientHello) is a fix. */
    CASE_SENSITIVE,
}

/**
 * Whether a plain TLS/SNI probe means anything for a config.
 * TLS configs get the full probe. REALITY configs do not: a plain TLS
 * handshake is not a REALITY handshake, so the probe would report
 * "TLS is blocked" for a server that works fine over REALITY — exactly
 * the false verdict this exists to avoid. Anything else has no TLS
 * handshake to test at all.
 */
enum class TlsProbeMode {
    TLS,
    REALITY,
    NONE,
}

enum class TlsSkippedReason {
    REALITY,
    NOT_TLS,
}

/** Pure decision for [TlsProbeMode]; covered by unit tests. */
fun tlsProbeMode(security: String?): TlsProbeMode {
    return when {
        "tls".equals(security, ignoreCase = true) -> TlsProbeMode.TLS
        "reality".equals(security, ignoreCase = true) -> TlsProbeMode.REALITY
        else -> TlsProbeMode.NONE
    }
}

/** Pure decision for [TlsProbe.probeConnection]; covered by unit tests. */
fun evaluateSniVerdict(
    real: TlsProbeResult?,
    harmless: TlsProbeResult?,
    noSni: TlsProbeResult?,
    caseSni: TlsProbeResult? = null,
): SniVerdictKind {
    if (real == null) return SniVerdictKind.SKIPPED
    // A completed handshake with the real SNI means the SNI is fine,
    // whatever the other variants did.
    if (real.outcome == TlsOutcome.HANDSHAKE_OK) return SniVerdictKind.NOT_BLOCKED
    // The real SNI's handshake failed but the same SNI with different
    // letter case completes: the filter matches case-sensitively. This
    // check runs before "reached" below, because a handshake that fails
    // after ServerHello is itself the blocking.
    if (caseSni?.let { reachedServer(it) } == true) {
        return SniVerdictKind.CASE_SENSITIVE
    }
    // The SNI reached the server (it answered, then the handshake
    // failed): the SNI itself is not blocked.
    if (reachedServer(real)) return SniVerdictKind.NOT_BLOCKED
    if (harmless?.let { reachedServer(it) } == true || noSni?.let { reachedServer(it) } == true) {
        return SniVerdictKind.FILTERED
    }
    if (real.outcome == TlsOutcome.NETWORK &&
        harmless?.outcome == TlsOutcome.NETWORK &&
        noSni?.outcome == TlsOutcome.NETWORK
    ) {
        return SniVerdictKind.INCONCLUSIVE
    }
    return SniVerdictKind.TLS_BLOCKED
}

/** A handshake that completed, or one that failed after a ServerHello
 *  arrived, proves the SNI reached the server. A timeout, reset or
 *  network failure before any ServerHello does not. */
fun reachedServer(result: TlsProbeResult): Boolean {
    return result.outcome == TlsOutcome.HANDSHAKE_OK || result.outcome == TlsOutcome.HANDSHAKE_FAILED
}

/**
 * Pick the IP the connection probes dial: a trusted DoH answer first.
 * When no DoH endpoint answered, the system resolver's answer is the
 * only candidate: dial it only when it looks like a real public
 * address. A bogon — including the filtering sinkhole 10.10.34.34/35 —
 * must never be dialled. This matters on a network that blocks the DoH
 * endpoints themselves while the system resolver still answers
 * correctly (for example, speedtest.net on such a network): the domain
 * is not filtered, DoH is, and skipping TCP/SNI would throw away the
 * one test that can still run. The verdict no longer gates this
 * choice: whether the system answer is plausible is decided from the
 * address itself, not from whether DoH happened to answer.
 * Pure logic, covered by unit tests.
 */
fun pickProbeIp(results: List<DnsProbeResult>): String? {
    val dohIps = results.filter { it.resolver != DnsResolver.SYSTEM }.flatMap { it.ips.orEmpty() }
    if (dohIps.isNotEmpty()) return dohIps.first()
    return results.firstOrNull { it.resolver == DnsResolver.SYSTEM }
        ?.ips.orEmpty()
        .firstOrNull { !isBogonIp(it) }
}

fun classifyTcpException(e: Exception): TcpOutcome {
    return when {
        e is SocketTimeoutException -> TcpOutcome.TIMEOUT
        e is ConnectException -> if (e.message?.contains("refused", ignoreCase = true) == true) {
            TcpOutcome.REFUSED
        } else {
            TcpOutcome.NETWORK
        }
        e is SocketException -> if (e.message?.contains("reset", ignoreCase = true) == true) {
            TcpOutcome.RESET
        } else {
            TcpOutcome.NETWORK
        }
        else -> TcpOutcome.NETWORK
    }
}

fun classifyTlsException(e: Exception): TlsOutcome {
    return when {
        e is SocketTimeoutException -> TlsOutcome.TIMEOUT
        e.message?.contains("reset", ignoreCase = true) == true -> TlsOutcome.RESET
        e is SSLHandshakeException -> TlsOutcome.HANDSHAKE_FAILED
        e is SSLException -> TlsOutcome.HANDSHAKE_FAILED
        e is IOException -> TlsOutcome.NETWORK
        else -> TlsOutcome.NETWORK
    }
}
