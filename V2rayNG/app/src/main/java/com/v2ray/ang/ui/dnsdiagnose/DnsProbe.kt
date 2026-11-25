package com.v2ray.ang.ui.dnsdiagnose

import android.content.Context
import android.net.ConnectivityManager
import android.os.SystemClock
import android.util.Base64
import com.v2ray.ang.util.HttpUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * Probes one domain against four resolvers in parallel:
 * the phone's system UDP resolver, and DoH to 1.1.1.1, 8.8.8.8 and
 * cloudflare-dns.com (RFC 8484 GET).
 *
 * The cloudflare-dns.com row never asks the system DNS for its own
 * hostname: the system resolver may be the poisoned one under test, so
 * the hostname is resolved first through the 1.1.1.1 DoH endpoint and the
 * answer is pinned in an OkHttp [Dns] override for that host only.
 */
object DnsProbe {

    private const val DOH_TIMEOUT_SECONDS = 5L
    private const val UDP_TIMEOUT_MS = 3000
    private const val UDP_MAX_ATTEMPTS = 2
    private const val CLOUDFLARE_HOST = "cloudflare-dns.com"

    private val plainClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(DOH_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(DOH_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .build()

    suspend fun probeDomain(domain: String, context: Context): List<DnsProbeResult> = coroutineScope {
        val asciiDomain = HttpUtil.toIdnDomain(domain.trim())
        val system = async(Dispatchers.IO) { probeSystemDns(asciiDomain, context) }
        val doh1 = async(Dispatchers.IO) { probeDoh(asciiDomain, DnsResolver.DOH_1_1_1_1, plainClient) }
        val doh8 = async(Dispatchers.IO) { probeDoh(asciiDomain, DnsResolver.DOH_8_8_8_8, plainClient) }
        val dohCf = async(Dispatchers.IO) { probeDohCloudflare(asciiDomain) }
        listOf(system.await(), doh1.await(), doh8.await(), dohCf.await())
    }

    private fun probeSystemDns(domain: String, context: Context): DnsProbeResult {
        val resolvers = systemResolvers(context)
        if (resolvers.isEmpty()) {
            return DnsProbeResult(DnsResolver.SYSTEM, null, null, ProbeError.NO_RESOLVER)
        }
        val queryId = Random.nextInt(1, 0xFFFF)
        val query = DnsWireCodec.buildQuery(domain, queryId)
        var lastError = ProbeError.TIMEOUT
        for (resolver in resolvers.take(UDP_MAX_ATTEMPTS)) {
            try {
                DatagramSocket().use { socket ->
                    socket.soTimeout = UDP_TIMEOUT_MS
                    val start = SystemClock.elapsedRealtime()
                    socket.send(DatagramPacket(query, query.size, resolver, 53))
                    val buffer = ByteArray(2048)
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val latency = SystemClock.elapsedRealtime() - start
                    val ips = DnsWireCodec.parseResponse(packet.data.copyOf(packet.length), queryId)
                    if (ips == null) {
                        return DnsProbeResult(DnsResolver.SYSTEM, null, latency, ProbeError.BAD_RESPONSE)
                    }
                    if (ips.isEmpty()) {
                        return DnsProbeResult(DnsResolver.SYSTEM, emptyList(), latency, ProbeError.NO_ANSWER)
                    }
                    return DnsProbeResult(DnsResolver.SYSTEM, ips, latency, null)
                }
            } catch (e: SocketTimeoutException) {
                lastError = ProbeError.TIMEOUT
            } catch (e: IOException) {
                return DnsProbeResult(DnsResolver.SYSTEM, null, null, ProbeError.NETWORK)
            }
        }
        return DnsProbeResult(DnsResolver.SYSTEM, null, null, lastError)
    }

    private fun probeDoh(domain: String, resolver: DnsResolver, client: OkHttpClient): DnsProbeResult {
        val endpoint = resolver.dohUrl
            ?: return DnsProbeResult(resolver, null, null, ProbeError.NETWORK)
        val queryId = Random.nextInt(1, 0xFFFF)
        val query = DnsWireCodec.buildQuery(domain, queryId)
        val encoded = Base64.encodeToString(query, Base64.URL_SAFE or Base64.NO_WRAP)
        val request = Request.Builder()
            .url("$endpoint?dns=$encoded")
            .header("Accept", "application/dns-message")
            .build()
        val start = SystemClock.elapsedRealtime()
        return try {
            client.newCall(request).execute().use { response ->
                val latency = SystemClock.elapsedRealtime() - start
                if (!response.isSuccessful) {
                    return DnsProbeResult(resolver, null, latency, ProbeError.BAD_RESPONSE)
                }
                val body = response.body?.bytes()
                    ?: return DnsProbeResult(resolver, null, latency, ProbeError.BAD_RESPONSE)
                val ips = DnsWireCodec.parseResponse(body, queryId)
                if (ips == null) {
                    return DnsProbeResult(resolver, null, latency, ProbeError.BAD_RESPONSE)
                }
                if (ips.isEmpty()) {
                    return DnsProbeResult(resolver, emptyList(), latency, ProbeError.NO_ANSWER)
                }
                DnsProbeResult(resolver, ips, latency, null)
            }
        } catch (e: SocketTimeoutException) {
            DnsProbeResult(resolver, null, null, ProbeError.TIMEOUT)
        } catch (e: IOException) {
            DnsProbeResult(resolver, null, null, ProbeError.NETWORK)
        }
    }

    private fun probeDohCloudflare(domain: String): DnsProbeResult {
        val bootstrap = probeDoh(CLOUDFLARE_HOST, DnsResolver.DOH_1_1_1_1, plainClient)
        val bootstrapIps = bootstrap.ips
        if (bootstrapIps.isNullOrEmpty()) {
            return DnsProbeResult(
                DnsResolver.DOH_CLOUDFLARE,
                null,
                null,
                bootstrap.error ?: ProbeError.NETWORK
            )
        }
        val bootstrapDns = Dns { hostname ->
            if (hostname == CLOUDFLARE_HOST) {
                bootstrapIps.map { InetAddress.getByName(it) }
            } else {
                Dns.SYSTEM.lookup(hostname)
            }
        }
        val client = plainClient.newBuilder().dns(bootstrapDns).build()
        return probeDoh(domain, DnsResolver.DOH_CLOUDFLARE, client)
    }

    private fun systemResolvers(context: Context): List<InetAddress> {
        return try {
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                    ?: return emptyList()
            val network = connectivityManager.activeNetwork ?: return emptyList()
            connectivityManager.getLinkProperties(network)?.dnsServers.orEmpty()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
