package com.v2ray.ang.ui.dnsdiagnose

/**
 * DNS probe result for one resolver.
 *
 * [ips] is non-null only when the resolver answered with a well-formed
 * response; an empty list means a valid response with no A records.
 * [error] is non-null when the probe failed for that resolver.
 * [queriedServers] holds the resolver server addresses actually asked,
 * for the system row: the DNS servers the active network assigned
 * (usually the ISP's), read from its link properties. Empty for DoH
 * rows, whose endpoint is in [DnsResolver.dohUrl].
 */
data class DnsProbeResult(
    val resolver: DnsResolver,
    val ips: List<String>?,
    val latencyMs: Long?,
    val error: ProbeError?,
    val queriedServers: List<String> = emptyList(),
)

enum class DnsResolver(
    /** Label shown in the UI for the DoH rows. The system row uses a string resource instead. */
    val displayName: String,
    /** DoH endpoint, or null for the system UDP resolver. */
    val dohUrl: String?,
) {
    SYSTEM("System DNS", null),
    DOH_1_1_1_1("DoH 1.1.1.1", "https://1.1.1.1/dns-query"),
    DOH_1_0_0_1("DoH 1.0.0.1", "https://1.0.0.1/dns-query"),
    DOH_8_8_8_8("DoH 8.8.8.8", "https://8.8.8.8/dns-query"),
    DOH_8_8_4_4("DoH 8.8.4.4", "https://8.8.4.4/dns-query"),
    DOH_9_9_9_9("DoH 9.9.9.9", "https://9.9.9.9/dns-query"),
    DOH_CLOUDFLARE("DoH cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
}

enum class ProbeError {
    TIMEOUT,
    NETWORK,
    NO_ANSWER,
    BAD_RESPONSE,
    NO_RESOLVER,
}
