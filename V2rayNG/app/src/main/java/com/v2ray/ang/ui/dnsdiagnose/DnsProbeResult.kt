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
    // More operators, same purpose: a filtered network blocks DoH
    // per IP/path, so the biggest endpoints (Cloudflare, Google,
    // Quad9) are the most likely to be blocked, while a smaller
    // operator's address may still be reachable.
    DOH_149_112_112_112("DoH 149.112.112.112", "https://149.112.112.112/dns-query"),
    DOH_208_67_222_222("DoH 208.67.222.222", "https://208.67.222.222/dns-query"),
    DOH_94_140_14_14("DoH 94.140.14.14", "https://94.140.14.14/dns-query"),
    DOH_76_76_2_0("DoH 76.76.2.0", "https://76.76.2.0/dns-query"),
    DOH_185_222_222_222("DoH 185.222.222.222", "https://185.222.222.222/dns-query"),
    DOH_194_242_2_2("DoH 194.242.2.2", "https://194.242.2.2/dns-query"),
    DOH_77_88_8_8("DoH 77.88.8.8", "https://77.88.8.8/dns-query"),
    DOH_CLOUDFLARE("DoH cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
}

enum class ProbeError {
    TIMEOUT,
    NETWORK,
    NO_ANSWER,
    BAD_RESPONSE,
    NO_RESOLVER,
}
