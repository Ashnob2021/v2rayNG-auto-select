package com.v2ray.ang.ui.dnsdiagnose

/**
 * The verdict of one diagnose round, decided from the probe rows.
 * Pure logic, covered by unit tests.
 */
enum class DnsVerdictKind {
    /** Every resolver that answered agrees. */
    HEALTHY,

    /** The system resolver returns a bogon/private address, or answers that
     *  do not overlap with the DoH answers at all. */
    HIJACKED,

    /** The system resolver returns the known filtering sinkhole
     *  (10.10.34.34 / 10.10.34.35): the domain is filtered, not merely
     *  hijacked. Direct DoH fixes DNS, but the SNI is filtered too, so a
     *  fragment is also needed to reach the server. */
    FILTERED,

    /** Nothing answered: neither the system resolver nor any DoH endpoint. */
    UNRESOLVABLE,

    /** The system resolver answers but no DoH endpoint does, so the answers
     *  cannot be checked against a trusted source. */
    DOH_UNREACHABLE,

    /** The system resolver answers nothing while direct DoH works. */
    SYSTEM_DNS_FAILED,
}

data class DnsVerdict(
    val kind: DnsVerdictKind,
    val systemIps: List<String> = emptyList(),
    val dohIps: List<String> = emptyList(),
)

data class VerdictEvaluation(
    val verdict: DnsVerdict,
    /** True when the round should be run once more before concluding. */
    val needsRetry: Boolean,
)

/**
 * Decide the verdict from one probe round.
 *
 * IP sets are compared, not exact strings: a domain may legitimately
 * resolve to several addresses (round-robin), so any overlap between the
 * system answer and the DoH answers counts as agreement.
 */
fun evaluateVerdict(results: List<DnsProbeResult>): VerdictEvaluation {
    val system = results.firstOrNull { it.resolver == DnsResolver.SYSTEM }
    val dohResults = results.filter { it.resolver != DnsResolver.SYSTEM }
    val dohOk = dohResults.filter { it.ips != null && it.ips.isNotEmpty() }
    val systemIps = system?.ips.orEmpty()
    val systemOk = systemIps.isNotEmpty()
    val dohIps = dohOk.flatMap { it.ips.orEmpty() }.toSet().toList()

    if (!systemOk && dohOk.isEmpty()) {
        return VerdictEvaluation(DnsVerdict(DnsVerdictKind.UNRESOLVABLE), needsRetry = false)
    }
    if (!systemOk) {
        return VerdictEvaluation(
            DnsVerdict(DnsVerdictKind.SYSTEM_DNS_FAILED, dohIps = dohIps),
            needsRetry = false
        )
    }
    // The filtering sinkhole is checked before DOH_UNREACHABLE on
    // purpose: 10.10.34.34/35 alone proves the domain is filtered,
    // even when no DoH endpoint answered to confirm the real address.
    // In that case the verdict is FILTERED with an empty DoH list, and
    // the screen says so instead of hiding the filtering behind
    // "DoH does not answer".
    if (systemIps.any { isFilteringIp(it) }) {
        return VerdictEvaluation(
            DnsVerdict(DnsVerdictKind.FILTERED, systemIps = systemIps, dohIps = dohIps),
            needsRetry = false
        )
    }
    if (dohOk.isEmpty()) {
        return VerdictEvaluation(
            DnsVerdict(DnsVerdictKind.DOH_UNREACHABLE, systemIps = systemIps),
            needsRetry = false
        )
    }
    if (systemIps.any { isBogonIp(it) }) {
        return VerdictEvaluation(
            DnsVerdict(DnsVerdictKind.HIJACKED, systemIps = systemIps, dohIps = dohIps),
            needsRetry = false
        )
    }
    val systemSet = systemIps.toSet()
    val dohSet = dohIps.toSet()
    if (systemSet.intersect(dohSet).isNotEmpty()) {
        return VerdictEvaluation(
            DnsVerdict(DnsVerdictKind.HEALTHY, systemIps = systemIps, dohIps = dohIps),
            // No retry: DoH endpoints may legitimately return different
            // subsets of a round-robin pool, and the verdict is already
            // conclusive (the system answer overlaps the DoH union).
            needsRetry = false
        )
    }
    // Disjoint public answers with no bogon: most likely a hijack, but DNS
    // can be flaky, so the caller retries once before concluding.
    return VerdictEvaluation(
        DnsVerdict(DnsVerdictKind.HIJACKED, systemIps = systemIps, dohIps = dohIps),
        needsRetry = true
    )
}

/**
 * True for the known filtering sinkhole addresses: when the system
 * resolver returns one of these for a public domain, the domain is
 * filtered (for example, pages.dev on Iranian networks returns
 * 10.10.34.35). This is a subset of [isBogonIp] and must be checked
 * first, so a filtered domain is not reported as a generic hijack.
 */
fun isFilteringIp(ip: String): Boolean {
    return ip.trim() == "10.10.34.34" || ip.trim() == "10.10.34.35"
}

/**
 * True for addresses a public DNS answer should never contain:
 * RFC1918, loopback, 0/8, link-local, shared address space, and the
 * IPv6 equivalents. A resolver answering one of these for a public domain
 * is proof of hijacking, not a flaky race.
 */
fun isBogonIp(ip: String): Boolean {
    val trimmed = ip.trim()
    val v4 = trimmed.split(".")
    if (v4.size == 4) {
        val octets = v4.map { it.toIntOrNull() ?: return false }
        if (octets.any { it < 0 || it > 255 }) return false
        val (a, b) = octets
        return when {
            a == 10 -> true
            a == 172 && b in 16..31 -> true
            a == 192 && b == 168 -> true
            a == 127 -> true
            a == 0 -> true
            a == 169 && b == 254 -> true
            a == 100 && b in 64..127 -> true
            else -> false
        }
    }
    val lower = trimmed.lowercase()
    if (lower == "::1") return true
    val firstHextet = lower.substringBefore(":")
    return when {
        firstHextet.startsWith("fe8") || firstHextet.startsWith("fe9") ||
            firstHextet.startsWith("fea") || firstHextet.startsWith("feb") -> true
        firstHextet.startsWith("fc") || firstHextet.startsWith("fd") -> true
        else -> false
    }
}
