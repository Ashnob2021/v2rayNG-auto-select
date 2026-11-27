package com.v2ray.ang.util

/**
 * The SNI with its letter case changed, to evade case-sensitive SNI
 * filtering. A SNI that contains any uppercase letter is lowercased; an
 * all-lowercase SNI gets the first letter of each label capitalized.
 * Pure logic, covered by unit tests. Used by the diagnose probe (as the
 * case-variant handshake) and by the mixed-case SNI fix (as the SNI the
 * connection actually sends when the fix is on).
 */
fun alterSniCase(sni: String?): String? {
    if (sni == null) return null
    if (sni.any { it.isUpperCase() }) return sni.lowercase()
    return sni.split(".").joinToString(".") { label ->
        label.replaceFirstChar { it.uppercaseChar() }
    }
}
