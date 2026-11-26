package com.v2ray.ang.ui.dnsdiagnose

import com.google.gson.JsonParser
import com.v2ray.ang.AppConfig

/**
 * Whether the direct-DoH fix is actually present in a generated runtime
 * config for [domain]. Pure logic, covered by unit tests.
 *
 * This is what "Fix verified" must mean: the generated config contains a
 * direct-DoH DNS entry for the domain, no hosts entry shadows it with a
 * (possibly poisoned) answer, and the proxy outbound for the domain has
 * `domainStrategy = "UseIP"` so the core consults that DNS entry when it
 * dials. A probe row alone cannot prove any of that: the probes resolve
 * through DoH directly, whether or not the fix was ever applied.
 */
fun isDirectDohAppliedInConfig(configJson: String?, domain: String): Boolean {
    val domainLower = domain.trim().lowercase()
    if (configJson.isNullOrBlank() || domainLower.isEmpty()) return false
    return try {
        val root = JsonParser.parseString(configJson).asJsonObject
        val dns = root.get("dns")?.takeIf { it.isJsonObject }?.asJsonObject ?: return false

        val servers = dns.get("servers")?.takeIf { it.isJsonArray }?.asJsonArray ?: return false
        val hasDirectDohServer = servers.any { server ->
            if (!server.isJsonObject) return@any false
            val obj = server.asJsonObject
            if (obj.get("tag")?.takeIf { it.isJsonPrimitive }?.asString != AppConfig.TAG_DIRECT_DOH) return@any false
            val address = obj.get("address")?.takeIf { it.isJsonPrimitive }?.asString ?: return@any false
            if (address !in AppConfig.DIRECT_DOH_ADDRESSES) return@any false
            val domains = obj.get("domains")?.takeIf { it.isJsonArray }?.asJsonArray ?: return@any false
            domains.any { it.isJsonPrimitive && it.asString.lowercase() == "full:$domainLower" }
        }
        if (!hasDirectDohServer) return false

        val hosts = dns.get("hosts")?.takeIf { it.isJsonObject }?.asJsonObject
        if (hosts != null && hosts.entrySet().any { it.key.lowercase() == domainLower }) return false

        val outbounds = root.get("outbounds")?.takeIf { it.isJsonArray }?.asJsonArray ?: return false
        outbounds.any { outbound ->
            if (!outbound.isJsonObject) return@any false
            val settings = outbound.asJsonObject.get("settings")?.takeIf { it.isJsonObject }?.asJsonObject ?: return@any false
            val addressMatches = settings.get("address")?.takeIf { it.isJsonPrimitive }?.asString?.lowercase() == domainLower ||
                settings.get("peers")?.takeIf { it.isJsonArray }?.asJsonArray?.firstOrNull()?.takeIf { it.isJsonObject }
                    ?.asJsonObject?.get("endpoint")?.takeIf { it.isJsonPrimitive }?.asString
                    ?.lowercase()?.startsWith("$domainLower:") == true
            if (!addressMatches) return@any false
            outbound.asJsonObject.get("streamSettings")?.takeIf { it.isJsonObject }?.asJsonObject
                ?.get("sockopt")?.takeIf { it.isJsonObject }?.asJsonObject
                ?.get("domainStrategy")?.takeIf { it.isJsonPrimitive }?.asString == "UseIP"
        }
    } catch (e: Exception) {
        false
    }
}
