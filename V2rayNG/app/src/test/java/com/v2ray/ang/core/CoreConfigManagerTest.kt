package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.CoreConfigManager.OutboundDomainResolution
import com.v2ray.ang.dto.V2rayConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class CoreConfigManagerTest {

    private val directDohDomains = setOf("nlp.dandev.de5.net")

    @Test
    fun `direct doh domain uses core dns when resolve method is do not resolve`() {
        assertEquals(
            OutboundDomainResolution.USE_CORE_DNS,
            CoreConfigManager.planOutboundDomainResolution("nlp.dandev.de5.net", directDohDomains, "0", false)
        )
    }

    @Test
    fun `direct doh domain uses core dns when resolve method is resolve and add`() {
        assertEquals(
            OutboundDomainResolution.USE_CORE_DNS,
            CoreConfigManager.planOutboundDomainResolution("nlp.dandev.de5.net", directDohDomains, "1", false)
        )
    }

    @Test
    fun `direct doh domain uses core dns when resolve method is resolve and replace`() {
        assertEquals(
            OutboundDomainResolution.USE_CORE_DNS,
            CoreConfigManager.planOutboundDomainResolution("nlp.dandev.de5.net", directDohDomains, "2", false)
        )
    }

    @Test
    fun `direct doh domain match is case insensitive`() {
        assertEquals(
            OutboundDomainResolution.USE_CORE_DNS,
            CoreConfigManager.planOutboundDomainResolution("Nlp.Dandev.De5.Net", directDohDomains, "0", false)
        )
    }

    @Test
    fun `other domain is untouched when resolve method is do not resolve`() {
        assertEquals(
            OutboundDomainResolution.NONE,
            CoreConfigManager.planOutboundDomainResolution("example.com", directDohDomains, "0", false)
        )
    }

    @Test
    fun `other domain is untouched when resolve method is resolve and replace`() {
        assertEquals(
            OutboundDomainResolution.NONE,
            CoreConfigManager.planOutboundDomainResolution("example.com", directDohDomains, "2", false)
        )
    }

    @Test
    fun `other domain is untouched when resolve method is unknown`() {
        assertEquals(
            OutboundDomainResolution.NONE,
            CoreConfigManager.planOutboundDomainResolution("example.com", directDohDomains, null, false)
        )
    }

    @Test
    fun `other domain with existing hosts entry uses it when resolve method is resolve and add`() {
        assertEquals(
            OutboundDomainResolution.USE_EXISTING_HOSTS,
            CoreConfigManager.planOutboundDomainResolution("example.com", directDohDomains, "1", true)
        )
    }

    @Test
    fun `other domain is pre resolved when resolve method is resolve and add`() {
        assertEquals(
            OutboundDomainResolution.PRE_RESOLVE_TO_HOSTS,
            CoreConfigManager.planOutboundDomainResolution("example.com", directDohDomains, "1", false)
        )
    }

    private fun dohServer(address: String) = V2rayConfig.DnsBean.ServersBean(
        address = address,
        domains = listOf("full:nlp.dandev.de5.net"),
        tag = AppConfig.TAG_DIRECT_DOH,
    )

    private fun dnsWith(vararg servers: Any) = V2rayConfig.DnsBean(
        servers = ArrayList(servers.toList()),
        hosts = mapOf("dns.google" to listOf("8.8.8.8")),
        tag = AppConfig.TAG_DNS,
    )

    @Test
    fun `direct doh domains are the full domains lowercased without the prefix`() {
        assertEquals(
            setOf("nlp.dandev.de5.net"),
            CoreConfigManager.directDohDomainsOf(
                dnsWith(
                    dohServer("https://208.67.222.222/dns-query"),
                    V2rayConfig.DnsBean.ServersBean(address = "223.5.5.5", domains = listOf("geosite:cn")),
                    dohServer("https://1.1.1.1/dns-query"),
                )
            )
        )
        assertEquals(
            emptySet<String>(),
            CoreConfigManager.directDohDomainsOf(
                dnsWith(
                    V2rayConfig.DnsBean.ServersBean(address = "223.5.5.5", domains = listOf("geosite:cn")),
                )
            )
        )
        assertEquals(emptySet<String>(), CoreConfigManager.directDohDomainsOf(null))
    }

    private fun proxyOutbound(protocol: String, address: String) = V2rayConfig.OutboundBean(
        protocol = protocol,
        settings = V2rayConfig.OutboundBean.OutSettingsBean(address = address, port = 15304),
    )

    @Test
    fun `outbound address is rewritten to the probe ip only for direct doh domains`() {
        val domains = setOf("nlp.dandev.de5.net")
        val matching = proxyOutbound("vless", "nlp.dandev.de5.net")
        val otherDomain = proxyOutbound("trojan", "www.speedtest.net")
        val ipAddress = proxyOutbound("vless", "1.2.3.4")
        val upperCase = proxyOutbound("vless", "NLP.DANDEV.DE5.NET")
        val wireguard = proxyOutbound("wireguard", "nlp.dandev.de5.net")
        CoreConfigManager.rewriteOutboundAddressesToProbeIp(
            listOf(matching, otherDomain, ipAddress, upperCase, wireguard),
            "91.198.77.180",
            domains,
        )
        assertEquals("91.198.77.180", matching.getServerAddress())
        assertEquals("www.speedtest.net", otherDomain.getServerAddress())
        assertEquals("1.2.3.4", ipAddress.getServerAddress())
        assertEquals("91.198.77.180", upperCase.getServerAddress())
        // WireGuard keeps its address: it lives in the peer endpoint,
        // not in settings.
        assertEquals("nlp.dandev.de5.net", wireguard.settings?.address)
    }

    @Test
    fun `no outbound is rewritten without direct doh domains`() {
        val outbound = proxyOutbound("vless", "nlp.dandev.de5.net")
        CoreConfigManager.rewriteOutboundAddressesToProbeIp(
            listOf(outbound),
            "91.198.77.180",
            emptySet(),
        )
        assertEquals("nlp.dandev.de5.net", outbound.getServerAddress())
    }
}
