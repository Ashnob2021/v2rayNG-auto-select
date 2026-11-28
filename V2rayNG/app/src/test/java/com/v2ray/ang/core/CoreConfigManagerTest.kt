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
    fun `speedtest dns keeps only direct doh entries in written order`() {
        val kept = CoreConfigManager.directDohOnlyDns(
            dnsWith(
                dohServer("https://208.67.222.222/dns-query"),
                V2rayConfig.DnsBean.ServersBean(address = "223.5.5.5", domains = listOf("geosite:cn")),
                "https://cloudflare-dns.com/dns-query",
                dohServer("https://1.1.1.1/dns-query"),
            )
        )
        assertEquals(
            listOf("https://208.67.222.222/dns-query", "https://1.1.1.1/dns-query"),
            kept!!.servers!!.map { (it as V2rayConfig.DnsBean.ServersBean).address }
        )
        assertEquals(AppConfig.TAG_DNS, kept.tag)
        assertNull(kept.hosts)
    }

    @Test
    fun `speedtest dns is null without direct doh entries`() {
        assertNull(
            CoreConfigManager.directDohOnlyDns(
                dnsWith(
                    V2rayConfig.DnsBean.ServersBean(address = "223.5.5.5", domains = listOf("geosite:cn")),
                    "https://cloudflare-dns.com/dns-query",
                )
            )
        )
        assertNull(CoreConfigManager.directDohOnlyDns(null))
    }
}
