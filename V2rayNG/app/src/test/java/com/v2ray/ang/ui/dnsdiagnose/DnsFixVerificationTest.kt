package com.v2ray.ang.ui.dnsdiagnose

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnsFixVerificationTest {

    private fun config(
        servers: String = """{"address": "https://1.1.1.1/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}""",
        hosts: String = "{}",
        outboundAddress: String = "nlp.dandev.de5.net",
        domainStrategy: String? = "UseIP",
    ): String {
        val sockopt = if (domainStrategy == null) {
            ""
        } else {
            """, "sockopt": {"domainStrategy": "$domainStrategy"}"""
        }
        return """
            {
              "dns": {"hosts": $hosts, "servers": [$servers, "https://cloudflare-dns.com/dns-query"]},
              "outbounds": [
                {"protocol": "vless", "settings": {"address": "$outboundAddress", "port": 15304}, "streamSettings": {"network": "tcp"$sockopt}, "tag": "proxy"},
                {"protocol": "freedom", "tag": "direct"}
              ]
            }
        """.trimIndent()
    }

    @Test
    fun `applied config is verified`() {
        assertTrue(isDirectDohAppliedInConfig(config(), "nlp.dandev.de5.net"))
    }

    @Test
    fun `config with a newer doh address is verified`() {
        assertTrue(
            isDirectDohAppliedInConfig(
                config(servers = """{"address": "https://208.67.222.222/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}"""),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `config with a small operator doh address is verified`() {
        assertTrue(
            isDirectDohAppliedInConfig(
                config(servers = """{"address": "https://185.222.222.222/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}"""),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `domain match is case insensitive`() {
        assertTrue(isDirectDohAppliedInConfig(config(outboundAddress = "Nlp.Dandev.De5.Net"), "NLP.DANDEV.DE5.NET"))
    }

    @Test
    fun `config without useip sockopt is not verified`() {
        assertFalse(isDirectDohAppliedInConfig(config(domainStrategy = null), "nlp.dandev.de5.net"))
    }

    @Test
    fun `config with asis domain strategy is not verified`() {
        assertFalse(isDirectDohAppliedInConfig(config(domainStrategy = "AsIs"), "nlp.dandev.de5.net"))
    }

    @Test
    fun `config without direct doh server is not verified`() {
        assertFalse(
            isDirectDohAppliedInConfig(
                config(servers = """{"address": "https://cloudflare-dns.com/dns-query", "domains": ["geosite:google"]}"""),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `config with another known doh address is verified`() {
        assertTrue(
            isDirectDohAppliedInConfig(
                config(servers = """{"address": "https://8.8.8.8/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}"""),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `config with several direct doh servers is verified`() {
        assertTrue(
            isDirectDohAppliedInConfig(
                config(
                    servers = """{"address": "https://1.1.1.1/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}, {"address": "https://9.9.9.9/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}"""
                ),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `config with an unknown doh address is not verified`() {
        assertFalse(
            isDirectDohAppliedInConfig(
                config(servers = """{"address": "https://dns.example.com/dns-query", "domains": ["full:nlp.dandev.de5.net"], "tag": "direct-doh"}"""),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `config with a poisoned hosts entry is not verified`() {
        assertFalse(
            isDirectDohAppliedInConfig(
                config(hosts = """{"nlp.dandev.de5.net": "10.10.34.35"}"""),
                "nlp.dandev.de5.net"
            )
        )
    }

    @Test
    fun `config for another domain is not verified`() {
        assertFalse(isDirectDohAppliedInConfig(config(), "example.com"))
    }

    @Test
    fun `invalid json is not verified`() {
        assertFalse(isDirectDohAppliedInConfig("{not json", "nlp.dandev.de5.net"))
        assertFalse(isDirectDohAppliedInConfig("", "nlp.dandev.de5.net"))
        assertFalse(isDirectDohAppliedInConfig(null, "nlp.dandev.de5.net"))
    }

    @Test
    fun `config without dns is not verified`() {
        assertFalse(isDirectDohAppliedInConfig("""{"outbounds": []}""", "nlp.dandev.de5.net"))
    }
}
