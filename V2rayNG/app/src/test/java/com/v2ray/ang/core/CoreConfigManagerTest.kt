package com.v2ray.ang.core

import com.v2ray.ang.core.CoreConfigManager.OutboundDomainResolution
import org.junit.jupiter.api.Assertions.assertEquals
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
}
