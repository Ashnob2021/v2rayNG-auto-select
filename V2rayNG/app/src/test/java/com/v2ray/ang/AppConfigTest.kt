package com.v2ray.ang

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AppConfigTest {

    @Test
    fun `preferred endpoint moves first and rest keep order`() {
        val ordered = AppConfig.orderedDirectDohAddresses(
            listOf("https://208.67.222.222/dns-query")
        )
        assertEquals("https://208.67.222.222/dns-query", ordered.first())
        assertEquals(AppConfig.DIRECT_DOH_ADDRESSES.size, ordered.size)
        assertEquals(AppConfig.DIRECT_DOH_ADDRESSES.toSet(), ordered.toSet())
        assertEquals(
            AppConfig.DIRECT_DOH_ADDRESSES.filter { it != "https://208.67.222.222/dns-query" },
            ordered.drop(1)
        )
    }

    @Test
    fun `unknown preferred endpoint is dropped`() {
        val ordered = AppConfig.orderedDirectDohAddresses(
            listOf("https://cloudflare-dns.com/dns-query")
        )
        assertEquals(AppConfig.DIRECT_DOH_ADDRESSES, ordered)
    }

    @Test
    fun `empty preferred keeps standard order`() {
        assertEquals(
            AppConfig.DIRECT_DOH_ADDRESSES,
            AppConfig.orderedDirectDohAddresses(emptyList())
        )
    }

    @Test
    fun `duplicate preferred is written once`() {
        val ordered = AppConfig.orderedDirectDohAddresses(
            listOf("https://208.67.222.222/dns-query", "https://208.67.222.222/dns-query")
        )
        assertEquals(1, ordered.count { it == "https://208.67.222.222/dns-query" })
        assertTrue(ordered.size == AppConfig.DIRECT_DOH_ADDRESSES.size)
    }
}
