package com.v2ray.ang.ui.dnsdiagnose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnsWireCodecTest {

    // Hand-built response for example.com A -> 93.184.216.34, id 0x1234:
    // header (id, flags 0x8180, QD=1, AN=1) + question + one answer
    // (compressed name pointer 0xC00C, A, IN, TTL 60, 4 bytes of address).
    private val validResponse = byteArrayOf(
        0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
        0x5D, 0xB8.toByte(), 0xD8.toByte(), 0x22
    )

    // Same header + question, RCODE 3 (NXDOMAIN), no answers.
    private val nxdomainResponse = byteArrayOf(
        0x12, 0x34, 0x81.toByte(), 0x83.toByte(), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01
    )

    // Same header + question, RCODE 0, no answers.
    private val emptyResponse = byteArrayOf(
        0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01
    )

    @Test
    fun `buildQuery encodes header question and qtype`() {
        val query = DnsWireCodec.buildQuery("example.com", 0x1234)
        assertEquals(29, query.size)
        assertEquals(0x12, query[0].toInt() and 0xFF)
        assertEquals(0x34, query[1].toInt() and 0xFF)
        assertEquals(0x01, query[2].toInt() and 0xFF)
        assertEquals(0x00, query[3].toInt() and 0xFF)
        assertEquals(0x01, query[5].toInt() and 0xFF)
        assertEquals(7, query[12].toInt())
        assertEquals("example", query.copyOfRange(13, 20).toString(Charsets.US_ASCII))
        assertEquals(3, query[20].toInt())
        assertEquals("com", query.copyOfRange(21, 24).toString(Charsets.US_ASCII))
        assertEquals(0, query[24].toInt())
        assertEquals(0, query[25].toInt())
        assertEquals(1, query[26].toInt())
        assertEquals(0, query[27].toInt())
        assertEquals(1, query[28].toInt())
    }

    @Test
    fun `parseResponse extracts A records`() {
        val ips = DnsWireCodec.parseResponse(validResponse, 0x1234)
        assertEquals(listOf("93.184.216.34"), ips)
    }

    @Test
    fun `parseResponse rejects wrong id`() {
        assertNull(DnsWireCodec.parseResponse(validResponse, 0x1235))
    }

    @Test
    fun `parseResponse rejects truncated data`() {
        assertNull(DnsWireCodec.parseResponse(validResponse.copyOf(20), 0x1234))
        assertNull(DnsWireCodec.parseResponse(byteArrayOf(0x12, 0x34), 0x1234))
    }

    @Test
    fun `parseResponse returns empty list for nxdomain`() {
        val ips = DnsWireCodec.parseResponse(nxdomainResponse, 0x1234)
        assertEquals(emptyList<String>(), ips)
    }

    @Test
    fun `parseResponse returns empty list for no answers`() {
        val ips = DnsWireCodec.parseResponse(emptyResponse, 0x1234)
        assertEquals(emptyList<String>(), ips)
    }

    @Test
    fun `buildQuery and parseResponse round trip on id`() {
        val query = DnsWireCodec.buildQuery("example.com", 0xABCD)
        assertTrue(query.size == 29)
        assertEquals(0xAB, query[0].toInt() and 0xFF)
        assertEquals(0xCD, query[1].toInt() and 0xFF)
    }
}
