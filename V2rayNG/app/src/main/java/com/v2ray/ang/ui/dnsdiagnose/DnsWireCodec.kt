package com.v2ray.ang.ui.dnsdiagnose

import java.io.ByteArrayOutputStream

/**
 * Minimal DNS wire-format codec for A-record queries.
 *
 * Pure functions, no Android or network dependencies, covered by unit tests.
 * Only what the diagnose screen needs: one question, A records in the
 * answer section. Compression pointers in names are handled when skipping.
 */
object DnsWireCodec {

    /**
     * Build a standard query (RD set, QTYPE A, QCLASS IN) for [domain].
     * [id] is the 16-bit query id echoed back by the server.
     */
    fun buildQuery(domain: String, id: Int): ByteArray {
        val asciiDomain = domain.trim().trimEnd('.')
        val out = ByteArrayOutputStream()
        // Header: id, flags (RD), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        out.write(id shr 8)
        out.write(id)
        out.write(0x01)
        out.write(0x00)
        out.write(0)
        out.write(1)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(0)
        // Question: QNAME, QTYPE A, QCLASS IN
        for (label in asciiDomain.split(".")) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        out.write(0)
        out.write(1)
        out.write(0)
        out.write(1)
        return out.toByteArray()
    }

    /**
     * Parse a DNS response and return its A-record addresses.
     *
     * Returns null when the response is malformed, truncated, or answers a
     * different query id. Returns an empty list for a well-formed response
     * with no A records (including NXDOMAIN).
     */
    fun parseResponse(data: ByteArray, expectedId: Int): List<String>? {
        if (data.size < 12) return null
        if (u16(data, 0) != expectedId) return null
        val rcode = u16(data, 2) and 0xF
        if (rcode == 3) return emptyList() // NXDOMAIN: the domain does not exist
        if (rcode != 0) return null
        val qdCount = u16(data, 4)
        val anCount = u16(data, 6)
        var pos = 12
        repeat(qdCount) {
            pos = skipName(data, pos) ?: return null
            if (pos + 4 > data.size) return null
            pos += 4
        }
        val ips = mutableListOf<String>()
        repeat(anCount) {
            pos = skipName(data, pos) ?: return null
            if (pos + 10 > data.size) return null
            val type = u16(data, pos)
            val rdLength = u16(data, pos + 8)
            pos += 10
            if (pos + rdLength > data.size) return null
            if (type == 1 && rdLength == 4) {
                ips.add(data.copyOfRange(pos, pos + 4).joinToString(".") { (it.toInt() and 0xFF).toString() })
            }
            pos += rdLength
        }
        return ips
    }

    private fun u16(data: ByteArray, pos: Int): Int =
        ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)

    /** Skip one DNS name starting at [pos]; returns the position after it, or null if malformed. */
    private fun skipName(data: ByteArray, pos: Int): Int? {
        var p = pos
        while (true) {
            if (p >= data.size) return null
            val len = data[p].toInt() and 0xFF
            if (len == 0) return p + 1
            if (len and 0xC0 == 0xC0) {
                // Compression pointer: two bytes, and the name ends here.
                if (p + 1 >= data.size) return null
                return p + 2
            }
            if (len and 0xC0 != 0) return null
            p += 1 + len
        }
    }
}
