package com.v2ray.ang.ui.dnsdiagnose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WsProbeTest {

    private fun ws(outcome: WsOutcome, httpStatus: Int? = null) =
        WsProbeResult("/?ed=2048", outcome, httpStatus, 42L)

    @Test
    fun `upgraded means the transport works`() {
        assertEquals(WsVerdictKind.OK, evaluateWsVerdict(ws(WsOutcome.UPGRADED, 101)))
    }

    @Test
    fun `http error means the server answered but refused the upgrade`() {
        assertEquals(WsVerdictKind.REACHED, evaluateWsVerdict(ws(WsOutcome.HTTP_ERROR, 403)))
    }

    @Test
    fun `timeout reset and network mean the transport is blocked`() {
        assertEquals(WsVerdictKind.BLOCKED, evaluateWsVerdict(ws(WsOutcome.TIMEOUT)))
        assertEquals(WsVerdictKind.BLOCKED, evaluateWsVerdict(ws(WsOutcome.RESET)))
        assertEquals(WsVerdictKind.BLOCKED, evaluateWsVerdict(ws(WsOutcome.NETWORK)))
    }

    @Test
    fun `no result means skipped`() {
        assertEquals(WsVerdictKind.SKIPPED, evaluateWsVerdict(null))
    }

    @Test
    fun `upgraded and http error prove the server answered`() {
        assertTrue(wsReachedServer(ws(WsOutcome.UPGRADED, 101)))
        assertTrue(wsReachedServer(ws(WsOutcome.HTTP_ERROR, 400)))
        assertFalse(wsReachedServer(ws(WsOutcome.TIMEOUT)))
        assertFalse(wsReachedServer(ws(WsOutcome.RESET)))
        assertFalse(wsReachedServer(ws(WsOutcome.NETWORK)))
    }

    @Test
    fun `status line parsing`() {
        assertEquals(101, parseHttpStatus("HTTP/1.1 101 Switching Protocols"))
        assertEquals(403, parseHttpStatus("HTTP/1.1 403 Forbidden"))
        assertEquals(200, parseHttpStatus("HTTP/2 200"))
        assertNull(parseHttpStatus(null))
        assertNull(parseHttpStatus(""))
        assertNull(parseHttpStatus("HTTP/1.1"))
        assertNull(parseHttpStatus("not a status line"))
        assertNull(parseHttpStatus("HTTP/1.1 abc"))
        assertNull(parseHttpStatus("HTTP/1.1 99"))
        assertNull(parseHttpStatus("HTTP/1.1 600"))
    }

    @Test
    fun `only the ws network is a websocket transport`() {
        assertTrue(isWsTransport("ws"))
        assertTrue(isWsTransport("WS"))
        assertFalse(isWsTransport("tcp"))
        assertFalse(isWsTransport("grpc"))
        assertFalse(isWsTransport(null))
    }
}
