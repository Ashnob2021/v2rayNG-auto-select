package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CoreOutboundBuilderTest {

    @Test
    fun `direct doh profile keeps its domain when resolve method is resolve and replace`() {
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(true, "2"))
    }

    @Test
    fun `other profile replaces its domain when resolve method is resolve and replace`() {
        assertTrue(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(false, "2"))
    }

    @Test
    fun `no profile replaces its domain when resolve method is resolve and add`() {
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(true, "1"))
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(false, "1"))
    }

    @Test
    fun `no profile replaces its domain when resolve method is do not resolve`() {
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(true, "0"))
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(false, "0"))
    }

    @Test
    fun `no profile replaces its domain when resolve method is unknown`() {
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(true, null))
        assertFalse(CoreOutboundBuilder.shouldReplaceDomainWithResolvedIp(false, null))
    }
}
