package com.v2ray.ang.ui.dnsdiagnose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class CoreTestTest {

    @Test
    fun `non-negative delay means success`() {
        assertEquals(CoreTestState.Success(123L), coreTestStateFromDelay(123L))
        assertEquals(CoreTestState.Success(0L), coreTestStateFromDelay(0L))
    }

    @Test
    fun `negative delay means failed`() {
        assertEquals(CoreTestState.Failed, coreTestStateFromDelay(-1L))
    }
}
