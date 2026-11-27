package com.v2ray.ang.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class SniCaseTest {

    @Test
    fun `all lowercase sni gets first letter of each label capitalized`() {
        assertEquals("Yrui0hd835j2.Pages.Dev", alterSniCase("yrui0hd835j2.pages.dev"))
    }

    @Test
    fun `mixed case sni is lowercased`() {
        assertEquals("pr2x23nrdweakz7tkrna.pages.dev", alterSniCase("pR2X23nrDWeakz7TKRNA.pAges.Dev"))
    }

    @Test
    fun `null sni stays null`() {
        assertNull(alterSniCase(null))
    }
}
