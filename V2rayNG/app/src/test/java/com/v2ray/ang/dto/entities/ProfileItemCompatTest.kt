package com.v2ray.ang.dto.entities

import com.v2ray.ang.util.JsonUtil
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Backward compatibility for the direct-DoH ordering field: profiles
 * stored before directDohPreferred existed must still decode, with the
 * field null (standard endpoint order).
 */
class ProfileItemCompatTest {

    @Test
    fun `profile json without directDohPreferred decodes to null`() {
        val profile = JsonUtil.fromJson(
            """{"configType":"VLESS","server":"nlp.dandev.de5.net","serverPort":"15304","directDohEnabled":true}""",
            ProfileItem::class.java
        )
        assertTrue(profile!!.directDohEnabled)
        assertNull(profile.directDohPreferred)
    }

    @Test
    fun `profile json with directDohPreferred round trips`() {
        val profile = JsonUtil.fromJson(
            """{"configType":"VLESS","directDohEnabled":true,"directDohPreferred":"https://208.67.222.222/dns-query"}""",
            ProfileItem::class.java
        )
        assertEquals("https://208.67.222.222/dns-query", profile!!.directDohPreferred)
        val reparsed = JsonUtil.fromJson(JsonUtil.toJson(profile), ProfileItem::class.java)
        assertEquals("https://208.67.222.222/dns-query", reparsed!!.directDohPreferred)
    }
}
