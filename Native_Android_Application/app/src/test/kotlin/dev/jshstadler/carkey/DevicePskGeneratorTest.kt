package dev.jshstadler.carkey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DevicePskGeneratorTest {
    @Test
    fun `generated PSK is 32 lowercase hexadecimal characters`() {
        val psk = DevicePskGenerator.generate()

        assertEquals(32, psk.length)
        assertTrue(psk.matches(Regex("^[0-9a-f]{32}$")))
    }

    @Test
    fun `consecutive generated PSKs differ`() {
        assertNotEquals(DevicePskGenerator.generate(), DevicePskGenerator.generate())
    }

    @Test
    fun `hex encoding preserves leading zeroes and unsigned bytes`() {
        val encoded = with(DevicePskGenerator) {
            byteArrayOf(0x00, 0x0f, 0x10, 0xff.toByte()).toLowercaseHex()
        }

        assertEquals("000f10ff", encoded)
    }
}
