package dev.jshstadler.carkey

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CarKeyProtocolTest {
    @Test fun buildsKnownHmacSha256Command() {
        val result = CarKeyProtocol.command(CarKeyProtocol.PRESS_COMMAND, "challenge".toByteArray(), "secret")
        assertEquals(33, result.size)
        assertEquals(CarKeyProtocol.PRESS_COMMAND, result.first())
        assertEquals("a1e505e96c6aa1ece082bb9efb06c80f12913d217a7ac2b08b347630787d1da0", result.drop(1).joinToString("") { "%02x".format(it) })
    }

    @Test fun pskUpdateContainsHmacSeparatorAndUtf8Key() {
        val result = CarKeyProtocol.pskUpdate(byteArrayOf(1, 2, 3), "old", "new-key")
        assertEquals(0, result[32].toInt())
        assertArrayEquals("new-key".toByteArray(), result.copyOfRange(33, result.size))
    }
}
