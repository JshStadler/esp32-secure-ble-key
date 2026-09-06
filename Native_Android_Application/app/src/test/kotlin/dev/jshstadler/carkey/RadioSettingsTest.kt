package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test

class RadioSettingsTest {
    @Test fun preservesExistingDefaultsAndExactBleUnits() {
        assertEquals(RadioSettings.DEFAULT, RadioSettings.fromInput("50-100", "200-400", "60"))
        assertEquals("50-100", RadioSettings.DEFAULT.recentText())
        assertEquals("200-400", RadioSettings.DEFAULT.inactiveText())
        assertArrayEquals(byteArrayOf(80, 0, -96, 0, 64, 1, -128, 2, 60, 0), RadioSettings.DEFAULT.encode())
        assertEquals(33, RadioSettings.fromInput("20.625", "2000", "5").fastMin)
    }
    @Test fun supportsFixedIntervalsAndLimits() {
        val config = RadioSettings.fromInput("20", "2000", "3600")
        assertTrue(config.valid())
        assertEquals("20", config.recentText())
        assertEquals("2000", config.inactiveText())
    }
    @Test fun rejectsUnsafeInvertedOrUnrepresentableValues() {
        listOf(Triple("19", "400", "60"), Triple("2001", "2001", "60"),
            Triple("50-20", "400", "60"), Triple("100", "50", "60"),
            Triple("100", "200-100", "60"), Triple("100", "400", "0"),
            Triple("100", "400", "3601"), Triple("100", "400", "abc"),
            Triple("100", "400", "60.5"), Triple("21", "400", "60"),
            Triple("50-100-200", "400", "60"), Triple("", "400", "60")
        ).forEach { (a, b, c) -> assertTrue(runCatching { RadioSettings.fromInput(a, b, c) }.isFailure) }
    }
    @Test fun authenticatesExactSettingsAndFreshNonce() {
        val nonce = ByteArray(16) { it.toByte() }
        val packet = RadioSettings.DEFAULT.packet(nonce, "test-key")
        assertEquals(43, packet.size)
        assertEquals(4.toByte(), packet[0])
        assertArrayEquals(RadioSettings.DEFAULT.encode(), packet.copyOfRange(1, 11))
        assertFalse(packet.contentEquals(RadioSettings.DEFAULT.copy(idleSeconds = 120).packet(nonce, "test-key")))
        assertFalse(packet.contentEquals(RadioSettings.DEFAULT.packet(ByteArray(16), "test-key")))
        assertFalse(packet.contentEquals(RadioSettings.DEFAULT.packet(nonce, "other-key")))
        val transcript = "BLEKEY-RADIO1\u0000car-main\u0000".toByteArray() + nonce + packet.copyOfRange(1, 11)
        assertEquals(49, transcript.size)
        assertArrayEquals(CarKeyProtocol.hmac(transcript, "test-key"), packet.copyOfRange(11, 43))
        // Independently calculated with Python's hmac/struct implementations.
        assertEquals("864d65c712232ba2baf4ac0b64dd7924c1321b428ceeaf471118fef5aec2016e",
            packet.copyOfRange(11, 43).joinToString("") { "%02x".format(it) })
        assertTrue(runCatching { RadioSettings.DEFAULT.packet(ByteArray(15), "test-key") }.isFailure)
    }
}
