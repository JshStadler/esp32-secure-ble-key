package dev.jshstadler.carkey

import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CarKeyProtocolTest {
    @Test fun pskUpdateContainsHmacSeparatorAndUtf8Key() {
        val result = CarKeyProtocol.pskUpdate(BleDeviceProfiles.CAR, byteArrayOf(1, 2, 3), "old", "new-key")
        assertEquals(0, result[32].toInt())
        assertArrayEquals("new-key".toByteArray(), result.copyOfRange(33, result.size))
    }

    @Test fun v2BindsProtocolDeviceCommandAndChallenge() {
        val challenge = ByteArray(16) { it.toByte() }
        val result = CarKeyProtocol.command(BleDeviceProfiles.GATE, CarKeyProtocol.PRESS_COMMAND, challenge, "secret")

        assertEquals(33, result.size)
        assertEquals(CarKeyProtocol.PRESS_COMMAND, result.first())
        assertEquals(
            "BLEKEY-V2\u0000gate-main\u0000\u0002" + challenge.toString(StandardCharsets.ISO_8859_1),
            CarKeyProtocol.v2Transcript("gate-main", CarKeyProtocol.PRESS_COMMAND, challenge)
                .toString(StandardCharsets.ISO_8859_1),
        )
        assertEquals(
            "44b5102e86f885879c3bdc6c2e526415628b53241556bfacb6ba56b6e5b5f4dd",
            result.drop(1).joinToString("") { "%02x".format(it) },
        )
    }

    @Test fun carAlsoUsesV2WithItsOwnBinding() {
        val challenge = ByteArray(16) { it.toByte() }
        val car = CarKeyProtocol.command(BleDeviceProfiles.CAR, CarKeyProtocol.PRESS_COMMAND, challenge, "secret")
        val gate = CarKeyProtocol.command(BleDeviceProfiles.GATE, CarKeyProtocol.PRESS_COMMAND, challenge, "secret")

        assertEquals(33, car.size)
        assertArrayEquals(
            "BLEKEY-V2\u0000car-main\u0000\u0002".toByteArray(StandardCharsets.ISO_8859_1) + challenge,
            CarKeyProtocol.v2Transcript("car-main", CarKeyProtocol.PRESS_COMMAND, challenge),
        )
        org.junit.Assert.assertFalse(car.contentEquals(gate))
    }

    @Test fun otaStartBindsSizeDigestAndCurrentNonce() {
        val nonce = ByteArray(16) { (it + 1).toByte() }
        val digest = ByteArray(32) { (31 - it).toByte() }
        val result = CarKeyProtocol.otaStart(0x123456, digest, nonce, "secret")

        assertEquals(69, result.size)
        assertArrayEquals(byteArrayOf(0x56, 0x34, 0x12, 0x00), result.copyOfRange(1, 5))
        assertArrayEquals(digest, result.copyOfRange(5, 37))
        assertEquals(
            "7d94bbe7aa963e381ffb1bb8c0d38b04976a1cae0d6678942635ec3483df6dd9",
            result.drop(37).joinToString("") { "%02x".format(it) },
        )
    }
}
