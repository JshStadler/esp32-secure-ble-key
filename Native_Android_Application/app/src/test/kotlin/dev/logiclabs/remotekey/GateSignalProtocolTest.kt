package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class GateSignalProtocolTest {
    private val request = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7)
    private fun reply(state: Int, rssi: Int) = byteArrayOf(state.toByte()) + request + byteArrayOf(rssi.toByte())

    @Test fun parsesSignedSignalAndDoesNotInventUnavailableOrPendingReadings() {
        assertEquals(-84, GateSignalProtocol.parse(reply(1, -84), request)!!.rssi)
        assertTrue(GateSignalProtocol.parse(reply(0, 127), request)!!.pending)
        assertEquals(GateSignalProtocol.Reply(false, null), GateSignalProtocol.parse(reply(2, 127), request))
        assertNull(GateSignalProtocol.parse(reply(1, 127), request))
        assertNull(GateSignalProtocol.parse(reply(1, -128), request))
        assertNull(GateSignalProtocol.parse(reply(1, 21), request))
    }

    @Test fun rejectsOldRequestMalformedAndUnknownReplies() {
        assertNull(GateSignalProtocol.parse(reply(1, -60), request.reversedArray()))
        assertNull(GateSignalProtocol.parse(reply(1, -60).dropLast(1).toByteArray(), request))
        assertNull(GateSignalProtocol.parse(reply(1, -60) + byteArrayOf(0), request))
        assertNull(GateSignalProtocol.parse(reply(3, -60), request))
        assertNull(GateSignalProtocol.parse(reply(1, -60), byteArrayOf()))
    }

    @Test fun signalOnlyHealthShowsBothDirectionsWithoutInventingFirmwareHealth() {
        val health = DeviceHealth.signalOnly(espSignalSupported = true).copy(espRssi = -60, phoneRssi = -79)
        assertTrue(health.display().contains("At ESP (phone → ESP): -60 dBm"))
        assertTrue(health.display().contains("At phone (ESP → phone): -79 dBm"))
        assertFalse(health.hasFirmwareHealth)
        assertFalse(health.display().contains("Firmware:"))
        assertTrue(health.copy(espRssi = null).display().contains("tap Refresh to retry"))
    }
}
