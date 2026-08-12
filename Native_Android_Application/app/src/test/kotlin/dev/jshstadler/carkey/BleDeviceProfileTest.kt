package dev.jshstadler.carkey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BleDeviceProfileTest {
    @Test
    fun configuredDevicesHaveUniqueIdsAndServices() {
        val devices = BleDeviceProfiles.configured

        assertEquals(devices.size, devices.map { it.id }.toSet().size)
        assertEquals(devices.size, devices.map { it.serviceUuid }.toSet().size)
        assertNotEquals(BleDeviceProfiles.CAR.serviceUuid, BleDeviceProfiles.GATE.serviceUuid)
    }

    @Test
    fun apiV2ProfilesKeepDistinctBindingsAndServices() {
        val gate = BleDeviceProfiles.GATE

        assertEquals(BleResponseMode.NOTIFICATIONS, BleDeviceProfiles.CAR.responseMode)
        assertEquals(BleResponseMode.READ_AFTER_WRITE, gate.responseMode)
        assertEquals("car-main", BleDeviceProfiles.CAR.securityBinding)
        assertEquals("gate-main", gate.securityBinding)
        assertTrue(gate.serviceUuid.toString().startsWith("b1b2c3d4-"))
        assertTrue(gate.challengeUuid.toString().endsWith("7891"))
        assertTrue(gate.commandUuid.toString().endsWith("7892"))
        assertTrue(gate.statusUuid.toString().endsWith("7893"))
    }
}
