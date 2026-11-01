package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class DevicePressRequestsTest {
    @Test fun differentDevicesOwnSeparateAuthorizationsAndResults() {
        val presses = DevicePressRequests()
        val gate = presses.begin("gate", 100)!!
        val car = presses.begin("car", 200)!!
        assertNull(presses.begin("gate", 300))
        assertNotEquals(gate.session, car.session)
        assertTrue(car.claim(400))
        assertFalse(car.claim(401))
        assertSame(car, presses.finish("car"))
        assertSame(gate, presses["gate"])
        assertTrue(presses.busy)
        assertTrue(gate.claim(500))
    }
    @Test fun cancellationAndDeadlinesOnlyAffectTheirOwnDeviceAndOldTapCannotReplay() {
        val presses = DevicePressRequests()
        val gate = presses.begin("gate", 0)!!
        val car = presses.begin("car", 5_000)!!
        assertFalse(gate.claim(10_000))
        presses.finish("gate")
        val replacement = presses.begin("gate", 10_001)!!
        assertNotSame(gate, replacement)
        assertFalse(gate.claim(10_002))
        assertTrue(car.claim(10_003))
        presses.clear()
        assertFalse(replacement.claim(10_004))
        assertFalse(presses.busy)
    }
}
