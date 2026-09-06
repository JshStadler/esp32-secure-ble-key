package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test

class DeviceHealthTest {
    private val identity = "blekey|2|car-main|car|press,ota1,psk2,health1"
    private val snapshot = "$identity,fw=2.7.0,build=012345abcdef,idf=v6.0.1,up=90061,reset=brownout,ota=valid,heap=123456,minheap=100000,links=2,advrec=4,ghost=1"

    @Test fun parsesFirmwareSnapshotAndPreservesCapabilities() {
        val health = DeviceHealth.parse(snapshot)!!
        assertEquals("2.7.0", health.firmware)
        assertEquals(90061L, health.uptimeSeconds)
        assertEquals(4L, health.advertisingRecoveries)
        assertTrue(health.display().contains("1d 1h 1m 1s"))
        assertTrue(health.display().contains("Validated"))
        assertTrue(DeviceHealth.capabilities(snapshot).contains("psk2"))
        assertNotNull(DeviceHealth.parse("$snapshot,future=ok"))
    }

    @Test fun rejectsUnauthenticatedOldOrTruncatedResponses() {
        assertNull(DeviceHealth.parse(identity))
        assertNull(DeviceHealth.parse("blekey|2|car-main|car|press,ota1,psk2"))
        assertNull(DeviceHealth.parse(snapshot.substringBefore(",ghost=")))
        assertNull(DeviceHealth.parse(snapshot.replace("|car|", "|gate|")))
    }

    @Test fun rejectsInvalidAndAmbiguousFields() {
        listOf(snapshot.replace("up=90061", "up=-1"),
            snapshot.replace("up=90061", "up=18446744073709551615"),
            snapshot.replace("heap=123456", "heap=99999999999999999"),
            snapshot.replace("links=2", "links=4"),
            snapshot.replace("build=012345abcdef", "build=wrong"),
            snapshot.replace("minheap=100000", "minheap=200000"),
            "$snapshot,fw=wrong", snapshot.replace("fw=2.7.0", "fw=2.7.0\nwrong")
        ).forEach { assertNull(it, DeviceHealth.parse(it)) }
    }

    @Test fun pendingOtaDoesNotClaimValidation() {
        val report = DeviceHealth.parse(snapshot.replace("ota=valid", "ota=pending"))!!.display()
        assertTrue(report.contains("refresh after one minute"))
        assertFalse(report.contains("Validated"))
    }

    @Test fun parsesAndValidatesAdvertisedRadioConfiguration() {
        val data = snapshot.replace("health1,", "health1,radio1,") +
            ",fastmin=80,fastmax=160,slowmin=320,slowmax=640,idlesec=60,advmode=inactive"
        assertEquals(RadioSettings.DEFAULT, DeviceHealth.parse(data)!!.radio)
        assertEquals("inactive", DeviceHealth.parse(data)!!.advertisingMode)
        assertNull(DeviceHealth.parse(data.replace("slowmax=640", "slowmax=9999")))
        assertNull(DeviceHealth.parse(data.substringBefore(",idlesec=")))
    }
}
