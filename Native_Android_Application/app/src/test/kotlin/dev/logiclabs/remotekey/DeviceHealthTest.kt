package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class DeviceHealthTest {
    @Test fun showsBothRssiDirectionsAndAcceptsOlderFirmwareWithoutRssi() {
        val health = DeviceHealth.parse("$snapshot,rssi=-71")!!.copy(phoneRssi = -62)
        assertEquals(-71, health.espRssi)
        assertTrue(health.display().contains("At phone (ESP → phone): -62 dBm"))
        assertTrue(health.display().contains("At ESP (phone → ESP): -71 dBm"))
        assertNull(DeviceHealth.parse(snapshot)!!.espRssi)
        assertFalse(DeviceHealth.signalOnly().hasFirmwareHealth)
        assertTrue(DeviceHealth.signalOnly().copy(phoneRssi = -58).display().contains("-58 dBm"))
    }

    @Test fun rejectsRssiSentinelsAndMalformedValues() {
        listOf("127", "-128", "21", "-999", "-70dBm", "", "--5").forEach {
            assertNull(it, DeviceHealth.parse("$snapshot,rssi=$it"))
        }
        assertNull(DeviceHealth.parse("$snapshot,rssi=-70,rssi=-50"))
    }
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
        assertTrue(DeviceHealth.parse(data)!!.display().contains("Inactive: 200-400 ms"))
        assertEquals("inactive", DeviceHealth.parse(data)!!.advertisingMode)
        assertNull(DeviceHealth.parse(data.replace("slowmax=640", "slowmax=9999")))
        assertNull(DeviceHealth.parse(data.substringBefore(",idlesec=")))
    }
    @Test fun powerReadbackDistinguishesTargetActualAndUnavailable() {
        val data = snapshot.replace("health1,", "health1,radio1,radio2,") +
            ",fastmin=80,fastmax=160,slowmin=320,slowmax=640,idlesec=60,advmode=inactive,txdbm=9"
        val missing = DeviceHealth.parse(data)!!
        assertEquals(9, missing.radio!!.txPowerDbm)
        assertNull(missing.advertisingTxDbm)
        assertTrue(missing.display().contains("Saved target: 9 dBm"))
        assertTrue(missing.display().contains("Advertising: Unavailable"))
        val actual = DeviceHealth.parse("$data,txadv=9,txconn=3")!!
        assertEquals(9, actual.advertisingTxDbm)
        assertEquals(3, actual.connectionTxDbm)
        assertTrue(actual.display().contains("This connection: 3 dBm"))
        assertTrue(actual.espSignalSupported)
        listOf("10", "-15", "", "abc", "127").forEach {
            assertNull(DeviceHealth.parse(data.replace("txdbm=9", "txdbm=$it")))
        }
        assertNull(DeviceHealth.parse("$data,txadv=127"))
        assertNull(DeviceHealth.parse(data.substringBefore(",txdbm=")))
    }

    @Test fun dualPowerHealthShowsBothTargetsAndCurrentMode() {
        val data = snapshot.replace("health1,", "health1,radio1,radio2,radio3,") +
            ",fastmin=80,fastmax=160,slowmin=320,slowmax=640,idlesec=60,advmode=inactive,txdbm=9,txidle=-3,txmode=inactive,txadv=-3,txconn=-3"
        val h = DeviceHealth.parse(data)!!
        assertEquals(9, h.radio!!.txPowerDbm)
        assertEquals(-3, h.radio.idleTxPowerDbm)
        assertEquals("inactive", h.powerMode)
        assertTrue(h.display().contains("Recent activity: 9 dBm\nInactive: -3 dBm\nPower mode: inactive"))
        assertEquals("update", DeviceHealth.parse(data.replace("txmode=inactive", "txmode=update"))!!.powerMode)
        listOf(data.replace("txidle=-3", "txidle=10"), data.replace("txdbm=9", "txdbm=-6"),
            data.replace("txmode=inactive", "txmode=bad"), data.replace(",txidle=-3", ""),
            data.replace(",txmode=inactive", "")).forEach { assertNull(it, DeviceHealth.parse(it)) }
    }

}
