package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class SupportSummaryTest {
    private fun format(snapshot: TimedDeviceHealth?) = SupportSummary.format("2.8.6", 32, 36, "On",
        BackgroundConnectionDuration.THIRTY_SECONDS,
        listOf(SupportDeviceInfo("Standalone", "CONNECTED", true, false, snapshot)), 125_000)

    @Test fun reportsMissingHealthWithoutInventingFirmwareOrSignalValues() {
        val report = format(null)
        assertTrue(report.contains("2.8.6 (build 32)"))
        assertTrue(report.contains("Background connections: 30 seconds"))
        assertTrue(report.contains("Auto-connect: Off"))
        assertTrue(report.contains("not collected this app session"))
        assertFalse(report.contains("dBm"))
    }

    @Test fun reportsSnapshotAgeAndBothSignalDirectionsWithoutUnknownHealthFields() {
        val health = DeviceHealth.parse("blekey|2|car-main|car|health1,fw=2.8.4,build=012345abcdef,idf=v6.0.1," +
            "up=10,reset=power_on,ota=valid,heap=120000,minheap=100000,links=1,advrec=0,ghost=0,rssi=-71," +
            "psk=never-copy-this-key,address=AA:BB:CC:DD:EE:FF,location=private-location")!!.copy(phoneRssi = -60)
        val report = format(TimedDeviceHealth(health, 5_000))
        assertTrue(report.contains("120 seconds ago; may be stale"))
        assertTrue(report.contains("ESP firmware: 2.8.4"))
        assertTrue(report.contains("BLE at phone (ESP → phone): -60 dBm"))
        assertTrue(report.contains("BLE at ESP (phone → ESP): -71 dBm"))
        listOf("never-copy-this-key", "AA:BB:CC:DD:EE:FF", "private-location").forEach { assertFalse(report.contains(it)) }
    }

    @Test fun supportsEspHomePhoneOnlySignalAndClampsSnapshotAge() {
        val report = format(TimedDeviceHealth(DeviceHealth.signalOnly().copy(phoneRssi = -55), 200_000))
        assertTrue(report.contains("0 seconds ago"))
        assertTrue(report.contains("ESP firmware: not reported"))
        assertTrue(report.contains("BLE at phone (ESP → phone): -55 dBm"))
        assertTrue(report.contains("BLE at ESP (phone → ESP): Unavailable"))
    }

    @Test fun emptySetupStillProducesACopyableSummary() {
        val report = SupportSummary.format("2.8.6-test", 32, 36, "Bluetooth is off",
            BackgroundConnectionDuration.OFF, emptyList(), 0)
        assertTrue(report.contains("2.8.6-test"))
        assertTrue(report.contains("Device count: 0"))
        assertTrue(report.contains("Bluetooth is off"))
        assertTrue(report.contains("Background connections: Off"))
    }
}
