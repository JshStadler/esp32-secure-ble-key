package dev.logiclabs.remotekey

import org.junit.Assert.assertEquals
import org.junit.Test

class ConnectionStatusTextTest {
    @Test fun initialScanConnectAuthenticationAndBackoffShareOneLabel() {
        val steps = listOf(
            BleCarKeyClient.State.CONNECTING to "Connecting to cached device…",
            BleCarKeyClient.State.RETRYING to "Bluetooth disconnected (status=133)",
            BleCarKeyClient.State.SCANNING to "Scanning…",
            BleCarKeyClient.State.CONNECTING to "Authenticating…",
        )
        steps.forEach { (state, message) ->
            assertEquals("Connecting…", ConnectionStatusText.label(state, message, false))
            assertEquals("Reconnecting…", ConnectionStatusText.label(state, message, true))
        }
    }

    @Test fun realStopsAndBluetoothFailuresRemainVisible() {
        assertEquals("Idle", ConnectionStatusText.label(BleCarKeyClient.State.DISCONNECTED, "Disconnected", true))
        assertEquals("Bluetooth is off", ConnectionStatusText.label(BleCarKeyClient.State.DISCONNECTED, "Bluetooth is off", true))
        assertEquals("Connected", ConnectionStatusText.label(BleCarKeyClient.State.CONNECTED, "Authenticated", true))
    }
}
