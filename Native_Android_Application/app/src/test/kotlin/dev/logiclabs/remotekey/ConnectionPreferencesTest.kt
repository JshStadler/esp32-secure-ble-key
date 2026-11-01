package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class ConnectionPreferencesTest {
    @Test fun oldAndInvalidPreferencesRetainExistingTwoMinuteBehavior() {
        listOf(null, "", "bad", "-1", "99999999").forEach {
            assertEquals(BackgroundConnectionDuration.TWO_MINUTES, BackgroundConnectionDuration.fromSaved(it))
        }
        BackgroundConnectionDuration.entries.forEach {
            assertEquals(it, BackgroundConnectionDuration.fromSaved(it.name))
        }
    }

    @Test fun existingDevicesAutoConnectUntilExplicitlyDisabled() {
        assertTrue(ConnectionPreferences.shouldAutoConnect(null, true))
        assertTrue(ConnectionPreferences.shouldAutoConnect("true", true))
        assertFalse(ConnectionPreferences.shouldAutoConnect("false", true))
        assertFalse(ConnectionPreferences.shouldAutoConnect(null, false))
    }

    @Test fun reconnectCannotInterruptAnyMutatingOperationOrFirmwarePicker() {
        assertTrue(ConnectionPreferences.canRestart(false, false, false, false, false))
        for (busyIndex in 0..4) {
            val busy = List(5) { it == busyIndex }
            assertFalse(ConnectionPreferences.canRestart(busy[0], busy[1], busy[2], busy[3], busy[4]))
        }
    }
}
