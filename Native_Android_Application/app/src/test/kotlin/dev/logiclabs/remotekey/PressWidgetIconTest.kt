package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class PressWidgetIconTest {
    @Test fun savedIconOverridesTheDeviceType() {
        PressWidgetIcon.entries.forEach { icon ->
            assertEquals(icon, PressWidgetIcon.saved(icon.name, BleDeviceType.CAR))
            assertEquals(icon, PressWidgetIcon.saved(icon.name, BleDeviceType.ESPHOME_ACCESS))
        }
    }
    @Test fun missingOrUnknownIconsHaveSafeDefaults() {
        assertEquals(PressWidgetIcon.CAR, PressWidgetIcon.saved(null, BleDeviceType.CAR))
        assertEquals(PressWidgetIcon.GATE, PressWidgetIcon.saved("old-icon", BleDeviceType.ESPHOME_ACCESS))
    }
}
