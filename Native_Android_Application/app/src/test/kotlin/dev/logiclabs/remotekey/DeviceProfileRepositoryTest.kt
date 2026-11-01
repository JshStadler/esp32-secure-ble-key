package dev.logiclabs.remotekey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceProfileRepositoryTest {
    private class Storage {
        val entries = mutableMapOf<String, String>()
        fun repository() = DeviceProfileRepository(entries::get) { key, value -> entries[key] = value }
    }

    @Test fun freshInstallWaitsForExplicitSetupInsteadOfCreatingCarAndGate() {
        val storage = Storage()
        val repository = storage.repository()

        assertTrue(repository.load().isEmpty())
        assertTrue(repository.needsInitialSetup())
        assertTrue(storage.entries.isEmpty())
        assertTrue(storage.repository().load().isEmpty())
        assertTrue(storage.repository().needsInitialSetup())
    }

    @Test fun selectedDeviceTypesAndNamesSurviveRestart() {
        val storage = Storage()
        val selected = listOf(
            BleDeviceProfiles.create(BleDeviceType.ESPHOME_ACCESS, displayName = "Front door"),
            BleDeviceProfiles.create(BleDeviceType.CAR, displayName = "Garage remote"),
        )
        storage.repository().save(selected)

        val restarted = storage.repository()
        assertEquals(selected, restarted.load())
        assertFalse(restarted.needsInitialSetup())
    }

    @Test fun setupCanChooseJustOneTypeWithoutAddingAnother() {
        val storage = Storage()
        val selected = listOf(BleDeviceProfiles.create(BleDeviceType.ESPHOME_ACCESS, displayName = "Gate"))
        storage.repository().save(selected)

        assertEquals(selected, storage.repository().load())
        assertFalse(storage.repository().needsInitialSetup())
    }

    @Test fun skippingSetupRemainsEmptyAfterRestart() {
        val storage = Storage()
        storage.repository().save(emptyList())

        assertTrue(storage.repository().load().isEmpty())
        assertFalse(storage.repository().needsInitialSetup())
    }

    @Test fun existingInstallKeepsDefaultCardIdsAndCredentials() {
        val storage = Storage()
        storage.repository().save(BleDeviceProfiles.defaults)
        storage.entries[BleDeviceProfiles.CAR.pskStoreKey] = "installed-car-key"
        storage.entries[BleDeviceProfiles.GATE.addressStoreKey] = "AA:BB:CC:DD:EE:FF"
        val before = storage.entries.toMap()

        assertEquals(BleDeviceProfiles.defaults, storage.repository().load())
        assertFalse(storage.repository().needsInitialSetup())
        assertEquals(before, storage.entries)
    }

    @Test fun preDashboardInstallMigratesWithoutDiscardingLegacyCredentials() {
        val storage = Storage()
        storage.entries["psk"] = "legacy-key"
        storage.entries["cached_address"] = "AA:BB:CC:DD:EE:FF"
        val repository = storage.repository()

        assertEquals(BleDeviceProfiles.defaults, repository.load())
        assertFalse(repository.needsInitialSetup())
        assertEquals("legacy-key", storage.entries["psk"])
        assertEquals("AA:BB:CC:DD:EE:FF", storage.entries["cached_address"])
    }

    @Test fun credentialsWithOriginalCardIdsAreAlsoMigrated() {
        val storage = Storage()
        storage.entries[BleDeviceProfiles.GATE.pskStoreKey] = "existing-gate-key"

        assertEquals(BleDeviceProfiles.defaults, storage.repository().load())
        assertFalse(storage.repository().needsInitialSetup())
        assertEquals("existing-gate-key", storage.entries[BleDeviceProfiles.GATE.pskStoreKey])
    }

    @Test fun removingAllCardsDoesNotRestartOnboarding() {
        val storage = Storage()
        storage.repository().save(BleDeviceProfiles.defaults)
        storage.entries[BleDeviceProfiles.CAR.pskStoreKey] = "retained-key"
        storage.repository().save(emptyList())

        assertTrue(storage.repository().load().isEmpty())
        assertFalse(storage.repository().needsInitialSetup())
    }
}
