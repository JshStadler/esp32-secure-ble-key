package dev.logiclabs.remotekey

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.security.MessageDigest

class FirmwareUpdatesTest {
    private fun image(chip: Int = 5) = ByteArray(80).apply { this[0] = 0xe9.toByte(); this[12] = chip.toByte() }
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun release(v: String, car: Boolean = true, bytes: ByteArray = image()): JSONObject {
        val tag = "firmware-v$v"
        val name = if (car) "BLE-Car-Key-v$v-signed-ota.bin" else "Centurion-D5-Evo-v$v.yaml"
        return JSONObject().put("tag_name", tag).put("draft", false).put("prerelease", true)
            .put("body", "Build: gate-ble-v$v-update-metadata")
            .put("assets", JSONArray().put(JSONObject().put("name", name).put("size", bytes.size)
                .put("digest", "sha256:${hash(bytes)}").put("browser_download_url", "${FirmwareUpdates.REPO}/releases/download/$tag/$name")))
    }
    @Test fun versionsAreComparedNumericallyAndOnlyTheCorrectFirmwareAssetsAreSelected() {
        val json = JSONArray().put(release("2.8.9")).put(release("2.8.12", false)).put(release("2.8.11"))
            .put(release("9.0.0").put("draft", true)).put(release("99.0.0").put("tag_name", "v99.0.0")).toString()
        assertEquals("2.8.11", FirmwareUpdates.parse(json, BleDeviceType.CAR)?.version.toString())
        assertEquals("2.8.12", FirmwareUpdates.parse(json, BleDeviceType.ESPHOME_ACCESS)?.version.toString())
    }
    @Test fun gateOnlyReleasesDoNotAdvertiseANewStandaloneEspImage() {
        val gate = release("2.8.12", false).put("tag_name", "gate-v2.8.12")
        gate.getJSONArray("assets").getJSONObject(0).put("browser_download_url",
            "${FirmwareUpdates.REPO}/releases/download/gate-v2.8.12/Centurion-D5-Evo-v2.8.12.yaml")
        val json = JSONArray().put(gate).put(release("2.8.11")).toString()
        assertEquals("2.8.11", FirmwareUpdates.parse(json, BleDeviceType.CAR)?.version.toString())
        assertEquals("2.8.12", FirmwareUpdates.parse(json, BleDeviceType.ESPHOME_ACCESS)?.version.toString())
    }
    @Test fun missingDigestsUnexpectedUrlsAndOversizedImagesCannotBeOffered() {
        listOf<(JSONObject) -> Unit>(
            { it.getJSONArray("assets").getJSONObject(0).remove("digest") },
            { it.getJSONArray("assets").getJSONObject(0).put("browser_download_url", "https://example.com/firmware.bin") },
            { it.getJSONArray("assets").getJSONObject(0).put("size", FirmwareImageReader.MAX_IMAGE_SIZE + 1) }
        ).forEach { change ->
            val candidate = release("2.8.11"); change(candidate)
            assertNull(FirmwareUpdates.parse(JSONArray().put(candidate).toString(), BleDeviceType.CAR))
        }
    }
    @Test fun aValidImageIsVerifiedBeforeItCanReachTheBleUpdater() {
        val bytes = image()
        val selected = FirmwareUpdates.parse(JSONArray().put(release("2.8.11", bytes = bytes)).toString(), BleDeviceType.CAR)!!
        val repository = FirmwareUpdates { _, limit -> assertEquals(FirmwareImageReader.MAX_IMAGE_SIZE, limit); bytes }
        assertArrayEquals(bytes, repository.download(selected))
        assertThrows(IllegalArgumentException::class.java) { FirmwareUpdates { _, _ -> bytes.copyOf().apply { this[25] = 1 } }.download(selected) }
        assertThrows(IllegalArgumentException::class.java) { FirmwareUpdates { _, _ -> bytes.copyOf(40) }.download(selected) }
    }
    @Test fun evenAChecksummedImageForAnotherEspChipIsRejected() {
        val bytes = image(0)
        val selected = FirmwareUpdates.parse(JSONArray().put(release("2.8.11", bytes = bytes)).toString(), BleDeviceType.CAR)!!
        assertThrows(IllegalArgumentException::class.java) { FirmwareUpdates { _, _ -> bytes }.download(selected) }
    }
    @Test fun openingSettingsReusesAMetadataCacheButExplicitRetryFetchesAgain() {
        var requests = 0
        val repository = FirmwareUpdates { url, _ -> assertEquals(FirmwareUpdates.FEED, url); requests++; JSONArray().put(release("2.8.11")).toString().toByteArray() }
        repository.check(BleDeviceType.CAR); repository.check(BleDeviceType.ESPHOME_ACCESS)
        assertEquals(1, requests)
        repository.check(BleDeviceType.CAR, true)
        assertEquals(2, requests)
    }
    @Test fun olderOrUnknownInstalledVersionsAreNeverReportedAsUpToDate() {
        val selected = FirmwareUpdates.parse(JSONArray().put(release("2.8.11")).toString(), BleDeviceType.CAR)!!
        assertTrue(selected.comparison(DeviceHealth.signalOnly().copy(firmware = "2.8.9")).startsWith("Update available"))
        assertTrue(selected.comparison(null).startsWith("Latest:"))
        assertTrue(selected.comparison(DeviceHealth.signalOnly().copy(firmware = "2.8.12")).contains("newer than published"))
    }
    @Test fun gateRevisionsAreOptionalAndCannotImpersonateAnotherDeviceFamily() {
        val prefix = "blekey|2|gate-main|gate|press,state,signal1"
        assertNull(DeviceHealth.gateIdentity(prefix))
        val identity = "$prefix,fw=2.8.12,build=gate-ble-v2.8.12-update-metadata"
        val snapshot = DeviceHealth.gateIdentity(identity)!!
        assertEquals("2.8.12", snapshot.firmware)
        assertFalse(snapshot.hasFirmwareHealth)
        assertTrue(snapshot.display().contains("Build: gate-ble-v2.8.12-update-metadata"))
        assertNull(DeviceHealth.gateIdentity(identity.replace("gate-main", "car-main")))
        assertNull(DeviceHealth.gateIdentity("$identity,fw=2.8.13"))
    }
}
