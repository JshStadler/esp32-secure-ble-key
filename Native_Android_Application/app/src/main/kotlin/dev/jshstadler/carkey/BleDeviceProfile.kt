package dev.jshstadler.carkey

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

enum class BleResponseMode { NOTIFICATIONS, READ_AFTER_WRITE }
enum class BleDeviceType { CAR, ESPHOME_ACCESS }

/** BLE identity, protocol, capabilities, and user-facing metadata for one card. */
data class BleDeviceProfile(
    val id: String,
    val type: BleDeviceType,
    val displayName: String,
    val advertisedName: String,
    val defaultAddress: String?,
    val securityBinding: String,
    val responseMode: BleResponseMode,
    val serviceUuid: UUID,
    val challengeUuid: UUID,
    val commandUuid: UUID,
    val statusUuid: UUID,
    val pskUpdateUuid: UUID,
    val identityUuid: UUID,
    val otaControlUuid: UUID,
    val otaDataUuid: UUID,
    val otaStatusUuid: UUID,
    val deviceStateUuid: UUID,
) {
    val supportsRemotePskUpdate get() = type == BleDeviceType.CAR
    val supportsBleOta get() = type == BleDeviceType.CAR
    val supportsLiveState get() = type == BleDeviceType.ESPHOME_ACCESS
    val actionLabel get() = "Press"
    val pskStoreKey get() = "device_${id}_psk"
    val addressStoreKey get() = "device_${id}_address"
    val preferCachedStoreKey get() = "device_${id}_prefer_cached"
    val recordLocationStoreKey get() = "device_${id}_record_location"
}

object BleDeviceProfiles {
    val CAR = create(BleDeviceType.CAR, "car", "Car")
    val GATE = create(BleDeviceType.ESPHOME_ACCESS, "gate", "Gate")
    val defaults get() = listOf(CAR, GATE)

    fun create(
        type: BleDeviceType,
        id: String = UUID.randomUUID().toString(),
        displayName: String = if (type == BleDeviceType.CAR) "Car" else "Access Device",
        targetAddress: String? = null,
    ): BleDeviceProfile {
        val car = type == BleDeviceType.CAR
        val prefix = if (car) "a1b2c3d4" else "b1b2c3d4"
        return BleDeviceProfile(
            id = id,
            type = type,
            displayName = displayName,
            advertisedName = if (car) "BLE-Device" else "centurion-d5-evo",
            defaultAddress = targetAddress?.trim()?.uppercase()?.ifEmpty { null },
            securityBinding = if (car) "car-main" else "gate-main",
            responseMode = if (car) BleResponseMode.NOTIFICATIONS else BleResponseMode.READ_AFTER_WRITE,
            serviceUuid = uuid(prefix, "90"),
            challengeUuid = uuid(prefix, "91"),
            commandUuid = uuid(prefix, "92"),
            statusUuid = uuid(prefix, "93"),
            pskUpdateUuid = uuid(prefix, "94"),
            identityUuid = uuid(prefix, "97"),
            otaControlUuid = uuid(prefix, "98"),
            otaDataUuid = uuid(prefix, "99"),
            otaStatusUuid = uuid(prefix, "9a"),
            deviceStateUuid = uuid(prefix, "9b"),
        )
    }

    private fun uuid(prefix: String, suffix: String) =
        UUID.fromString("$prefix-e5f6-7890-abcd-ef12345678$suffix")
}

/** Encrypted ordered card list. PSKs remain in their own encrypted entries. */
class DeviceProfileRepository(private val store: SecureStore) {
    companion object { private const val KEY = "device_profiles_v1" }

    fun load(): MutableList<BleDeviceProfile> {
        val saved = store.get(KEY)
        if (saved == null) return BleDeviceProfiles.defaults.toMutableList().also(::save)
        return runCatching {
            val array = JSONArray(saved)
            MutableList(array.length()) { index ->
                val item = array.getJSONObject(index)
                BleDeviceProfiles.create(
                    type = BleDeviceType.valueOf(item.getString("type")),
                    id = item.getString("id"),
                    displayName = item.getString("name"),
                    targetAddress = item.optString("address").ifEmpty { null },
                )
            }
        }.getOrElse { BleDeviceProfiles.defaults.toMutableList().also(::save) }
    }

    fun save(profiles: List<BleDeviceProfile>) {
        val array = JSONArray()
        profiles.forEach { profile ->
            array.put(JSONObject().apply {
                put("id", profile.id)
                put("type", profile.type.name)
                put("name", profile.displayName)
                put("address", profile.defaultAddress ?: "")
            })
        }
        store.put(KEY, array.toString())
    }
}
