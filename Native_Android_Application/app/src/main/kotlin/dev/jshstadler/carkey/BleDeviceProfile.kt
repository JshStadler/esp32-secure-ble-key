package dev.jshstadler.carkey

import java.util.UUID

enum class BleResponseMode { NOTIFICATIONS, READ_AFTER_WRITE }

/** BLE identity, protocol, and UI metadata for one configured key device. */
data class BleDeviceProfile(
    val id: String,
    val displayName: String,
    val actionLabel: String,
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
) {
    val pskStoreKey: String get() = "device_${id}_psk"
    val addressStoreKey: String get() = "device_${id}_address"
    val preferCachedStoreKey: String get() = "device_${id}_prefer_cached"
    val recordLocationStoreKey: String get() = "device_${id}_record_location"
}

object BleDeviceProfiles {
    val CAR = profile(
        id = "car",
        displayName = "Car",
        actionLabel = "Press Car Remote",
        advertisedName = "BLE-Device",
        defaultAddress = null,
        securityBinding = "car-main",
        responseMode = BleResponseMode.NOTIFICATIONS,
        uuidPrefix = "a1b2c3d4",
    )

    val GATE = profile(
        id = "gate",
        displayName = "Gate",
        actionLabel = "Press Gate Remote",
        advertisedName = "centurion-d5-evo",
        defaultAddress = null,
        securityBinding = "gate-main",
        responseMode = BleResponseMode.READ_AFTER_WRITE,
        uuidPrefix = "b1b2c3d4",
    )

    val configured = listOf(CAR, GATE)

    fun byId(id: String): BleDeviceProfile? = configured.firstOrNull { it.id == id }

    private fun profile(
        id: String,
        displayName: String,
        actionLabel: String,
        advertisedName: String,
        defaultAddress: String?,
        securityBinding: String,
        responseMode: BleResponseMode,
        uuidPrefix: String,
    ) = BleDeviceProfile(
        id = id,
        displayName = displayName,
        actionLabel = actionLabel,
        advertisedName = advertisedName,
        defaultAddress = defaultAddress,
        securityBinding = securityBinding,
        responseMode = responseMode,
        serviceUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567890"),
        challengeUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567891"),
        commandUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567892"),
        statusUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567893"),
        pskUpdateUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567894"),
        identityUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567897"),
        otaControlUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567898"),
        otaDataUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef1234567899"),
        otaStatusUuid = UUID.fromString("$uuidPrefix-e5f6-7890-abcd-ef123456789a"),
    )
}
