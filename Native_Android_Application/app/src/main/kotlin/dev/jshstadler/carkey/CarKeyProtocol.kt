package dev.jshstadler.carkey

import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CarKeyProtocol {
    private const val V2_DOMAIN = "BLEKEY-V2"
    private const val OTA_DOMAIN = "BLEKEY-OTA1"
    const val AUTH_COMMAND: Byte = 0x01
    const val PRESS_COMMAND: Byte = 0x02
    const val PSK_UPDATE_COMMAND: Byte = 0x03

    fun hmac(challenge: ByteArray, key: String): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        doFinal(challenge)
    }

    /**
     * Builds the API-v2 command. The domain-separated transcript binds every
     * response to its device, command, and one-time challenge:
     *
     * BLEKEY-V2 || 0x00 || deviceBinding || 0x00 || command || challenge
     */
    fun command(
        profile: BleDeviceProfile,
        command: Byte,
        challenge: ByteArray,
        key: String,
    ): ByteArray = byteArrayOf(command) +
        hmac(v2Transcript(profile.securityBinding, command, challenge), key)

    internal fun v2Transcript(deviceBinding: String, command: Byte, challenge: ByteArray): ByteArray =
        V2_DOMAIN.toByteArray(StandardCharsets.US_ASCII) +
            byteArrayOf(0) +
            deviceBinding.toByteArray(StandardCharsets.UTF_8) +
            byteArrayOf(0, command) +
            challenge

    fun pskUpdate(profile: BleDeviceProfile, challenge: ByteArray, currentKey: String, newKey: String): ByteArray =
        hmac(v2Transcript(profile.securityBinding, PSK_UPDATE_COMMAND, challenge), currentKey) +
            byteArrayOf(0) + newKey.toByteArray(StandardCharsets.UTF_8)

    /** START || image-size-LE || SHA-256 || HMAC(domain, size, digest, nonce). */
    fun otaStart(imageSize: Int, digest: ByteArray, challenge: ByteArray, key: String): ByteArray {
        require(digest.size == 32)
        require(challenge.size == 16)
        val sizeLe = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(imageSize).array()
        val transcript = OTA_DOMAIN.toByteArray(StandardCharsets.US_ASCII) +
            byteArrayOf(0) + sizeLe + digest + challenge
        return byteArrayOf(0x01) + sizeLe + digest + hmac(transcript, key)
    }
}
