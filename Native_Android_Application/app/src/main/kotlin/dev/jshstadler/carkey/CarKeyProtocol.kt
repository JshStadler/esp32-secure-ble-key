package dev.jshstadler.carkey

import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CarKeyProtocol {
    const val AUTH_COMMAND: Byte = 0x01
    const val PRESS_COMMAND: Byte = 0x02

    fun hmac(challenge: ByteArray, key: String): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key.toByteArray(StandardCharsets.UTF_8), "HmacSHA256"))
        doFinal(challenge)
    }

    fun command(command: Byte, challenge: ByteArray, key: String): ByteArray =
        byteArrayOf(command) + hmac(challenge, key)

    fun pskUpdate(challenge: ByteArray, currentKey: String, newKey: String): ByteArray =
        hmac(challenge, currentKey) + byteArrayOf(0) + newKey.toByteArray(StandardCharsets.UTF_8)
}
