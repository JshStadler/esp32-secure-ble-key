package dev.jshstadler.carkey

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** PSK2: AES-256-GCM with independent, challenge-derived request/receipt keys. */
object PskUpdateProtocol {
    private val random = SecureRandom()
    const val MAX_KEY_BYTES = 128
    data class Request(val payload: ByteArray, internal val receiptKey: ByteArray)

    fun validKey(value: String): Boolean = value.isNotEmpty() &&
        '\u0000' !in value && value.toByteArray(Charsets.UTF_8).size <= MAX_KEY_BYTES

    internal fun mac(key: ByteArray, value: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(value)
    }

    internal fun context(domain: String, binding: String, nonce: ByteArray): ByteArray =
        "$domain\u0000$binding\u0000".toByteArray(Charsets.UTF_8) + nonce

    fun create(binding: String, nonce: ByteArray, currentKey: String, replacement: String): Request =
        create(binding, nonce, currentKey, replacement, ByteArray(12).also(random::nextBytes))

    internal fun create(binding: String, nonce: ByteArray, currentKey: String, replacement: String, iv: ByteArray): Request {
        require(nonce.size == 16 && iv.size == 12 && validKey(replacement))
        val key = currentKey.toByteArray(Charsets.UTF_8)
        val encryptionKey = mac(key, context("BLEKEY-PSK2-ENC", binding, nonce))
        val receiptKey = mac(key, context("BLEKEY-PSK2-ACK", binding, nonce))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptionKey, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(context("BLEKEY-PSK2", binding, nonce))
        val encrypted = cipher.doFinal(replacement.toByteArray(Charsets.UTF_8))
        encryptionKey.fill(0)
        return Request(byteArrayOf(0xA2.toByte()) + iv + encrypted, receiptKey)
    }

    /** null means untrusted/malformed receipt; false means authenticated persistence failure. */
    fun verifyReceipt(request: Request, value: String): Boolean? {
        val fields = value.split(':')
        if (fields.size != 3 || fields[0] != "PSK2" || fields[1] !in listOf("OK", "FAIL")) return null
        val supplied = runCatching {
            require(fields[2].length == 64)
            fields[2].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }.getOrNull() ?: return null
        val success = fields[1] == "OK"
        val digest = MessageDigest.getInstance("SHA-256").digest(request.payload)
        val expected = mac(request.receiptKey, byteArrayOf(if (success) 1 else 0) + digest)
        return if (MessageDigest.isEqual(expected, supplied)) success else null
    }
}
