package dev.logiclabs.remotekey

import java.security.MessageDigest
import java.security.SecureRandom

/** RCP1 fits the default ATT MTU, including its authenticated receipt. */
object PressReceiptProtocol {
    const val PROVE: Byte = 1
    const val PRESS: Byte = 2
    const val QUERY: Byte = 3
    const val ACK: Byte = 4
    const val UNKNOWN = 0
    const val PENDING = 1
    const val PRESSED = 2
    const val BUSY = 3
    const val ACKED = 4
    const val FULL = 5
    const val PROVED = 6
    const val RECOVERY_MS = 25_000L
    fun newId(): ByteArray = ByteArray(16).also(SecureRandom()::nextBytes)
    fun transcript(reply: Boolean, op: Byte, id: ByteArray, nonce: ByteArray, result: Int = 0): ByteArray {
        require(id.size == 16 && nonce.size == 16 && op in PROVE..ACK)
        val domain = if (reply) "BLEKEY-RCP1-ACK" else "BLEKEY-RCP1"
        return "$domain\u0000car-main\u0000".toByteArray(Charsets.UTF_8) +
            byteArrayOf(op) + id + nonce + if (reply) byteArrayOf(result.toByte()) else byteArrayOf()
    }
    fun fragments(op: Byte, id: ByteArray, nonce: ByteArray, key: String): List<ByteArray> {
        val mac = CarKeyProtocol.hmac(transcript(false, op, id, nonce), key)
        return listOf(byteArrayOf(0xf0.toByte()) + id,
            byteArrayOf(0xf1.toByte(), op) + mac.copyOfRange(0, 16),
            byteArrayOf(0xf2.toByte()) + mac.copyOfRange(16, 32))
    }
    fun verify(value: ByteArray, op: Byte, id: ByteArray, nonce: ByteArray, key: String): Int? {
        if (value.size != 19 || value[0] != 0xb1.toByte() || value[1] != op) return null
        val result = value[2].toInt() and 255
        if (result !in UNKNOWN..PROVED) return null
        val mac = CarKeyProtocol.hmac(transcript(true, op, id, nonce, result), key).copyOf(16)
        return if (MessageDigest.isEqual(mac, value.copyOfRange(3, 19))) result else null
    }
}
