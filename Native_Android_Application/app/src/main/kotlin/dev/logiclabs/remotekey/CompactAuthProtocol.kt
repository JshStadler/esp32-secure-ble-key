package dev.logiclabs.remotekey

/** AUTH2 changes transport only: retain RCP1's independent client ID, full
 * request HMAC and constant-time verified 128-bit peripheral proof. */
internal object CompactAuthProtocol {
    fun packets(id: ByteArray, nonce: ByteArray, key: String, mtu: Int): List<ByteArray> {
        val parts = PressReceiptProtocol.fragments(PressReceiptProtocol.PROVE, id, nonce, key)
        return if (mtu >= 52) listOf(byteArrayOf(0xf3.toByte()) + id +
            parts[1].copyOfRange(2, 18) + parts[2].copyOfRange(1, 17))
        else listOf(parts[0], parts[1].copyOf().also { it[0] = 0xf4.toByte() }, parts[2])
    }
}

/** A result may precede the final write callback. Never become ready until both
 * the write and the proof have succeeded. A failed proof is never retried as a
 * weaker authentication method on the same connection. */
internal class CompactAuthSession(val id: ByteArray, val nonce: ByteArray, private val key: String) {
    private var written = false
    private var verified = false
    fun receive(value: ByteArray): Boolean {
        verified = PressReceiptProtocol.verify(value, PressReceiptProtocol.PROVE, id, nonce, key) == PressReceiptProtocol.PROVED
        return verified
    }
    fun writeCompleted() { written = true }
    val complete get() = written && verified
}
