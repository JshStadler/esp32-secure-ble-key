package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test

class PressReceiptProtocolTest {
    private val id = ByteArray(16) { it.toByte() }
    private val nonce = ByteArray(16) { (it + 16).toByte() }
    private val key = "synthetic-review-key"
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val receipt = hex("b103027defe39309a7421827d0073f8758f582")

    @Test fun commandMatchesIndependentHmacVectorAndFitsGarminMtu() {
        val fragments = PressReceiptProtocol.fragments(2, id, nonce, key)
        assertEquals(listOf(17, 18, 17), fragments.map { it.size })
        assertArrayEquals(hex("b283a67b754b8920d59a78a552dae0ae23751c2a3ee0d77d6f1e286fecc64eb2"),
            fragments[1].copyOfRange(2, 18) + fragments[2].copyOfRange(1, 17))
        assertArrayEquals(id, fragments[0].copyOfRange(1, 17))
    }
    @Test fun acceptsAuthenticatedQueryReceiptOnlyForExactRequest() {
        assertEquals(2, PressReceiptProtocol.verify(receipt, 3, id, nonce, key))
        assertNull(PressReceiptProtocol.verify(receipt, 2, id, nonce, key))
        assertNull(PressReceiptProtocol.verify(receipt, 3, id.reversedArray(), nonce, key))
        assertNull(PressReceiptProtocol.verify(receipt, 3, id, nonce.reversedArray(), key))
        assertNull(PressReceiptProtocol.verify(receipt, 3, id, nonce, "wrong-key"))
    }
    @Test fun rejectsEveryTamperedByteAndTruncatedOrExtendedReplies() {
        receipt.indices.forEach { index ->
            val changed = receipt.copyOf(); changed[index] = (changed[index].toInt() xor 1).toByte()
            assertNull(PressReceiptProtocol.verify(changed, 3, id, nonce, key))
        }
        assertNull(PressReceiptProtocol.verify(receipt.copyOf(18), 3, id, nonce, key))
        assertNull(PressReceiptProtocol.verify(receipt + byteArrayOf(0), 3, id, nonce, key))
    }
    @Test fun requestAndReceiptDomainsCannotBeInterchanged() {
        assertFalse(PressReceiptProtocol.transcript(false, 2, id, nonce)
            .contentEquals(PressReceiptProtocol.transcript(true, 2, id, nonce, 2)))
    }
}
