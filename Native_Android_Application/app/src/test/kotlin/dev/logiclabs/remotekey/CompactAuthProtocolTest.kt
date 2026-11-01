package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class CompactAuthProtocolTest {
    private val id = ByteArray(16) { it.toByte() }
    private val nonce = ByteArray(16) { (it + 16).toByte() }
    private val key = "synthetic-review-key"
    // Independent Python hmac.digest vector, not produced by the code under test.
    private val proof = "b101065905db3e1055cdb46fa7b42263104e55".chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun fullRequestRetainsFullMacAndIndependentClientId() {
        val old = PressReceiptProtocol.fragments(1, id, nonce, key)
        val packet = CompactAuthProtocol.packets(id, nonce, key, 52).single()
        assertEquals(49, packet.size)
        assertEquals(0xf3, packet[0].toInt() and 255)
        assertArrayEquals(id, packet.copyOfRange(1, 17))
        assertArrayEquals(old[1].copyOfRange(2, 18) + old[2].copyOfRange(1, 17), packet.copyOfRange(17, 49))
    }

    @Test fun splitRequestFitsDefaultMtuAndCannotBecomePress() {
        val packets = CompactAuthProtocol.packets(id, nonce, key, 23)
        assertEquals(listOf(17, 18, 17), packets.map { it.size })
        assertEquals(0xf4, packets[1][0].toInt() and 255)
        assertEquals(PressReceiptProtocol.PROVE, packets[1][1])
        assertEquals(3, CompactAuthProtocol.packets(id, nonce, key, 51).size)
    }

    @Test fun earlyProofWaitsForSuccessfulFinalWrite() {
        val auth = CompactAuthSession(id, nonce, key)
        assertTrue(auth.receive(proof))
        assertFalse(auth.complete)
        auth.writeCompleted()
        assertTrue(auth.complete)
    }

    @Test fun writeCallbackAloneCannotAuthenticate() {
        val auth = CompactAuthSession(id, nonce, key)
        auth.writeCompleted()
        assertFalse(auth.complete)
        assertTrue(auth.receive(proof))
        assertTrue(auth.complete)
    }

    @Test fun rejectsTamperWrongSessionWrongKeyAndWrongOperation() {
        proof.indices.forEach { i ->
            val changed = proof.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertFalse(CompactAuthSession(id, nonce, key).receive(changed))
        }
        assertFalse(CompactAuthSession(id.reversedArray(), nonce, key).receive(proof))
        assertFalse(CompactAuthSession(id, nonce.reversedArray(), key).receive(proof))
        assertFalse(CompactAuthSession(id, nonce, "wrong").receive(proof))
        assertFalse(CompactAuthSession(id, nonce, key).receive(proof.copyOf(18)))
    }
}
