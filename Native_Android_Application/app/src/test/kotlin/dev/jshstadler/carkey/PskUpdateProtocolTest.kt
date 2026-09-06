package dev.jshstadler.carkey

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.*
import org.junit.Test

class PskUpdateProtocolTest {
    @Test fun matchesIndependentPythonAndFirmwareVector() {
        val r = request()
        assertEquals("a2101112131415161718191a1b57a484ca886ec772bfd91e3cc1bbd99006b661e3d9af4484dbcd511cba14a8",
            r.payload.joinToString("") { "%02x".format(it) })
        assertEquals(true, PskUpdateProtocol.verifyReceipt(r,
            "PSK2:OK:c4db2030f6f70abe4ca45388d740c7c8e8e1bfb2266c08d460ce3ad642c2c54d"))
    }
    private val nonce = ByteArray(16) { it.toByte() }
    private val iv = ByteArray(12) { (it + 16).toByte() }
    private fun request(replacement: String = "replacement-key") = PskUpdateProtocol.create("car-main", nonce, "synthetic-current-key", replacement, iv)
    private fun decrypt(payload: ByteArray, binding: String = "car-main", challenge: ByteArray = nonce): ByteArray {
        val key = PskUpdateProtocol.mac("synthetic-current-key".toByteArray(), PskUpdateProtocol.context("BLEKEY-PSK2-ENC", binding, challenge))
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, payload.copyOfRange(1, 13)))
            updateAAD(PskUpdateProtocol.context("BLEKEY-PSK2", binding, challenge))
            doFinal(payload.copyOfRange(13, payload.size))
        }
    }
    @Test fun replacementIsEncryptedAndEveryCiphertextByteIsAuthenticated() {
        val r = request()
        assertArrayEquals("replacement-key".toByteArray(), decrypt(r.payload))
        assertFalse(r.payload.toString(Charsets.ISO_8859_1).contains("replacement-key"))
        for (i in 1 until r.payload.size) {
            val changed = r.payload.copyOf(); changed[i] = (changed[i].toInt() xor 1).toByte()
            assertTrue("byte $i", runCatching { decrypt(changed) }.isFailure)
        }
        assertTrue(runCatching { decrypt(r.payload, "gate-main") }.isFailure)
        assertTrue(runCatching { decrypt(r.payload, challenge = ByteArray(16)) }.isFailure)
    }
    @Test fun receiptBindsPersistenceResultAndExactRequest() {
        val r = request()
        fun receipt(ok: Boolean): String {
            val transcript = byteArrayOf(if (ok) 1 else 0) + MessageDigest.getInstance("SHA-256").digest(r.payload)
            val tag = PskUpdateProtocol.mac(r.receiptKey, transcript).joinToString("") { "%02x".format(it) }
            return "PSK2:${if (ok) "OK" else "FAIL"}:$tag"
        }
        assertEquals(true, PskUpdateProtocol.verifyReceipt(r, receipt(true)))
        assertEquals(false, PskUpdateProtocol.verifyReceipt(r, receipt(false)))
        assertNull(PskUpdateProtocol.verifyReceipt(r, receipt(false).replace("FAIL", "OK")))
        assertNull(PskUpdateProtocol.verifyReceipt(request("different"), receipt(true)))
        assertNull(PskUpdateProtocol.verifyReceipt(r, "OK:PSK_UPDATED"))
    }
    @Test fun keyLimitsUseUtf8BytesAndRejectEmbeddedNul() {
        for (n in listOf(127, 128)) assertArrayEquals("x".repeat(n).toByteArray(), decrypt(request("x".repeat(n)).payload))
        assertTrue(PskUpdateProtocol.validKey("é".repeat(64)))
        assertFalse(PskUpdateProtocol.validKey("é".repeat(65)))
        assertFalse(PskUpdateProtocol.validKey("a\u0000b"))
        assertFalse(PskUpdateProtocol.validKey(""))
        assertFalse(PskUpdateProtocol.validKey("x".repeat(129)))
    }
    @Test fun unavailableAuthenticationNeverGrantsAccess() {
        assertEquals(AppPolicies.AuthenticationRoute.UNAVAILABLE, AppPolicies.authenticationRoute(29, false, false))
        assertEquals(AppPolicies.AuthenticationRoute.CREDENTIAL, AppPolicies.authenticationRoute(29, false, true))
        assertEquals(AppPolicies.AuthenticationRoute.CREDENTIAL, AppPolicies.authenticationRoute(36, false, true))
        assertEquals(AppPolicies.AuthenticationRoute.BIOMETRIC, AppPolicies.authenticationRoute(28, true, true))
        assertEquals(AppPolicies.AuthenticationRoute.COMBINED, AppPolicies.authenticationRoute(36, true, true))
    }
}
