package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class PskKeyPolicyTest {
    private val strong = "5e90b1c274a83d6f0a519fbe842c73d6"

    @Test fun existingKeysRemainImportableButCannotBeNewReplacements() {
        for (key in listOf("a", "replacement-key", "x".repeat(128))) {
            assertTrue(PskUpdateProtocol.validKey(key))
            assertFalse(PskUpdateProtocol.validNewKey(key))
        }
    }

    @Test fun rejectsShortLowDiversityAndRepeatedPatterns() {
        for (key in listOf("", strong.dropLast(1), "x".repeat(32),
            "a".repeat(31) + "b", "password".repeat(4),
            "0123456789abcdef".repeat(8).take(127), "abcdef01".repeat(16))) {
            assertFalse(key, PskUpdateProtocol.validNewKey(key))
        }
    }

    @Test fun boundariesUseUtf8BytesAndAlwaysRejectNul() {
        assertTrue(PskUpdateProtocol.validNewKey(strong))
        assertTrue(PskUpdateProtocol.validNewKey(strong.repeat(4)))
        assertFalse(PskUpdateProtocol.validNewKey(strong.repeat(4) + "a"))
        assertTrue(PskUpdateProtocol.validNewKey(strong + "é".repeat(48)))
        assertFalse(PskUpdateProtocol.validNewKey(strong + "é".repeat(49)))
        assertTrue(PskUpdateProtocol.validNewKey("éÉßøåΩЖ漢🙂0123456789abcdef"))
        assertFalse(PskUpdateProtocol.validNewKey(strong + "\u0000"))
        assertFalse(PskUpdateProtocol.validKey(strong + "\u0000"))
    }

    @Test fun generatedKeysAlwaysMeetNewKeyPolicy() {
        repeat(100) { assertTrue(PskUpdateProtocol.validNewKey(DevicePskGenerator.generate())) }
    }
}
