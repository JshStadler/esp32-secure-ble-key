package dev.jshstadler.carkey

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppPoliciesTest {
    data class Item(val value: Int, val session: String?)

    @Test fun appliesExpectedRetentionWindows() {
        val now = 1_000_000_000L
        assertEquals(now - AppPolicies.DIAGNOSTIC_RETENTION_MS, AppPolicies.retentionCutoff(now, true))
        assertEquals(now - AppPolicies.OPERATION_RETENTION_MS, AppPolicies.retentionCutoff(now, false))
    }

    @Test fun replacesOnlyTheMatchingForegroundSession() {
        val result = AppPolicies.replaceSession(listOf(Item(1, "a"), Item(2, "b")), "a", Item::session, Item(3, "a"))
        assertEquals(listOf(Item(2, "b"), Item(3, "a")), result)
    }

    @Test fun offersFallbackAfterThreePreferredDirectFailures() {
        assertFalse(AppPolicies.shouldOfferScanFallback(2, true))
        assertTrue(AppPolicies.shouldOfferScanFallback(3, true))
        assertFalse(AppPolicies.shouldOfferScanFallback(3, false))
    }
}
