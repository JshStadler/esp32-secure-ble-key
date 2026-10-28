package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class WidgetPressWindowTest {
    @Test fun oneTapCanOnlyAuthorizeOneCommand() {
        val w = WidgetPressWindow()
        assertTrue(w.tap(100))
        assertFalse(w.tap(200))
        assertTrue(w.claim(300))
        assertFalse(w.claim(301))
        assertFalse(w.tap(400))
    }
    @Test fun theConnectionLeaseStartsAfterTheResultAndRestartsAfterEachPress() {
        val w = WidgetPressWindow()
        w.tap(0); w.claim(9_000); w.complete(10_000)
        assertFalse(w.expired(39_999))
        assertTrue(w.tap(39_999))
        assertFalse(w.expired(40_000))
        assertTrue(w.claim(40_000))
        assertTrue(w.complete(41_000))
        assertFalse(w.expired(70_999))
        assertTrue(w.expired(71_000))
    }
    @Test fun connectionArrivingAfterTheDeadlineCannotSendAStalePress() {
        val w = WidgetPressWindow()
        w.tap(1_000)
        assertNotNull(w.timeout(11_000))
        assertFalse(w.claim(11_000))
        assertFalse(w.claim(30_000))
    }
    @Test fun waitingForTheReceiptDoesNotExpireTheWarmConnectionTimer() {
        val w = WidgetPressWindow()
        w.tap(0); w.claim(9_999)
        assertNull(w.timeout(17_999))
        assertEquals("Unable to confirm — check the device", w.timeout(18_000))
        assertFalse(w.expired(18_000))
    }
    @Test fun cancellationMakesLaterReadyCallbacksHarmless() {
        val w = WidgetPressWindow()
        w.tap(0); w.cancel()
        assertFalse(w.claim(1))
        assertFalse(w.complete(2))
        assertFalse(w.busy)
        assertFalse(w.active)
    }
    @Test fun duplicateResultsCannotExtendTheConnectionLease() {
        val w = WidgetPressWindow()
        w.tap(0); w.claim(1); assertTrue(w.complete(2))
        assertFalse(w.complete(29_000))
        assertTrue(w.expired(30_002))
    }
    @Test fun scheduleFollowsTheCurrentDeadlineWithoutPollingDuringTheLease() {
        val w = WidgetPressWindow()
        w.tap(100)
        assertEquals(10_000, w.nextCheckDelay(100))
        w.claim(1_000)
        assertEquals(17_100, w.nextCheckDelay(1_000))
        w.complete(2_000)
        assertEquals(30_000, w.nextCheckDelay(2_000))
        assertEquals(1, w.nextCheckDelay(40_000))
    }
}
