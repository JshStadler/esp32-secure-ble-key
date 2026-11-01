package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class PendingButtonPressTest {
    @Test fun pendingTapKeepsOffLeaseAliveUntilItIsDispatchedAndCompleted() {
        val press = PendingButtonPress(1_000)
        val lease = BackgroundGracePeriod(2_000, BackgroundConnectionDuration.OFF.milliseconds)
        assertFalse(lease.expired(3_000, true))
        assertTrue(press.claim(4_000))
        assertFalse(lease.expired(5_000, true)) // Still waiting for the ESP receipt.
        press.cancel()
        assertTrue(lease.expired(5_001, false))
        assertFalse(press.claim(5_002))
    }

    @Test fun returningToForegroundDoesNotAllowTheSameTapToSendTwice() {
        val press = PendingButtonPress(1_000)
        val lease = BackgroundGracePeriod(2_000, 30_000)
        assertTrue(press.claim(3_000))
        lease.cancel()
        assertFalse(press.claim(3_001))
        assertFalse(lease.expired(90_000, false))
    }

    @Test fun connectionArrivingAtTheDeadlineCannotSendEvenIfTimeoutCallbackIsDelayed() {
        val press = PendingButtonPress(1_000)
        assertFalse(press.claim(11_000))
        assertFalse(press.claim(90_000))
    }

    @Test fun connectionJustBeforeDeadlineCanSendOnce() {
        val press = PendingButtonPress(1_000)
        assertTrue(press.claim(10_999))
        assertFalse(press.claim(10_999))
    }

    @Test fun cancelOrTeardownRevokesATapBeforeConnectionCompletes() {
        val press = PendingButtonPress(1_000)
        press.cancel()
        assertFalse(press.claim(2_000))
    }

    @Test fun aNewTapDoesNotReviveAnOldCancelledAuthorization() {
        val old = PendingButtonPress(1_000)
        old.cancel()
        val next = PendingButtonPress(2_000)
        assertFalse(old.claim(3_000))
        assertTrue(next.claim(3_000))
    }
}
