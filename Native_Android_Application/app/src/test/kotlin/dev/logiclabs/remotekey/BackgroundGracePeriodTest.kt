package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class BackgroundGracePeriodTest {
    @Test fun offExpiresImmediatelyUnlessAnOperationIsFinishing() {
        val period = BackgroundGracePeriod(5_000, BackgroundConnectionDuration.OFF.milliseconds)
        assertTrue(period.expired(5_000, false))
        assertFalse(period.expired(100_000, true))
        assertTrue(period.expired(100_000, false))
    }

    @Test fun shortDurationUsesElapsedTimeAndDoesNotRestartAfterAnOperation() {
        val period = BackgroundGracePeriod(5_000, BackgroundConnectionDuration.THIRTY_SECONDS.milliseconds)
        assertFalse(period.expired(34_999, false))
        assertTrue(period.expired(35_000, false))
        assertFalse(period.expired(60_000, true))
        assertTrue(period.expired(60_001, false))
    }

    @Test fun returningToAppCancelsAShortLease() {
        val period = BackgroundGracePeriod(0, 30_000)
        period.cancel()
        assertFalse(period.expired(1_000_000, false))
    }
    @Test fun disconnectsAtTwoMinutesIncludingTimeAsleep() {
        val period = BackgroundGracePeriod(1_000)
        assertFalse(period.expired(120_999, false))
        assertTrue(period.expired(121_000, false))
        assertTrue(period.expired(900_000, false))
    }
    @Test fun returningToAppCancelsOldDeadline() {
        val old = BackgroundGracePeriod(0)
        old.cancel()
        val next = BackgroundGracePeriod(100_000)
        assertFalse(old.expired(220_000, false))
        assertFalse(next.expired(219_999, false))
        assertTrue(next.expired(220_000, false))
    }
    @Test fun activeFirmwareTransferFinishesBeforeDisconnect() {
        val period = BackgroundGracePeriod(0)
        assertFalse(period.expired(180_000, true))
        assertTrue(period.expired(180_000, false))
    }
}
