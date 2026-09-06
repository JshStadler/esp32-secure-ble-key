package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test

class BackgroundGracePeriodTest {
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
