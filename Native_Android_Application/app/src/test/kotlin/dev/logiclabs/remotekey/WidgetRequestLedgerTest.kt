package dev.logiclabs.remotekey

import org.junit.Assert.*
import org.junit.Test

class WidgetRequestLedgerTest {
    @Test fun rejectsMissingFutureExpiredAndRepeatedAuthorizations() {
        val ledger = WidgetRequestLedger()
        assertFalse(ledger.accept(null, 0, 0))
        assertFalse(ledger.accept("", 0, 0))
        assertFalse(ledger.accept("future", 2, 1))
        assertFalse(ledger.accept("missing-time", -1, 1))
        assertFalse(ledger.accept("old", 0, 10_000))
        assertTrue(ledger.accept("tap", 10, 10))
        assertFalse(ledger.accept("tap", 10, 11))
    }
    @Test fun fillingTheLedgerCannotEvictAnUnexpiredRequestAndAllowReplay() {
        val ledger = WidgetRequestLedger()
        repeat(256) { assertTrue(ledger.accept("tap-$it", 0, 0)) }
        assertFalse(ledger.accept("overflow", 1, 1))
        assertFalse(ledger.accept("tap-0", 0, 2))
        assertTrue(ledger.accept("fresh", 10_000, 10_000))
        assertFalse(ledger.accept("tap-0", 0, 10_000))
    }
}
