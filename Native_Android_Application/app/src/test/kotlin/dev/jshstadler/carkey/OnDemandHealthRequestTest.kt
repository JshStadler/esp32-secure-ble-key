package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test

class OnDemandHealthRequestTest {
    @Test fun ordinaryConnectionsNeverFetch() {
        val request = OnDemandHealthRequest()
        repeat(10) { assertNull(request.takeWhenReady()) }
    }
    @Test fun openingWaitsForReadyThenFetchesOnlyOnce() {
        val request = OnDemandHealthRequest()
        val token = request.begin()
        assertEquals(token, request.takeWhenReady())
        assertNull(request.takeWhenReady())
        assertTrue(request.complete(token))
        assertNull(request.takeWhenReady())
        assertFalse(request.complete(token))
    }
    @Test fun closingWhileConnectingCancelsFetch() {
        val request = OnDemandHealthRequest()
        val token = request.begin()
        request.cancel()
        assertNull(request.takeWhenReady())
        assertFalse(request.complete(token))
    }
    @Test fun staleRepliesAndTimeoutsCannotReplaceNewRefresh() {
        val request = OnDemandHealthRequest()
        val old = request.begin()
        request.takeWhenReady()
        val fresh = request.begin()
        assertFalse(request.complete(old))
        assertEquals(fresh, request.takeWhenReady())
        assertTrue(request.complete(fresh))
    }
    @Test fun timeoutStopsFetchingOnLaterReconnect() {
        val request = OnDemandHealthRequest()
        val token = request.begin()
        assertTrue(request.complete(token))
        assertNull(request.takeWhenReady())
    }
}
