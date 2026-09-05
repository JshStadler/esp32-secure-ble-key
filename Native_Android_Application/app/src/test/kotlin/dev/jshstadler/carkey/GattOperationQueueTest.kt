package dev.jshstadler.carkey

import org.junit.Assert.*
import org.junit.Test

class GattOperationQueueTest {
    private class Rig {
        val timers = mutableListOf<() -> Unit>()
        val failures = mutableListOf<String>()
        val starts = mutableListOf<String>()
        var idles = 0
        val queue = GattOperationQueue({ _, f -> timers.add(f); { timers.remove(f); Unit } }, failures::add, { idles++ })
        fun add(name: String, accepted: Boolean = true, done: () -> Unit = {}) =
            queue.enqueue(name, { starts.add(name); accepted }, done)
    }
    @Test fun waitsForWriteCallbackBeforeSendingQueuedPress() {
        val r = Rig()
        r.add("auth"); r.add("press")
        assertEquals(listOf("auth"), r.starts)
        assertFalse(r.queue.complete("stale-read", true))
        r.queue.complete("auth", true)
        assertEquals(listOf("auth", "press"), r.starts)
        r.queue.complete("press", true)
        assertFalse(r.queue.busy)
        assertTrue(r.timers.isEmpty())
    }
    @Test fun enqueueRejectionAndMissingCallbackTerminateAttemptWithoutReplayingPress() {
        val r = Rig()
        r.add("press", false)
        assertEquals(1, r.failures.size)
        assertFalse(r.queue.busy)
        r.add("press"); r.add("read")
        r.timers.single().invoke()
        assertEquals(2, r.failures.size)
        assertEquals(listOf("press", "press"), r.starts)
        assertFalse(r.queue.complete("press", true))
    }
    @Test fun oldTimeoutCannotCancelReplacementRequest() {
        val r = Rig()
        r.add("read")
        val stale = r.timers.single()
        r.queue.clear()
        r.add("read")
        stale()
        assertTrue(r.queue.busy)
        assertTrue(r.failures.isEmpty())
    }
    @Test fun completionCanEnqueueNextStageAndSynchronousCompletionDoesNotLeaveTimer() {
        val r = Rig()
        r.add("discover", done = { r.add("subscribe") })
        r.queue.complete("discover", true)
        assertEquals(listOf("discover", "subscribe"), r.starts)
        r.queue.complete("subscribe", true)
        r.queue.enqueue("sync", { r.queue.complete("sync", true); true })
        assertFalse(r.queue.busy)
        assertTrue(r.timers.isEmpty())
    }
    @Test fun failedCallbackDiscardsQueuedActions() {
        val r = Rig()
        r.add("read"); r.add("press")
        r.queue.complete("read", false)
        assertEquals(listOf("read"), r.starts)
        assertEquals(1, r.failures.size)
    }
}
