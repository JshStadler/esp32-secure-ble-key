package dev.logiclabs.remotekey

/** A short, single-use authorization from an explicit button tap. UI visibility
 * does not change it; cancellation, teardown or its elapsed-time deadline does. */
internal class PendingButtonPress(private val startedAt: Long) {
    companion object {
        const val CONNECTION_TIMEOUT_MS = 10_000L
        const val RESULT_TIMEOUT_MS = 18_000L
    }

    private var consumed = false

    fun claim(now: Long): Boolean {
        if (consumed || now - startedAt >= CONNECTION_TIMEOUT_MS) return false
        consumed = true
        return true
    }

    fun cancel() { consumed = true }
}
