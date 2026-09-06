package dev.jshstadler.carkey

/** Uses elapsed time, so screen-off sleep cannot reset the two-minute deadline. */
internal class BackgroundGracePeriod(private val startedAt: Long) {
    companion object { const val DURATION_MS = 120_000L }
    private var cancelled = false
    fun cancel() { cancelled = true }
    fun expired(now: Long, transferActive: Boolean): Boolean =
        !cancelled && !transferActive && now - startedAt >= DURATION_MS
}
