package dev.logiclabs.remotekey

/** One explicit tap at a time; a warm connection is never permission to replay a tap. */
internal class WidgetPressWindow {
    private var press: PendingButtonPress? = null
    private var started = 0L
    private var sent = false
    private var requestId: String? = null
    private var idleUntil = Long.MAX_VALUE
    var active = false
        private set
    val busy get() = press != null
    val dispatched get() = busy && sent
    val cancellationId get() = requestId?.takeIf { busy && !sent }

    fun tap(now: Long, requestId: String? = null): Boolean {
        if (busy) return false
        press = PendingButtonPress(now)
        started = now
        sent = false
        this.requestId = requestId
        active = true
        idleUntil = Long.MAX_VALUE
        return true
    }
    fun claim(now: Long): Boolean {
        if (sent || press?.claim(now) != true) return false
        sent = true
        return true
    }
    fun timeout(now: Long): String? = when {
        !busy -> null
        !sent && now - started >= PendingButtonPress.CONNECTION_TIMEOUT_MS -> "Not sent — connection timed out"
        sent && now - started >= PendingButtonPress.RESULT_TIMEOUT_MS -> "Unable to confirm — check the device"
        else -> null
    }
    fun complete(now: Long, durationMs: Long = 30_000L): Boolean {
        if (!busy) return false
        press?.cancel(); press = null
        idleUntil = now + durationMs.coerceAtLeast(0)
        return true
    }
    fun expired(now: Long) = active && !busy && now >= idleUntil
    fun nextCheckDelay(now: Long): Long {
        val deadline = when {
            busy -> started + if (sent) PendingButtonPress.RESULT_TIMEOUT_MS else PendingButtonPress.CONNECTION_TIMEOUT_MS
            active -> idleUntil
            else -> now
        }
        return (deadline - now).coerceAtLeast(1)
    }
    /** A delayed launcher/notification tap may cancel only the request it displayed. */
    fun cancelPending(requestId: String?): Boolean {
        if (requestId == null || requestId != cancellationId) return false
        cancel()
        return true
    }
    fun cancel() { press?.cancel(); press = null; requestId = null; active = false }
}
