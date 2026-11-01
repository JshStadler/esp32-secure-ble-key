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
    var connectingOnly = false
        private set
    val busy get() = press != null
    val dispatched get() = busy && sent
    val cancellationId get() = requestId?.takeIf { busy && !sent }

    fun tap(now: Long, requestId: String? = null): Boolean {
        if (busy) return false
        connectingOnly = false
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
        connectingOnly && now - started >= PendingButtonPress.CONNECTION_TIMEOUT_MS -> "Not sent — connection timed out"
        !busy -> null
        !sent && now - started >= PendingButtonPress.CONNECTION_TIMEOUT_MS -> "Not sent — connection timed out"
        sent && now - started >= PendingButtonPress.RESULT_TIMEOUT_MS -> "Unable to confirm — check the device"
        else -> null
    }
    fun complete(now: Long, durationMs: Long = 30_000L): Boolean {
        if (!busy && !connectingOnly) return false
        press?.cancel(); press = null
        connectingOnly = false; requestId = null
        idleUntil = now + durationMs.coerceAtLeast(0)
        return true
    }
    fun expired(now: Long) = active && !busy && !connectingOnly && now >= idleUntil
    fun nextCheckDelay(now: Long): Long {
        val deadline = when {
            busy || connectingOnly -> started + if (sent) PendingButtonPress.RESULT_TIMEOUT_MS else PendingButtonPress.CONNECTION_TIMEOUT_MS
            active -> idleUntil
            else -> now
        }
        return (deadline - now).coerceAtLeast(1)
    }
    /** A delayed launcher/notification tap may cancel only the request it displayed. */
    fun cancelPending(requestId: String?): Boolean {
        if (requestId == null || requestId != cancellationId) return false
        // Revoke the command permanently, preserving the original connection
        // attempt and its deadline. A fresh tap is required to authorize a press.
        press?.cancel(); press = null; this.requestId = null
        connectingOnly = true
        return true
    }
    fun cancel() { press?.cancel(); press = null; requestId = null; connectingOnly = false; active = false }
}
