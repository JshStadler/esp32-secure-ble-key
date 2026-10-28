package dev.logiclabs.remotekey

/** One explicit tap at a time; a warm connection is never permission to replay a tap. */
internal class WidgetPressWindow {
    companion object { const val IDLE_MS = 30_000L }
    private var press: PendingButtonPress? = null
    private var started = 0L
    private var sent = false
    private var idleUntil = Long.MAX_VALUE
    var active = false
        private set
    val busy get() = press != null
    val dispatched get() = busy && sent

    fun tap(now: Long): Boolean {
        if (busy) return false
        press = PendingButtonPress(now)
        started = now
        sent = false
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
    fun complete(now: Long): Boolean {
        if (!busy) return false
        press?.cancel(); press = null
        idleUntil = now + IDLE_MS
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
    fun cancel() { press?.cancel(); press = null; active = false }
}
