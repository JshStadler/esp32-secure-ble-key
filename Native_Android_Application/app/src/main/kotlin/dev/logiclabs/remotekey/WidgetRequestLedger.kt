package dev.logiclabs.remotekey

/** Keep every live authorization until expiry; capacity pressure must never enable replay. */
internal class WidgetRequestLedger {
    private val requests = mutableMapOf<String, Long>()
    fun accept(id: String?, requestedAt: Long, now: Long): Boolean {
        requests.entries.removeAll { now - it.value >= PendingButtonPress.CONNECTION_TIMEOUT_MS }
        if (id.isNullOrBlank() || requestedAt < 0 || now - requestedAt !in 0 until PendingButtonPress.CONNECTION_TIMEOUT_MS ||
            id in requests || requests.size >= 256) return false
        requests[id] = requestedAt
        return true
    }
}
