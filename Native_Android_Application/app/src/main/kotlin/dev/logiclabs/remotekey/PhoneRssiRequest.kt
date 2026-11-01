package dev.logiclabs.remotekey

/** HCI RSSI callbacks have no request ID. Keep timed-out requests quarantined
 * until their callback drains, so it can never complete a newer measurement. */
internal class PhoneRssiRequest {
    private var sequence = 0L
    private var outstanding: Long? = null
    private var completion: ((Int?) -> Unit)? = null

    fun request(start: () -> Boolean, timeout: (() -> Unit) -> Unit, done: (Int?) -> Unit) {
        if (outstanding != null) { done(null); return }
        val ticket = ++sequence
        outstanding = ticket
        completion = done
        if (!start()) {
            if (outstanding == ticket) { outstanding = null; finish(null) }
        } else timeout {
            if (outstanding == ticket) finish(null) // Do not release HCI ownership.
        }
    }

    fun complete(value: Int?) {
        if (outstanding == null) return
        outstanding = null
        finish(value?.takeIf { it in -127..20 })
    }

    private fun finish(value: Int?) {
        val done = completion
        completion = null
        done?.invoke(value)
    }

    fun cancel() { completion = null }
    // Only reset when the owning GATT is discarded; its callbacks are filtered there.
    fun reset() { sequence++; outstanding = null; completion = null }
}
