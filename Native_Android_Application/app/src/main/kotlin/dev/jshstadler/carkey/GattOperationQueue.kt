package dev.jshstadler.carkey

/** One ATT request at a time. Call exclusively from the client's dispatcher. */
internal class GattOperationQueue(
    private val schedule: (Long, () -> Unit) -> (() -> Unit),
    private val failed: (String) -> Unit,
    private val idle: () -> Unit,
) {
    private data class Request(val name: String, val start: () -> Boolean, val done: () -> Unit)
    private val pending = ArrayDeque<Request>()
    private var active: Request? = null
    private var cancelTimeout: (() -> Unit)? = null
    val busy get() = active != null || pending.isNotEmpty()

    fun contains(name: String) = active?.name == name || pending.any { it.name == name }

    fun enqueue(name: String, start: () -> Boolean, done: () -> Unit = {}) {
        pending.addLast(Request(name, start, done))
        drain()
    }

    fun complete(name: String, success: Boolean): Boolean {
        val request = active ?: return false
        if (request.name != name) return false
        cancelTimeout?.invoke()
        cancelTimeout = null
        active = null
        if (!success) {
            clear()
            failed("$name callback failed")
        } else {
            request.done()
            drain()
        }
        return true
    }

    fun clear() {
        cancelTimeout?.invoke()
        cancelTimeout = null
        active = null
        pending.clear()
    }

    private fun drain() {
        if (active != null) return
        val request = pending.removeFirstOrNull() ?: return idle()
        active = request
        // Arm before starting: fake transports (and some callback adapters) can
        // complete synchronously. The timeout belongs to this exact request.
        cancelTimeout = schedule(6_000) {
            if (active === request) {
                clear()
                failed("${request.name} callback timed out")
            }
        }
        val accepted = runCatching { request.start() }.getOrDefault(false)
        if (!accepted && active === request) {
            clear()
            failed("${request.name} was not accepted by Android")
        }
    }
}
