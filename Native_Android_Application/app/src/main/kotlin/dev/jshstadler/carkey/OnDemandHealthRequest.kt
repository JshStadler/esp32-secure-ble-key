package dev.jshstadler.carkey

/** One user request may wait for a connection, but never repeats on reconnect. */
class OnDemandHealthRequest {
    private var generation = 0
    private var waiting = false
    private var active = false

    fun begin(): Int {
        generation++
        waiting = true
        active = true
        return generation
    }

    fun takeWhenReady(): Int? {
        if (!active || !waiting) return null
        waiting = false
        return generation
    }

    fun complete(token: Int): Boolean {
        if (!active || generation != token) return false
        active = false
        waiting = false
        return true
    }

    fun cancel() { generation++; active = false; waiting = false }
}
