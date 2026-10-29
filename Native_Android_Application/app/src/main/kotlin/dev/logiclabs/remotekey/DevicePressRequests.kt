package dev.logiclabs.remotekey

import java.util.UUID

/** Each device owns one explicit tap; completing one never authorizes or clears another. */
internal class DevicePressRequests {
    class Request(now: Long) {
        val session = UUID.randomUUID().toString()
        private val authorization = PendingButtonPress(now)
        var dispatched = false
            private set
        fun claim(now: Long): Boolean {
            if (dispatched || !authorization.claim(now)) return false
            dispatched = true
            return true
        }
        fun cancel() = authorization.cancel()
    }
    private val requests = mutableMapOf<String, Request>()
    val busy get() = requests.isNotEmpty()
    val deviceIds get() = requests.keys.toList()
    operator fun get(deviceId: String) = requests[deviceId]
    fun begin(deviceId: String, now: Long): Request? {
        if (deviceId in requests) return null
        return Request(now).also { requests[deviceId] = it }
    }
    fun finish(deviceId: String): Request? = requests.remove(deviceId)?.also { it.cancel() }
    fun clear() { requests.values.forEach { it.cancel() }; requests.clear() }
}
