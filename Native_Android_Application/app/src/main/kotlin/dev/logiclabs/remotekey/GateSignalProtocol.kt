package dev.logiclabs.remotekey

import java.security.SecureRandom

/** Optional, authenticated-session diagnostic; never a command or distance estimate. */
object GateSignalProtocol {
    data class Reply(val pending: Boolean, val rssi: Int?)
    fun newRequest() = ByteArray(8).also { SecureRandom().nextBytes(it) }

    fun parse(value: ByteArray, request: ByteArray): Reply? {
        if (request.size != 8 || value.size != 10 || !value.copyOfRange(1, 9).contentEquals(request)) return null
        return when (value[0].toInt()) {
            0 -> Reply(true, null)
            1 -> value[9].toInt().takeIf { it in -127..20 }?.let { Reply(false, it) }
            2 -> Reply(false, null)
            else -> null
        }
    }
}
