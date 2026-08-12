package dev.jshstadler.carkey

import java.security.SecureRandom

object DevicePskGenerator {
    private const val DEFAULT_BYTES = 16
    private val random = SecureRandom()

    /** Returns 128 random bits as 32 lowercase hexadecimal characters. */
    fun generate(): String = ByteArray(DEFAULT_BYTES)
        .also(random::nextBytes)
        .toLowercaseHex()

    internal fun ByteArray.toLowercaseHex(): String = joinToString(separator = "") {
        "%02x".format(it.toInt() and 0xff)
    }
}
