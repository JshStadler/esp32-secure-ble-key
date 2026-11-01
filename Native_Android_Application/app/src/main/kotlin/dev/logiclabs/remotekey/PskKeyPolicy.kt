package dev.logiclabs.remotekey

/** Checks obvious weaknesses; only a random generator can establish key entropy. */
object PskKeyPolicy {
    const val MIN_NEW_KEY_BYTES = 32
    const val MAX_KEY_BYTES = 128
    const val NEW_KEY_GUIDANCE = "Use Generate secure PSK, or 32–128 UTF-8 bytes with at least 8 different bytes and no repeating pattern."

    fun validExisting(value: String): Boolean = value.isNotEmpty() &&
        '\u0000' !in value && value.toByteArray(Charsets.UTF_8).size <= MAX_KEY_BYTES

    fun validNew(value: String): Boolean {
        if (!validExisting(value)) return false
        val bytes = value.toByteArray(Charsets.UTF_8)
        if (bytes.size < MIN_NEW_KEY_BYTES || bytes.toSet().size < 8) return false
        // Include partial final repeats, e.g. a 127-byte repeated pattern.
        for (period in 1..16) {
            if ((period until bytes.size).all { bytes[it] == bytes[it % period] }) return false
        }
        return true
    }
}
