package dev.jshstadler.carkey

import java.math.BigDecimal
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** BLE intervals use 0.625ms units; users enter milliseconds. */
data class RadioSettings(val fastMin: Int, val fastMax: Int, val slowMin: Int,
    val slowMax: Int, val idleSeconds: Int) {
    fun valid(): Boolean = fastMin in 32..3200 && fastMax in fastMin..3200 &&
        slowMin in fastMin..3200 && slowMax in maxOf(slowMin, fastMax)..3200 && idleSeconds in 5..3600

    fun encode(): ByteArray {
        require(valid())
        return ByteBuffer.allocate(10).order(ByteOrder.LITTLE_ENDIAN).apply {
            listOf(fastMin, fastMax, slowMin, slowMax, idleSeconds).forEach { putShort(it.toShort()) }
        }.array()
    }

    fun packet(nonce: ByteArray, key: String): ByteArray {
        require(nonce.size == 16)
        val data = encode()
        val transcript = "BLEKEY-RADIO1\u0000car-main\u0000".toByteArray(Charsets.US_ASCII) + nonce + data
        return byteArrayOf(4) + data + CarKeyProtocol.hmac(transcript, key)
    }

    fun recentText() = rangeText(fastMin, fastMax)
    fun inactiveText() = rangeText(slowMin, slowMax)

    companion object {
        val DEFAULT = RadioSettings(80, 160, 320, 640, 60)
        private fun ms(units: Int) = BigDecimal(units).multiply(BigDecimal("0.625")).stripTrailingZeros().toPlainString()
        private fun rangeText(min: Int, max: Int) = if (min == max) ms(min) else "${ms(min)}-${ms(max)}"

        fun fromInput(recent: String, inactive: String, seconds: String): RadioSettings {
            fun range(value: String): Pair<Int, Int> {
                val parts = value.trim().split('-').map { it.trim() }
                require(parts.size in 1..2) { "Enter an interval or a range, for example 100 or 50-100." }
                fun units(text: String): Int {
                    val n = text.toBigDecimalOrNull()
                    require(n != null && n >= BigDecimal(20) && n <= BigDecimal(2000)) { "Intervals must be between 20 and 2000 ms." }
                    return try { n.divide(BigDecimal("0.625")).intValueExact() }
                    catch (_: ArithmeticException) { throw IllegalArgumentException("Use multiples of 0.625 ms (whole multiples of 5 ms are simplest).") }
                }
                return units(parts[0]) to units(parts.last())
            }
            val fast = range(recent)
            val slow = range(inactive)
            val idle = seconds.trim().toIntOrNull()
            require(idle != null && idle in 5..3600) { "Inactivity must be 5-3600 seconds." }
            return RadioSettings(fast.first, fast.second, slow.first, slow.second, idle).also {
                require(it.valid()) { "Ranges must run low to high; inactive intervals must be at least as long as recent-activity intervals." }
            }
        }
    }
}
