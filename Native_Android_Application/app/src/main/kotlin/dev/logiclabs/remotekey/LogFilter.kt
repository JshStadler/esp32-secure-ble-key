package dev.logiclabs.remotekey

import java.util.Calendar
import java.util.TimeZone

/** A local calendar day has an exclusive next-midnight boundary, even across DST. */
data class LogDay(val year: Int, val month: Int, val day: Int) {
    fun bounds(zone: TimeZone = TimeZone.getDefault()): LongRange {
        val calendar = Calendar.getInstance(zone).apply {
            clear()
            set(year, month, day)
        }
        val start = calendar.timeInMillis
        calendar.add(Calendar.DAY_OF_MONTH, 1)
        return start until calendar.timeInMillis
    }
}

data class LogFilter(
    val deviceId: String? = null,
    val day: LogDay? = null,
    val query: String = "",
    val zone: TimeZone = TimeZone.getDefault(),
) {
    private val bounds = day?.bounds(zone)
    fun matches(timestamp: Long, entryDeviceId: String?, text: String): Boolean =
        (deviceId == null || deviceId == entryDeviceId) &&
            (bounds == null || timestamp in bounds) &&
            (query.isBlank() || text.contains(query.trim(), ignoreCase = true))
}
