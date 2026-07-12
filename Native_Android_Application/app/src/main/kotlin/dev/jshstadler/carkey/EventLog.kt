package dev.jshstadler.carkey

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object EventLog {
    enum class Kind(val key: String) { DIAGNOSTIC("diagnostic"), PRESS("presses") }
    data class Entry(val timestamp: Long, val message: String, val session: String? = null)
    data class LocationEntry(val timestamp: Long, val latitude: Double, val longitude: Double, val accuracy: Float, val session: String? = null)

    private const val PREFS = "car_key_logs"
    private const val LOCATIONS_KEY = "locations"

    @Synchronized
    fun add(context: Context, kind: Kind, message: String, timestamp: Long = System.currentTimeMillis()) {
        val entries = read(context, kind).toMutableList()
        entries += Entry(timestamp, message)
        write(context, kind, entries)
    }

    @Synchronized
    fun addSessionPress(context: Context, message: String, session: String) {
        val entries = read(context, Kind.PRESS).filterNot { it.session == session }.toMutableList()
        entries += Entry(System.currentTimeMillis(), message, session)
        write(context, Kind.PRESS, entries)
    }

    @Synchronized
    fun read(context: Context, kind: Kind): List<Entry> {
        val retention = if (kind == Kind.DIAGNOSTIC) 24L * 60 * 60 * 1000 else 7L * 24 * 60 * 60 * 1000
        val cutoff = System.currentTimeMillis() - retention
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val raw = prefs.getString(kind.key, "[]") ?: "[]"
        val result = mutableListOf<Entry>()
        try {
            val array = JSONArray(raw)
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val timestamp = item.optLong("time")
                if (timestamp >= cutoff) result += Entry(timestamp, item.optString("message"), item.optString("session").ifEmpty { null })
            }
        } catch (_: Exception) {
            // A corrupt log should never prevent the car key from operating.
        }
        if (result.size != runCatching { JSONArray(raw).length() }.getOrDefault(0)) write(context, kind, result)
        return result.sortedByDescending { it.timestamp }
    }

    @Synchronized
    fun clear(context: Context, kind: Kind) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(kind.key).apply()
    }

    @Synchronized
    fun addLocation(context: Context, latitude: Double, longitude: Double, accuracy: Float, session: String, operationTime: Long) {
        val current = readLocations(context)
        if (current.any { it.session == session && it.timestamp > operationTime }) return
        val entries = current.filterNot { it.session == session }.toMutableList()
        entries.add(0, LocationEntry(operationTime, latitude, longitude, accuracy, session))
        writeLocations(context, entries.take(30))
    }

    @Synchronized
    fun readLocations(context: Context): List<LocationEntry> {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(LOCATIONS_KEY, "[]") ?: "[]"
        return try {
            val array = JSONArray(raw)
            (0 until array.length()).map { index ->
                val item = array.getJSONObject(index)
                LocationEntry(item.getLong("time"), item.getDouble("lat"), item.getDouble("lon"), item.optDouble("accuracy").toFloat(), item.optString("session").ifEmpty { null })
            }.take(30)
        } catch (_: Exception) {
            emptyList()
        }
    }

    @Synchronized
    fun clearLocations(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(LOCATIONS_KEY).apply()
    }

    private fun write(context: Context, kind: Kind, entries: List<Entry>) {
        val array = JSONArray()
        entries.takeLast(2_000).forEach { entry ->
            array.put(JSONObject().put("time", entry.timestamp).put("message", entry.message).apply {
                entry.session?.let { put("session", it) }
            })
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(kind.key, array.toString()).apply()
    }

    private fun writeLocations(context: Context, entries: List<LocationEntry>) {
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(JSONObject().put("time", entry.timestamp).put("lat", entry.latitude).put("lon", entry.longitude).put("accuracy", entry.accuracy.toDouble()).apply {
                entry.session?.let { put("session", it) }
            })
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(LOCATIONS_KEY, array.toString()).apply()
    }
}
