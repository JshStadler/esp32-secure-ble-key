package dev.logiclabs.remotekey

enum class BackgroundConnectionDuration(val milliseconds: Long, val label: String) {
    OFF(0, "Off"),
    THIRTY_SECONDS(30_000, "30 seconds"),
    TWO_MINUTES(120_000, "2 minutes");

    companion object {
        const val STORE_KEY = "background_connection_duration"
        fun fromSaved(value: String?) = entries.find { it.name == value } ?: TWO_MINUTES
    }
}

/** Automatic setup uses the saved preference; explicit press/health/reconnect
 * actions may still connect. Never interrupt a command that can change the ESP. */
internal object ConnectionPreferences {
    fun shouldAutoConnect(saved: String?, keyConfigured: Boolean) = keyConfigured && saved != "false"
    fun canRestart(pressPending: Boolean, keyChangePending: Boolean, firmwarePending: Boolean,
        radioPending: Boolean, firmwarePicker: Boolean) =
        !pressPending && !keyChangePending && !firmwarePending && !radioPending && !firmwarePicker
}
