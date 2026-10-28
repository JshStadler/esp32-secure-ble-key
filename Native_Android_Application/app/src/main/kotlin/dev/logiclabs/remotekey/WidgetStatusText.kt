package dev.logiclabs.remotekey

internal object WidgetStatusText {
    enum class Tone(val background: Int, val accent: Int) {
        IDLE(R.drawable.widget_background, 0xFF8EB4FF.toInt()),
        CONNECTING(R.drawable.widget_background_connecting, 0xFFFFCC80.toInt()),
        SENDING(R.drawable.widget_background_sending, 0xFF9AC5FF.toInt()),
        CONFIRMED(R.drawable.widget_background_confirmed, 0xFF96E6AB.toInt()),
        ERROR(R.drawable.widget_background_error, 0xFFFFB4AB.toInt())
    }
    fun tone(message: String): Tone = when {
        message.startsWith("Pressed") -> Tone.CONFIRMED
        message.startsWith("Connecting") -> Tone.CONNECTING
        message.startsWith("Sending") -> Tone.SENDING
        message.startsWith("Unable to confirm") || message.startsWith("Not sent") || message.startsWith("Canceled") -> Tone.ERROR
        else -> Tone.IDLE
    }
    fun label(message: String): String = when {
        message.startsWith("Pressed") -> "Pressed ✓"
        message.startsWith("Unable to confirm") -> "Check device"
        message.startsWith("Not sent") -> "Not sent"
        message.startsWith("Canceled") -> "Canceled"
        message == "Tap to reconnect" -> "Disconnected"
        else -> message
    }
    fun compactLabel(message: String): String = when (tone(message)) {
        Tone.CONNECTING -> "Wait…"
        Tone.SENDING -> "Send…"
        Tone.CONFIRMED -> "Done"
        Tone.ERROR -> when {
            message.startsWith("Unable to confirm") -> "Check"
            message.startsWith("Canceled") -> "Cancel"
            else -> "Unsent"
        }
        Tone.IDLE -> label(message)
    }
    fun replacesCompactName(message: String) = tone(message) != Tone.IDLE
}
