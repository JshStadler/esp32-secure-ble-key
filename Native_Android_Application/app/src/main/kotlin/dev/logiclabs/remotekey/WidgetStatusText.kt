package dev.logiclabs.remotekey

internal object WidgetStatusText {
    fun label(message: String): String = when {
        message.startsWith("Pressed") -> "Ready • 30s"
        message.startsWith("Unable to confirm") -> "Check device"
        message.startsWith("Not sent") -> "Not sent"
        message.startsWith("Canceled") -> "Canceled"
        message == "Tap to reconnect" -> "Disconnected"
        else -> message
    }
}
