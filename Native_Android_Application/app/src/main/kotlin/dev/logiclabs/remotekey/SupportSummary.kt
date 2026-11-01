package dev.logiclabs.remotekey

data class TimedDeviceHealth(val health: DeviceHealth, val capturedAt: Long)

/** Deliberately accepts no credentials, device names/addresses, locations or logs. */
data class SupportDeviceInfo(val kind: String, val state: String, val ready: Boolean,
    val autoConnect: Boolean, val snapshot: TimedDeviceHealth?)

object SupportSummary {
    fun format(version: String, build: Int, androidApi: Int, bluetooth: String,
        duration: BackgroundConnectionDuration, devices: List<SupportDeviceInfo>, now: Long): String = buildString {
        appendLine("Remote Key support summary")
        appendLine("App version: $version (build $build)")
        appendLine("Android API: $androidApi")
        appendLine("Bluetooth: $bluetooth")
        appendLine("Background connections: ${duration.label}")
        appendLine("Device count: ${devices.size}")
        devices.forEachIndexed { index, device ->
            appendLine()
            appendLine("Device ${index + 1}: ${device.kind}")
            appendLine("Connection: ${if (device.ready) "Ready" else device.state}")
            appendLine("Auto-connect: ${if (device.autoConnect) "On" else "Off"}")
            val snapshot = device.snapshot
            if (snapshot == null) {
                appendLine("Health: not collected this app session. Open Device health and Refresh.")
            } else {
                val health = snapshot.health
                appendLine("Last health snapshot: ${((now - snapshot.capturedAt).coerceAtLeast(0) / 1000)} seconds ago; may be stale.")
                if (health.hasFirmwareHealth) {
                    appendLine("ESP firmware: ${health.firmware}")
                    appendLine("ESP build: ${health.build}")
                    appendLine("OTA state: ${health.otaState}")
                } else appendLine("ESP firmware: not reported by this firmware")
                appendLine("BLE at phone (ESP → phone): ${health.phoneRssi?.let { "$it dBm" } ?: "Unavailable"}")
                appendLine("BLE at ESP (phone → ESP): ${health.espRssi?.let { "$it dBm" } ?: "Unavailable"}")
            }
        }
        appendLine()
        append("No PSKs, device names, BLE addresses, locations or diagnostic logs are included.")
    }
}
