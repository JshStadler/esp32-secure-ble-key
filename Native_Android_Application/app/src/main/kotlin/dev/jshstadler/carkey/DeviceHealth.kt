package dev.jshstadler.carkey

/** A single authenticated snapshot, never a cached estimate or a battery reading. */
data class DeviceHealth(
    val firmware: String, val build: String, val idf: String,
    val uptimeSeconds: Long, val resetReason: String, val otaState: String,
    val freeHeap: Long, val minimumHeap: Long, val connections: Long,
    val advertisingRecoveries: Long, val ghostReaps: Long,
    val radio: RadioSettings? = null, val advertisingMode: String = "unknown",
) {
    fun display(): String {
        val ota = when (otaState) {
            "valid" -> "Validated"
            "pending" -> "Checking BLE health — refresh after one minute"
            "initial" -> "Initial / USB installation"
            else -> "Unknown"
        }
        val reset = when (resetReason) {
            "ota_update" -> "Firmware update"
            "scheduled_idle" -> "Scheduled restart while idle"
            "scheduled_daily" -> "Scheduled daily restart"
            "power_on" -> "Power on"
            "brownout" -> "Brownout / low supply voltage"
            "ble_host_reset" -> "BLE host reset"
            "ble_host_exit" -> "BLE host stopped"
            "ble_host_stall" -> "BLE host stopped responding"
            "advertising_failure" -> "Advertising recovery failed"
            "ota_health_failure" -> "OTA health check failed"
            else -> resetReason.replace('_', ' ')
        }
        val advertising = radio?.let { "\n\nAdvertising: $advertisingMode\nRecent activity: ${it.recentText()} ms\n" +
            "Inactive: ${it.inactiveText()} ms\nInactivity before slowing: ${it.idleSeconds}s" }.orEmpty()
        return "Firmware: $firmware\nBuild: $build\nOTA status: $ota\n\n" +
            "Uptime: ${uptimeSeconds / 86400}d ${uptimeSeconds / 3600 % 24}h ${uptimeSeconds / 60 % 60}m ${uptimeSeconds % 60}s\n" +
            "Last reset: $reset\n\n" +
            "Free memory: ${freeHeap / 1024} KiB\nLowest free memory: ${minimumHeap / 1024} KiB\n" +
            "BLE connections: $connections\nAdvertising recoveries: $advertisingRecoveries\n" +
            "Stale connections cleared: $ghostReaps\nESP-IDF: $idf$advertising\n\n" +
            "Memory minimum and recovery counts are since this boot. This is a one-time snapshot; tap Refresh for new data."
    }

    companion object {
        fun capabilities(value: String): List<String> = value.split('|').let {
            if (it.size == 5 && it[0] == "blekey" && it[1] == "2" && it[3] == "car") it[4].split(',') else emptyList()
        }

        fun parse(value: String): DeviceHealth? = runCatching {
            require(value.length <= 512)
            val caps = capabilities(value)
            require("health1" in caps)
            val pairs = caps.filter { '=' in it }.map { it.substringBefore('=') to it.substringAfter('=') }
            require(pairs.map { it.first }.distinct().size == pairs.size)
            val fields = pairs.toMap()
            fun field(key: String): String = fields.getValue(key).also {
                require(it.isNotEmpty() && it.length <= 32 && it.all { c -> c.code in 32..126 })
            }
            fun number(key: String, max: Long = 0xffffffffL): Long = field(key).also {
                require(it.all(Char::isDigit))
            }.toLong().also { require(it in 0..max) }
            val build = field("build").also { require(it.matches(Regex("[a-fA-F0-9]{12}"))) }
            val heap = number("heap")
            val minimum = number("minheap").also { require(it <= heap) }
            val radio = if ("radio1" in caps) RadioSettings(number("fastmin", 3200).toInt(),
                number("fastmax", 3200).toInt(), number("slowmin", 3200).toInt(),
                number("slowmax", 3200).toInt(), number("idlesec", 3600).toInt()).also { require(it.valid()) } else null
            DeviceHealth(field("fw"), build, field("idf"), number("up", Long.MAX_VALUE),
                field("reset"), field("ota"), heap, minimum, number("links", 3),
                number("advrec"), number("ghost"), radio, if (radio == null) "unknown" else field("advmode"))
        }.getOrNull()
    }
}
