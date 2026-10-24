package dev.logiclabs.remotekey

/** A single authenticated snapshot, never a cached estimate or a battery reading. */
data class DeviceHealth(
    val firmware: String, val build: String, val idf: String,
    val uptimeSeconds: Long, val resetReason: String, val otaState: String,
    val freeHeap: Long, val minimumHeap: Long, val connections: Long,
    val advertisingRecoveries: Long, val ghostReaps: Long,
    val radio: RadioSettings? = null, val advertisingMode: String = "unknown",
    val espRssi: Int? = null, val phoneRssi: Int? = null,
    val hasFirmwareHealth: Boolean = true,
    val espSignalSupported: Boolean = false,
    val advertisingTxDbm: Int? = null, val connectionTxDbm: Int? = null,
    val powerMode: String = "fixed", val connectionPowerHeldHigh: Boolean = false,
) {
    fun display(): String {
        val signal = "BLE signal strength\n" +
            "At phone (ESP → phone): ${phoneRssi?.let { "$it dBm" } ?: "Unavailable"}\n" +
            "At ESP (phone → ESP): ${espRssi?.let { "$it dBm" } ?: if (espSignalSupported) "Unavailable — tap Refresh to retry" else "Unavailable — firmware support required"}\n" +
            "Closer to 0 dBm means a stronger received signal. These are connection snapshots, not transmit power."
        if (!hasFirmwareHealth) return "$signal\n\nDetailed ESP health is not supported by this firmware. Tap Refresh for a new phone signal reading."
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
        val advertising = radio?.let { settings ->
            val power = settings.txPowerDbm?.let { recent ->
                val targets = settings.idleTxPowerDbm?.let { idle ->
                    if (connectionPowerHeldHigh) "Connected links / recent advertising: $recent dBm\n" +
                        "Inactive advertising: $idle dBm\nAdvertising power mode: $powerMode"
                    else "Recent activity: $recent dBm\nInactive: $idle dBm\nPower mode: $powerMode"
                } ?: "Saved target: $recent dBm"
                "\n\nESP transmit power\n$targets\n" +
                    "Advertising: ${advertisingTxDbm?.let { "$it dBm" } ?: "Unavailable"}\n" +
                    "This connection: ${connectionTxDbm?.let { "$it dBm" } ?: "Unavailable"}"
            }.orEmpty()
            "\n\nAdvertising: $advertisingMode\nRecent activity: ${settings.recentText()} ms\n" +
                "Inactive: ${settings.inactiveText()} ms\nInactivity before slowing: ${settings.idleSeconds}s$power"
        }.orEmpty()
        return "$signal\n\nFirmware: $firmware\nBuild: $build\nOTA status: $ota\n\n" +
            "Uptime: ${uptimeSeconds / 86400}d ${uptimeSeconds / 3600 % 24}h ${uptimeSeconds / 60 % 60}m ${uptimeSeconds % 60}s\n" +
            "Last reset: $reset\n\n" +
            "Free memory: ${freeHeap / 1024} KiB\nLowest free memory: ${minimumHeap / 1024} KiB\n" +
            "BLE connections: $connections\nAdvertising recoveries: $advertisingRecoveries\n" +
            "Stale connections cleared: $ghostReaps\nESP-IDF: $idf$advertising\n\n" +
            "Memory minimum and recovery counts are since this boot. This is a one-time snapshot; tap Refresh for new data."
    }

    companion object {
        fun signalOnly(espSignalSupported: Boolean = false) = DeviceHealth("", "", "", 0, "", "unknown", 0, 0, 0, 0, 0,
            hasFirmwareHealth = false, espSignalSupported = espSignalSupported)
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
            fun signed(key: String, range: IntRange): Int? = fields[key]?.let {
                require(it.matches(Regex("-?[0-9]{1,3}")))
                it.toInt().also { n -> require(n in range) }
            }
            val tx = if ("radio2" in caps) signed("txdbm", -12..9).also { require(it != null) } else null
            val dualPower = "radio3" in caps
            val idleTx = if (dualPower) signed("txidle", -12..9).also { require(it != null) } else null
            val powerMode = if (dualPower) field("txmode").also { require(it in listOf("recent", "inactive", "update")) } else "fixed"
            val radio = if ("radio1" in caps) RadioSettings(number("fastmin", 3200).toInt(),
                number("fastmax", 3200).toInt(), number("slowmin", 3200).toInt(),
                number("slowmax", 3200).toInt(), number("idlesec", 3600).toInt(), tx, idleTx).also { require(it.valid()) } else null
            val rssi = fields["rssi"]?.let { value ->
                require(value.matches(Regex("-?[0-9]{1,3}")))
                value.toInt().also { require(it in -127..20) }
            }
            DeviceHealth(field("fw"), build, field("idf"), number("up", Long.MAX_VALUE),
                field("reset"), field("ota"), heap, minimum, number("links", 3),
                number("advrec"), number("ghost"), radio, if (radio == null) "unknown" else field("advmode"), espRssi = rssi,
                espSignalSupported = true, advertisingTxDbm = signed("txadv", -24..20),
                connectionTxDbm = signed("txconn", -24..20), powerMode = powerMode, connectionPowerHeldHigh = "linkpower1" in caps)
        }.getOrNull()
    }
}
