package dev.logiclabs.remotekey

import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest

internal data class FirmwareVersion(val major: Int, val minor: Int, val patch: Int) : Comparable<FirmwareVersion> {
    override fun compareTo(other: FirmwareVersion) = compareValuesBy(this, other, { it.major }, { it.minor }, { it.patch })
    override fun toString() = "$major.$minor.$patch"
    companion object {
        fun parse(value: String?): FirmwareVersion? = value?.takeIf { it.matches(Regex("[0-9]{1,5}\\.[0-9]{1,5}\\.[0-9]{1,5}")) }
            ?.split('.')?.map(String::toInt)?.let { FirmwareVersion(it[0], it[1], it[2]) }
    }
}

internal data class FirmwareRelease(val version: FirmwareVersion, val beta: Boolean, val assetUrl: String,
    val releaseUrl: String, val size: Int, val sha256: String?, val gateBuild: String?) {
    val label get() = "$version${if (beta) " (beta)" else ""}"
    fun comparison(installed: DeviceHealth?): String {
        val running = FirmwareVersion.parse(installed?.firmware)
        return when {
            running == null -> "Latest: $label. Connect and read Device health to compare the installed version."
            version > running -> "Update available: $label (installed $running)"
            version < running -> "Installed $running is newer than published $label."
            gateBuild != null && installed?.build?.isNotEmpty() == true && gateBuild != installed.build ->
                "Config revision differs. Installed: ${installed.build}. Published: $gateBuild."
            else -> "Up to date: $running"
        }
    }
}

/** Public project release metadata only. Never sends PSKs, addresses or device names. */
internal class FirmwareUpdates(private val fetch: (String, Int) -> ByteArray = ::readHttps) {
    companion object {
        const val REPO = "https://github.com/JshStadler/esp32-secure-ble-key"
        const val FEED = "https://api.github.com/repos/JshStadler/esp32-secure-ble-key/releases?per_page=100"
        const val GATE_SOURCE = "$REPO/blob/main/ESPHome_Gate_Firmware/centurion-d5-evo-ble-v2.yaml"
        fun parse(json: String, type: BleDeviceType): FirmwareRelease? {
            val releases = JSONArray(json)
            require(releases.length() <= 100)
            return (0 until releases.length()).mapNotNull { index -> runCatching {
                val release = releases.getJSONObject(index)
                if (release.optBoolean("draft", true)) return@runCatching null
                val tag = release.getString("tag_name")
                val car = type == BleDeviceType.CAR
                val prefix = if (tag.startsWith("firmware-v")) "firmware-v"
                    else if (!car && tag.startsWith("gate-v")) "gate-v" else return@runCatching null
                val version = FirmwareVersion.parse(tag.removePrefix(prefix)) ?: return@runCatching null
                val name = if (car) "BLE-Car-Key-v$version-signed-ota.bin" else "Centurion-D5-Evo-v$version.yaml"
                val assets = release.getJSONArray("assets")
                require(assets.length() <= 100)
                val matches = (0 until assets.length()).map { assets.getJSONObject(it) }.filter { it.optString("name") == name }
                if (matches.size != 1) return@runCatching null
                val asset = matches.single()
                val url = "$REPO/releases/download/$tag/$name"
                require(asset.getString("browser_download_url") == url)
                val size = asset.getLong("size").also { require(it in 1..(if (car) FirmwareImageReader.MAX_IMAGE_SIZE else 262144).toLong()) }.toInt()
                val hash = asset.optString("digest").removePrefix("sha256:").takeIf { it.matches(Regex("[a-f0-9]{64}")) }
                if (car && hash == null) return@runCatching null
                val build = if (car) null else Regex("gate-ble-v${Regex.escape(version.toString())}-[a-z0-9-]{1,64}")
                    .find(release.optString("body").take(32768))?.value
                FirmwareRelease(version, release.optBoolean("prerelease"), url, "$REPO/releases/tag/$tag", size, hash, build)
            }.getOrNull() }.maxByOrNull { it.version }
        }
        private fun readHttps(url: String, limit: Int): ByteArray {
            var uri = URI(url)
            repeat(5) {
                require(uri.scheme == "https" && uri.userInfo == null && uri.port in listOf(-1, 443))
                require(uri.host in setOf("api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"))
                val connection = uri.toURL().openConnection() as HttpURLConnection
                try {
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 8000; connection.readTimeout = 12000
                    connection.setRequestProperty("User-Agent", "Remote-Key-Android")
                    connection.setRequestProperty("Accept", if (uri.host == "api.github.com") "application/vnd.github+json" else "application/octet-stream")
                    if (uri.host == "api.github.com") connection.setRequestProperty("X-GitHub-Api-Version", "2026-03-10")
                    val code = connection.responseCode
                    if (code in listOf(301, 302, 303, 307, 308)) {
                        uri = uri.resolve(connection.getHeaderField("Location") ?: error("Missing download location"))
                    } else {
                        check(code == 200) { if (code == 403 || code == 429) "GitHub rate limit; try again later" else "GitHub request failed ($code)" }
                        require(connection.contentLengthLong <= limit) { "Download exceeds the size limit" }
                        return connection.inputStream.use { input ->
                            val output = ByteArrayOutputStream()
                            val buffer = ByteArray(8192)
                            while (true) {
                                check(!Thread.currentThread().isInterrupted) { "Download canceled" }
                                val count = input.read(buffer)
                                if (count < 0) break
                                require(output.size() + count <= limit) { "Download exceeds the size limit" }
                                output.write(buffer, 0, count)
                            }
                            output.toByteArray()
                        }
                    }
                } finally { connection.disconnect() }
            }
            error("Too many download redirects")
        }
    }
    private var cached: Pair<Long, String>? = null
    @Synchronized fun check(type: BleDeviceType, force: Boolean = false): FirmwareRelease? {
        val now = System.nanoTime()
        val json = cached?.takeIf { !force && now - it.first < 300_000_000_000L }?.second
            ?: fetch(FEED, 1_048_576).toString(Charsets.UTF_8).also { cached = now to it }
        return parse(json, type)
    }
    fun download(release: FirmwareRelease): ByteArray {
        require(release.sha256 != null && release.assetUrl.startsWith("$REPO/releases/download/firmware-v"))
        require(release.size in 24..FirmwareImageReader.MAX_IMAGE_SIZE)
        val image = fetch(release.assetUrl, FirmwareImageReader.MAX_IMAGE_SIZE)
        require(image.size == release.size) { "Firmware size differs from the release" }
        val hash = MessageDigest.getInstance("SHA-256").digest(image).joinToString("") { "%02x".format(it) }
        require(hash == release.sha256) { "Firmware checksum verification failed" }
        require(image.size >= 24 && (image[0].toInt() and 255) == 0xe9 && (image[12].toInt() and 255) == 5 && image[13].toInt() == 0) {
            "Firmware is not an ESP32-C3 application image"
        }
        return image
    }
}
