package dev.logiclabs.remotekey

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.util.concurrent.Executors
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future

/** Checks only while explicitly opened. Closing the view invalidates every callback. */
internal class FirmwareUpdatePanel(private val activity: Activity, private val profile: BleDeviceProfile,
    private val installed: () -> DeviceHealth?, private val install: (ByteArray) -> Unit,
    private val updates: FirmwareUpdates = repository, private val executor: ExecutorService = workers) : LinearLayout(activity) {
    companion object {
        private val workers = Executors.newFixedThreadPool(2) { task -> Thread(task, "firmware-release").apply { isDaemon = true } }
        private val repository = FirmwareUpdates()
    }
    private val handler = Handler(Looper.getMainLooper())
    private val status = TextView(activity).apply { setTextColor(Color.LTGRAY); textSize = 14f }
    private val action = Button(activity)
    private val retry = Button(activity).apply { text = "Check again" }
    private var closed = false
    private var generation = 0
    private var task: Future<*>? = null
    private var release: FirmwareRelease? = null
    private var checking = false
    private var downloading = false
    private var confirmation: AlertDialog? = null
    init {
        orientation = VERTICAL
        addView(status, LayoutParams(-1, -2)); addView(action, LayoutParams(-1, -2)); addView(retry, LayoutParams(-1, -2))
        action.isEnabled = false
        retry.setOnClickListener { check(true) }
        action.setOnClickListener {
            val selected = release
            if (profile.supportsBleOta && selected != null) download(selected)
            else {
                val source = selected?.let { "${it.releaseUrl.replace("/releases/tag/", "/blob/")}/ESPHome_Gate_Firmware/centurion-d5-evo-ble-v2.yaml" }
                    ?: FirmwareUpdates.GATE_SOURCE
                runCatching { activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(source))) }
            }
        }
    }
    fun start() { check(false) }
    fun refreshInstalled() { if (!checking && !downloading && release != null) showRelease() }
    private fun showRelease() {
        val selected = release
        status.text = selected?.comparison(installed()) ?: "No compatible published firmware found."
        action.text = if (profile.supportsBleOta) "Download and update ${selected?.label ?: "firmware"}" else "View ESPHome config source"
        val current = FirmwareVersion.parse(installed()?.firmware)
        action.isEnabled = if (!profile.supportsBleOta) true else selected != null &&
            (current == null || selected.version > current) && installed()?.otaState != "pending"
        if (installed()?.otaState == "pending") status.append("\nWait for the current firmware's startup health check.")
        if (!profile.supportsBleOta) status.append("\nInstall through ESPHome. Older gate firmware does not report its revision over BLE.")
        retry.isEnabled = true
    }
    private fun check(force: Boolean) {
        if (closed) return
        val token = ++generation
        task?.cancel(true); checking = true
        status.text = "Checking GitHub firmware releases…"
        action.isEnabled = false; retry.isEnabled = false
        task = executor.submit {
            val result = runCatching { updates.check(profile.type, force) }
            handler.post {
                if (closed || generation != token || activity.isDestroyed) return@post
                checking = false
                result.onSuccess { release = it; showRelease() }.onFailure {
                    status.text = "Could not check firmware updates. Check your internet connection or try again later."
                    action.text = if (profile.supportsBleOta) "Download firmware" else "View ESPHome config source"
                    action.isEnabled = !profile.supportsBleOta; retry.isEnabled = true
                }
            }
        }
    }
    private fun download(selected: FirmwareRelease) {
        if (closed || downloading) return
        val token = ++generation
        downloading = true; action.isEnabled = false; retry.isEnabled = false
        status.text = "Downloading ${selected.label} and verifying its checksum…"
        task = executor.submit {
            val result = runCatching { updates.download(selected) }
            handler.post {
                if (closed || generation != token || activity.isDestroyed) return@post
                downloading = false
                showRelease()
                result.onSuccess { image ->
                    confirmation = AlertDialog.Builder(activity, R.style.Theme_CarKey_Dialog)
                        .setTitle("Install firmware ${selected.label}?")
                        .setMessage("Transfer ${(image.size + 1023) / 1024} KiB over Bluetooth to ${profile.displayName}. Keep the phone nearby and leave ESP power on. The checksum is verified; the ESP will verify the firmware signature. Settings and keys are preserved." +
                            if (FirmwareVersion.parse(installed()?.firmware) == null) "\n\nThe installed version could not be read. This installs the selected published release." else "")
                        .setNegativeButton("Cancel", null)
                        .setPositiveButton("Install") { _, _ ->
                            if (closed || activity.isDestroyed) return@setPositiveButton
                            val current = FirmwareVersion.parse(installed()?.firmware)
                            if (installed()?.otaState == "pending") {
                                status.text = "Wait for the current firmware's startup health check."
                            } else if (current != null && current >= selected.version) {
                                status.text = "The installed firmware is already this version or newer."
                            } else install(image)
                        }.show()
                }.onFailure { status.text = "Firmware download or verification failed. Nothing was sent to the ESP. Tap Download to retry." }
            }
        }
    }
    fun close() { closed = true; generation++; task?.cancel(true); confirmation?.dismiss() }
}
