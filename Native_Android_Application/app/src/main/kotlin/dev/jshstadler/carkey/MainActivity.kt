package dev.jshstadler.carkey

import android.Manifest
import android.app.AlertDialog
import android.app.KeyguardManager
import android.bluetooth.BluetoothManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import java.util.UUID

class MainActivity : FragmentActivity() {
    private data class DeviceRuntime(
        var psk: String = "",
        var cachedAddress: String? = null,
        var preferCached: Boolean = false,
        var recordLocation: Boolean = false,
        var state: BleCarKeyClient.State = BleCarKeyClient.State.DISCONNECTED,
        var message: String = "Idle",
        var ready: Boolean = false,
        var deviceState: String? = null,
    )

    private data class DeviceViews(
        val statusIcon: ImageView,
        val statusText: TextView,
        val actionButton: Button,
    )

    private val store by lazy { SecureStore(this) }
    private val profileRepository by lazy { DeviceProfileRepository(store) }
    private val bluetoothManager by lazy { getSystemService(BluetoothManager::class.java) }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val runtimes = mutableMapOf<String, DeviceRuntime>()
    private val deviceViews = mutableMapOf<String, DeviceViews>()
    private val clients = mutableMapOf<String, BleCarKeyClient>()
    private val clientGenerations = mutableMapOf<String, Int>()
    private val profiles = mutableListOf<BleDeviceProfile>()

    private var appForeground = false
    private var pendingPressId: String? = null
    private var pressDispatched = false
    private var pendingPskValue: String? = null
    private var pendingPskOnSaved: (() -> Unit)? = null
    private var pendingOtaImage: ByteArray? = null
    private var pendingLocationDeviceId: String? = null
    private var pendingFirmwareProfileId: String? = null
    private var firmwarePickerActive = false
    private var operationGeneration = 0
    private var operationSession = UUID.randomUUID().toString()
    private var requireAuthentication = true
    private var authenticated = false
    private var credentialCallback: ((Boolean) -> Unit)? = null
    private val credentialLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val callback = credentialCallback
        credentialCallback = null
        callback?.invoke(it.resultCode == RESULT_OK)
    }
    private lateinit var authOverlay: LinearLayout

    private val vibrator: Vibrator by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            getSystemService(VibratorManager::class.java).defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        if (result.values.all { it }) startOrConfigure()
        else toast("Bluetooth permission is required")
    }

    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        val granted = result[Manifest.permission.ACCESS_FINE_LOCATION] == true ||
            result[Manifest.permission.ACCESS_COARSE_LOCATION] == true
        val profile = pendingLocationDeviceId?.let { id -> profiles.firstOrNull { it.id == id } }
        pendingLocationDeviceId = null
        profile?.let {
            runtimes.getValue(it.id).recordLocation = granted
            store.put(it.recordLocationStoreKey, granted.toString())
        }
        toast(
            if (granted && profile != null) "Location recording enabled for ${profile.displayName}"
            else "Location recording remains disabled",
        )
    }

    private val firmwareFileLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        firmwarePickerActive = false
        val profileId = pendingFirmwareProfileId
        pendingFirmwareProfileId = null
        if (uri == null) return@registerForActivityResult
        val image = runCatching { contentResolver.openInputStream(uri)?.use { it.readBytes() } }.getOrNull()
        when {
            image == null -> toast("Could not read firmware file")
            image.isEmpty() || image.size > 0x1e0000 -> toast("Firmware must be 1 byte to 1,966,080 bytes")
            else -> {
                val profile = profileId?.let { id -> profiles.firstOrNull { it.id == id } }
                if (profile == null) {
                    toast("Device is no longer configured")
                    return@registerForActivityResult
                }
                AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
                .setTitle("Update ${profile.displayName} firmware?")
                .setMessage("Transfer ${(image.size + 1023) / 1024} KiB over BLE. Keep the phone near the car and do not remove car power. Only signed firmware from this project is accepted.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Update") { _, _ -> requestCarOta(profile, image) }
                .show()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_CarKey)
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK

        requireAuthentication = store.get("require_auth") != "false"
        profiles.addAll(profileRepository.load())
        loadDeviceSettings()
        setContentView(buildUi())
        requestPermissionsAndStart()

        if (requireAuthentication) {
            authenticate("Authenticate to access BLE Key") { ok ->
                authenticated = ok
                authOverlay.visibility = if (ok) View.GONE else View.VISIBLE
                if (ok) startForegroundClients()
            }
        } else {
            authenticated = true
            authOverlay.visibility = View.GONE
        }
    }

    override fun onDestroy() {
        BackgroundConnectionService.finish(this, false)
        operationGeneration++
        pendingPressId = null
        pendingPskValue = null
        pendingPskOnSaved = null
        stopAllClients()
        super.onDestroy()
    }

    override fun onStart() {
        super.onStart()
        BackgroundConnectionService.finish(this, true)
        appForeground = true
        startForegroundClients()
    }

    override fun onResume() {
        super.onResume()
        BackgroundConnectionService.finish(this, true)
        startForegroundClients()
    }

    override fun onPause() {
        // Start while still visible, before Android's background-start limits apply.
        if (!isFinishing && authenticated && hasPermissions() && clients.isNotEmpty()) {
            BackgroundConnectionService.begin(this, BackgroundConnectionService.Lease(
                busy = { pendingOtaImage != null },
                disconnect = {
                    EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Background connection window ended")
                    stopAllClients()
                },
            ))
        }
        super.onPause()
    }

    override fun onStop() {
        appForeground = false
        if (isFinishing) {
            BackgroundConnectionService.finish(this, false)
            stopAllClients()
        }
        super.onStop()
    }

    private fun loadDeviceSettings() {
        val legacyPsk = store.get("psk") ?: ""
        val legacyAddress = store.get("cached_address")
        val legacyPreferCached = store.get("prefer_cached") == "true"
        val legacyRecordLocation = store.get("record_location") == "true"

        profiles.forEach { profile ->
            val runtime = DeviceRuntime(
                psk = store.get(profile.pskStoreKey) ?: legacyPsk,
                cachedAddress = store.get(profile.addressStoreKey)
                    ?: if (profile.id == "car") legacyAddress else profile.defaultAddress,
                preferCached = store.get(profile.preferCachedStoreKey)?.toBooleanStrictOrNull()
                    ?: if (profile.id == "car") legacyPreferCached else profile.defaultAddress != null,
                recordLocation = store.get(profile.recordLocationStoreKey)?.toBooleanStrictOrNull()
                    ?: (profile.id == "car" && legacyRecordLocation),
            )
            if (runtime.psk.isEmpty()) runtime.message = "PSK required"
            runtimes[profile.id] = runtime
            if (runtime.psk.isNotEmpty()) store.put(profile.pskStoreKey, runtime.psk)
            runtime.cachedAddress?.let { store.put(profile.addressStoreKey, it) }
            store.put(profile.preferCachedStoreKey, runtime.preferCached.toString())
            store.put(profile.recordLocationStoreKey, runtime.recordLocation.toString())
        }
    }

    private fun buildUi(): View {
        deviceViews.clear()
        val background = Color.BLACK
        val surface = Color.rgb(31, 34, 48)
        val root = FrameLayout(this).apply { setBackgroundColor(background) }
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(0, bars.top, 0, bars.bottom)
            insets
        }

        val scroll = ScrollView(this).apply { isFillViewport = true }
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), 0, dp(20), dp(24))
        }
        scroll.addView(page, FrameLayout.LayoutParams(-1, -2))
        root.addView(scroll, FrameLayout.LayoutParams(-1, -1))

        val bar = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        bar.addView(text("BLE Key", 23f, true), LinearLayout.LayoutParams(0, dp(64), 1f))
        bar.addView(
            iconButton(R.drawable.ic_logs, "Logs") { startActivity(Intent(this, LogActivity::class.java)) },
            LinearLayout.LayoutParams(dp(48), dp(48)),
        )
        bar.addView(
            iconButton(R.drawable.ic_settings, "App settings") { showAppSettings() },
            LinearLayout.LayoutParams(dp(48), dp(48)),
        )
        page.addView(bar, LinearLayout.LayoutParams(-1, dp(72)))

        page.addView(sectionLabel("Devices").apply { setPadding(0, dp(8), 0, dp(8)) })
        profiles.forEach { profile ->
            page.addView(buildDeviceCard(profile, surface), LinearLayout.LayoutParams(-1, dp(108)).apply {
                bottomMargin = dp(12)
            })
        }
        if (profiles.isEmpty()) {
            page.addView(text("No devices configured. Open Settings to add one.", 14f, false).apply {
                setTextColor(Color.rgb(184, 186, 198))
                gravity = Gravity.CENTER
                setPadding(dp(12), dp(24), dp(12), dp(32))
            })
        }

        page.addView(text("Nearby devices stay connected while app is open", 13f, false).apply {
            setTextColor(Color.rgb(153, 156, 171))
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), 0)
        })

        authOverlay = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(32), dp(32), dp(32), dp(32))
            setBackgroundColor(background)
            addView(ImageView(context).apply { setImageResource(R.drawable.ic_lock) }, LinearLayout.LayoutParams(dp(64), dp(64)))
            addView(text("Authentication required", 19f, true).apply {
                gravity = Gravity.CENTER
                setPadding(0, dp(20), 0, dp(16))
            })
            addView(primaryButton("Authenticate") {
                authenticate("Authenticate to access BLE Key") { ok ->
                    authenticated = ok
                    if (ok) {
                        authOverlay.visibility = View.GONE
                        startForegroundClients()
                    }
                }
            }, LinearLayout.LayoutParams(dp(180), dp(52)))
        }
        root.addView(authOverlay, FrameLayout.LayoutParams(-1, -1))
        updateAllDeviceViews()
        return root
    }

    private fun buildDeviceCard(profile: BleDeviceProfile, surface: Int): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(12), dp(12), dp(12))
            background = rounded(surface, 18f)
            elevation = dp(2).toFloat()
        }
        val statusIcon = ImageButton(this).apply {
            setImageResource(if (profile.type == BleDeviceType.ESPHOME_ACCESS) R.drawable.ic_gate else R.drawable.ic_car)
            contentDescription = "${profile.displayName} settings"
            imageTintList = ColorStateList.valueOf(Color.rgb(132, 136, 153))
            setPadding(dp(7), dp(7), dp(7), dp(7))
            background = selectableBorderlessBackground()
            setOnClickListener { showDeviceSettingsAuthenticated(profile) }
        }
        card.addView(statusIcon, LinearLayout.LayoutParams(dp(48), dp(48)))

        val labels = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(8), 0)
        }
        labels.addView(text(profile.displayName, 17f, true))
        val status = text("Idle", 13f, false).apply {
            setTextColor(Color.rgb(184, 186, 198))
            maxLines = 2
        }
        labels.addView(status)
        card.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))

        val shortAction = profile.actionLabel.substringBefore(' ')
        val action = primaryButton(shortAction) { requestPress(profile) }
        card.addView(action, LinearLayout.LayoutParams(dp(100), dp(52)))
        deviceViews[profile.id] = DeviceViews(statusIcon, status, action)
        return card
    }

    private fun requestPermissionsAndStart() {
        if (hasPermissions()) startOrConfigure() else permissionLauncher.launch(requiredPermissions())
    }

    private fun startOrConfigure() {
        startForegroundClients()
    }

    private fun requestPress(profile: BleDeviceProfile) {
        if (!authenticated) {
            authOverlay.visibility = View.VISIBLE
            return
        }
        if (!hasPermissions()) {
            permissionLauncher.launch(requiredPermissions())
            return
        }
        val runtime = runtimes.getValue(profile.id)
        if (runtime.psk.isEmpty()) {
            showDevicePskDialog(profile) { requestPress(profile) }
            return
        }
        if (pendingPressId != null) {
            toast("Another BLE action is already running")
            return
        }

        operationGeneration++
        val generation = operationGeneration
        operationSession = UUID.randomUUID().toString()
        pendingPressId = profile.id
        pendingPskValue = null
        pendingPskOnSaved = null
        pendingOtaImage = null
        pressDispatched = false
        setAllActionsEnabled(false)

        if (runtime.ready) {
            pressDispatched = true
            runtime.message = "Sending command..."
            updateDeviceView(profile.id)
            clients[profile.id]?.press()
        } else {
            runtime.state = BleCarKeyClient.State.CONNECTING
            runtime.message = "Connecting..."
            updateDeviceView(profile.id)
            ensureClient(profile)
        }

        mainHandler.postDelayed({
            if (generation == operationGeneration && pendingPressId == profile.id) {
                finishOperation(profile, false, "Timed out")
            }
        }, 18_000)
    }

    private fun listenerFor(profile: BleDeviceProfile, generation: Int) = object : BleCarKeyClient.Listener {
        private fun current() = clientGenerations[profile.id] == generation && clients.containsKey(profile.id)
        override fun onState(state: BleCarKeyClient.State, message: String) = runOnUiThread {
            if (!current()) return@runOnUiThread
            EventLog.add(this@MainActivity, EventLog.Kind.DIAGNOSTIC, "${profile.displayName} ${state.name}: $message", deviceId = profile.id, deviceName = profile.displayName)
            val runtime = runtimes.getValue(profile.id)
            runtime.state = state
            runtime.message = when {
                state == BleCarKeyClient.State.DISCONNECTED && message == "Disconnected" -> "Idle"
                else -> message
            }
            if (state != BleCarKeyClient.State.CONNECTED) runtime.ready = false
            updateDeviceView(profile.id)
            if (message.contains("scan fallback")) {
                mainHandler.post { clients[profile.id]?.scanFallback() }
            }
        }

        override fun onDiagnostic(message: String) {
            if (!current()) return
            EventLog.add(this@MainActivity, EventLog.Kind.DIAGNOSTIC, "${profile.displayName}: $message", deviceId = profile.id, deviceName = profile.displayName)
        }

        override fun onReadyChanged(ready: Boolean) = runOnUiThread {
            if (!current()) return@runOnUiThread
            val runtime = runtimes.getValue(profile.id)
            runtime.ready = ready
            if (ready) runtime.message = "Ready"
            updateDeviceView(profile.id)
            if (ready && pendingPressId == profile.id && !pressDispatched) {
                pressDispatched = true
                runtime.message = when {
                    pendingOtaImage != null -> "Preparing firmware update..."
                    pendingPskValue != null -> "Updating ESP PSK..."
                    else -> "Sending command..."
                }
                updateDeviceView(profile.id)
                when {
                    pendingOtaImage != null -> clients[profile.id]?.startOta(pendingOtaImage!!)
                    pendingPskValue != null -> {
                        if (clients[profile.id]?.updatePsk(pendingPskValue!!) != true) {
                            finishPskUpdate(profile, false, "ESP firmware does not support PSK updates")
                        }
                    }
                    else -> clients[profile.id]?.press()
                }
            }
        }

        override fun onDeviceAddress(address: String) {
            if (!current()) return
            val runtime = runtimes.getValue(profile.id)
            runtime.cachedAddress = address
            store.put(profile.addressStoreKey, address)
        }

        override fun onDeviceState(state: String) = runOnUiThread {
            if (!current()) return@runOnUiThread
            val normalized = state.trim().lowercase().replaceFirstChar { it.uppercase() }
            runtimes.getValue(profile.id).deviceState = normalized
            updateDeviceView(profile.id)
        }

        override fun onCommandResult(success: Boolean, message: String) = runOnUiThread {
            if (!current()) return@runOnUiThread
            finishOperation(profile, success, message)
        }

        override fun onPskUpdateResult(success: Boolean, message: String) = runOnUiThread {
            if (!current()) return@runOnUiThread
            finishPskUpdate(profile, success, message)
        }

        override fun onOtaProgress(sent: Int, total: Int) = runOnUiThread {
            if (!current()) return@runOnUiThread
            val percent = if (total == 0) 0 else sent * 100 / total
            runtimes.getValue(profile.id).message = "Updating firmware: $percent%"
            updateDeviceView(profile.id)
        }

        override fun onOtaResult(success: Boolean, message: String) = runOnUiThread {
            if (!current()) return@runOnUiThread
            finishOtaOperation(profile, success, message)
        }
    }

    private fun finishOperation(profile: BleDeviceProfile, success: Boolean, message: String) {
        if (pendingPressId != profile.id) return
        pendingPressId = null
        pressDispatched = false
        operationGeneration++
        val runtime = runtimes.getValue(profile.id)
        runtime.message = if (success && message == "Pressed") "Command completed" else message
        updateDeviceView(profile.id)
        setAllActionsEnabled(true)

        EventLog.add(
            this,
            EventLog.Kind.DIAGNOSTIC,
            if (success) "${profile.displayName} command completed" else "${profile.displayName} command failed: $message",
            deviceId = profile.id,
            deviceName = profile.displayName,
        )
        if (success && message == "Pressed") {
            EventLog.addSessionPress(this, "${profile.displayName} remote button pressed", operationSession, profile.id, profile.displayName)
            captureOperationLocation(profile)
            vibrateSuccess()
        } else if (!success) {
            vibrateFailure()
        }

        mainHandler.postDelayed({
            if (pendingPressId == null && runtime.ready) {
                runtime.message = "Ready"
                updateDeviceView(profile.id)
            }
        }, 1_500)
    }

    private fun requestCarPskUpdate(profile: BleDeviceProfile, newPsk: String, onSaved: () -> Unit) {
        if (!hasPermissions()) {
            toast("Bluetooth permission is required")
            return
        }
        if (pendingPressId != null) {
            toast("Another BLE action is already running")
            return
        }

        val runtime = runtimes.getValue(profile.id)
        operationGeneration++
        val generation = operationGeneration
        pendingPressId = profile.id
        pendingPskValue = newPsk
        pendingPskOnSaved = onSaved
        pendingOtaImage = null
        pressDispatched = false
        setAllActionsEnabled(false)
        runtime.message = if (runtime.ready) "Updating device PSK..." else "Connecting to update device PSK..."
        updateDeviceView(profile.id)

        if (runtime.ready) {
            pressDispatched = true
            if (clients[profile.id]?.updatePsk(newPsk) != true) {
                finishPskUpdate(profile, false, "This firmware does not support PSK updates")
                return
            }
        } else {
            ensureClient(profile)
        }

        mainHandler.postDelayed({
            if (generation == operationGeneration && pendingPskValue != null) {
                finishPskUpdate(profile, false, "PSK update timed out")
            }
        }, 18_000)
    }

    private fun finishPskUpdate(profile: BleDeviceProfile, success: Boolean, message: String) {
        val newPsk = pendingPskValue ?: return
        if (pendingPressId != profile.id) return
        val onSaved = pendingPskOnSaved
        pendingPskValue = null
        pendingPskOnSaved = null
        pendingPressId = null
        pressDispatched = false
        operationGeneration++

        if (success) savePsk(profile, newPsk, restartClient = false)
        val runtime = runtimes.getValue(profile.id)
        runtime.message = message
        updateDeviceView(profile.id)
        setAllActionsEnabled(true)
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, message, deviceId = profile.id, deviceName = profile.displayName)
        if (success) {
            vibrateSuccess()
            toast("${profile.displayName} and phone PSK updated")
            onSaved?.invoke()
        } else {
            vibrateFailure()
            toast(message)
        }
    }

    private fun requestCarOta(profile: BleDeviceProfile, image: ByteArray) {
        if (!hasPermissions()) {
            toast("Bluetooth permission is required")
            return
        }
        val runtime = runtimes.getValue(profile.id)
        if (runtime.psk.isEmpty()) {
            showDevicePskDialog(profile) { requestCarOta(profile, image) }
            return
        }
        if (pendingPressId != null) {
            toast("Another BLE action is already running")
            return
        }

        operationGeneration++
        val generation = operationGeneration
        pendingPressId = profile.id
        pendingPskValue = null
        pendingPskOnSaved = null
        pendingOtaImage = image
        pressDispatched = false
        setAllActionsEnabled(false)
        runtime.state = BleCarKeyClient.State.CONNECTING
        runtime.message = "Connecting for firmware update..."
        updateDeviceView(profile.id)
        val client = clients[profile.id]
        if (runtime.ready && client != null) {
            pressDispatched = true
            runtime.message = "Preparing firmware update..."
            updateDeviceView(profile.id)
            EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "${profile.displayName}: OTA dispatched on ready connection", deviceId = profile.id, deviceName = profile.displayName)
            client.startOta(image)
        } else if (client?.requestFreshChallenge() == true) {
            runtime.message = "Preparing secure firmware connection..."
            updateDeviceView(profile.id)
        } else {
            if (client != null) stopClient(profile.id)
            ensureClient(profile)
        }

        mainHandler.postDelayed({
            if (generation == operationGeneration && pendingOtaImage != null && !pressDispatched) {
                finishOtaOperation(profile, false, "Could not prepare the BLE firmware connection")
            }
        }, 20_000L)

        mainHandler.postDelayed({
            if (generation == operationGeneration && pendingOtaImage != null) {
                finishOtaOperation(profile, false, "Firmware update timed out")
            }
            // Per-chunk and validation watchdogs detect a genuinely stalled link.
            // Keep this only as a generous whole-operation failsafe so an active,
            // low-throughput transfer is never aborted at an arbitrary percentage.
        }, 30 * 60 * 1000L)
    }

    private fun finishOtaOperation(profile: BleDeviceProfile, success: Boolean, message: String) {
        if (pendingPressId != profile.id || pendingOtaImage == null) return
        pendingOtaImage = null
        pendingPressId = null
        pressDispatched = false
        operationGeneration++
        val runtime = runtimes.getValue(profile.id)
        runtime.message = message
        updateDeviceView(profile.id)
        setAllActionsEnabled(true)
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "ESP firmware update ${if (success) "completed" else "failed"}: $message", deviceId = profile.id, deviceName = profile.displayName)
        if (success) vibrateSuccess() else vibrateFailure()
        mainHandler.postDelayed({
            stopClient(profile.id)
            if (appForeground) mainHandler.postDelayed({ ensureClient(profile) }, 2_000L)
        }, if (success) 300L else 1_500L)
    }

    private fun startForegroundClients() {
        if (!appForeground || !authenticated || !hasPermissions()) return
        profiles.forEach { profile ->
            if (runtimes.getValue(profile.id).psk.isNotEmpty()) ensureClient(profile)
        }
    }

    private fun ensureClient(profile: BleDeviceProfile) {
        if (!appForeground || !authenticated || !hasPermissions() || clients.containsKey(profile.id)) return
        val runtime = runtimes.getValue(profile.id)
        if (runtime.psk.isEmpty()) return
        runtime.state = BleCarKeyClient.State.CONNECTING
        runtime.message = "Connecting..."
        updateDeviceView(profile.id)
        val generation = (clientGenerations[profile.id] ?: 0) + 1
        clientGenerations[profile.id] = generation
        val client = BleCarKeyClient(this, bluetoothManager, profile, listenerFor(profile, generation))
        clients[profile.id] = client
        client.start(runtime.psk, runtime.cachedAddress ?: profile.defaultAddress, runtime.preferCached)
    }

    private fun stopClient(deviceId: String) {
        clientGenerations[deviceId] = (clientGenerations[deviceId] ?: 0) + 1
        clients.remove(deviceId)?.stop(true)
        runtimes[deviceId]?.apply {
            ready = false
            state = BleCarKeyClient.State.DISCONNECTED
            message = "Idle"
        }
        updateDeviceView(deviceId)
    }

    private fun stopAllClients() {
        clients.keys.toList().forEach(::stopClient)
    }

    private fun updateAllDeviceViews() = profiles.forEach { updateDeviceView(it.id) }

    private fun updateDeviceView(deviceId: String) {
        val runtime = runtimes[deviceId] ?: return
        val views = deviceViews[deviceId] ?: return
        views.statusText.text = when {
            runtime.ready && runtime.deviceState != null -> "${runtime.deviceState} • Connected"
            runtime.deviceState != null -> "${runtime.message}\nLast state: ${runtime.deviceState}"
            else -> runtime.message
        }
        views.statusIcon.imageTintList = ColorStateList.valueOf(
            when {
                runtime.ready -> Color.rgb(38, 196, 104)
                runtime.state == BleCarKeyClient.State.SCANNING || runtime.state == BleCarKeyClient.State.CONNECTING -> Color.rgb(255, 170, 30)
                runtime.message == "Command completed" -> Color.rgb(38, 196, 104)
                runtime.message.contains("failed", true) || runtime.message.contains("timed out", true) -> Color.rgb(219, 68, 75)
                else -> Color.rgb(132, 136, 153)
            },
        )
        val busy = pendingPressId != null
        views.actionButton.isEnabled = !busy
        views.actionButton.alpha = if (busy) 0.5f else 1f
    }

    private fun setAllActionsEnabled(enabled: Boolean) {
        deviceViews.values.forEach { views ->
            views.actionButton.isEnabled = enabled
            views.actionButton.alpha = if (enabled) 1f else 0.5f
        }
    }

    private fun showDeviceSettingsAuthenticated(profile: BleDeviceProfile) {
        if (pendingPressId != null) {
            toast(if (pendingOtaImage != null) "Finish the firmware update before changing settings" else "Finish the current BLE action first")
            return
        }
        authenticate("Authenticate to edit ${profile.displayName} settings") { ok ->
            if (ok) showDeviceSettings(profile)
        }
    }

    private fun showDevicePskDialog(profile: BleDeviceProfile, onSaved: () -> Unit = {}) {
        authenticate("Authenticate to edit ${profile.displayName} PSK") { ok ->
            if (ok) showPskEditor(
                profile,
                recovery = profile.supportsRemotePskUpdate && runtimes.getValue(profile.id).psk.isNotEmpty(),
                onSaved,
            )
        }
    }

    private fun showDeviceSettings(profile: BleDeviceProfile, onSaved: () -> Unit = {}) {
        val runtime = runtimes.getValue(profile.id)
        lateinit var settingsDialog: AlertDialog
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(12))
        }
        val name = EditText(this).apply {
            hint = "Device name"
            setText(profile.displayName)
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        }
        val configuredAddress = EditText(this).apply {
            hint = "BLE address (optional)"
            setText(profile.defaultAddress ?: runtime.cachedAddress.orEmpty())
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
        }
        val cachedSwitch = Switch(this).apply {
            text = "Use cached device address"
            setTextColor(Color.WHITE)
            isChecked = runtime.preferCached
            isEnabled = runtime.cachedAddress != null || profile.defaultAddress != null
            setPadding(0, dp(6), 0, dp(6))
        }
        val locationSwitch = Switch(this).apply {
            text = "Record location when this device is triggered"
            setTextColor(Color.WHITE)
            isChecked = runtime.recordLocation
            setPadding(0, dp(6), 0, dp(6))
        }
        val address = text("Address: ${runtime.cachedAddress ?: profile.defaultAddress ?: "Not learned yet"}", 12f, false).apply {
            setTextColor(Color.rgb(184, 186, 198))
            setPadding(0, dp(2), 0, dp(8))
        }
        layout.addView(sectionLabel("Device"))
        layout.addView(name, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) })
        layout.addView(configuredAddress, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
        layout.addView(sectionLabel("Security"))
        val pskActionLabel = when {
            runtime.psk.isEmpty() -> "Set PSK on app"
            profile.supportsRemotePskUpdate -> "Change PSK on ESP and app"
            else -> "Change PSK saved on app"
        }
        layout.addView(primaryButton(pskActionLabel) {
            showPskEditor(profile, recovery = false, onSaved)
        }, LinearLayout.LayoutParams(-1, dp(48)).apply { bottomMargin = dp(8) })
        if (runtime.psk.isNotEmpty() && profile.supportsRemotePskUpdate) {
            layout.addView(primaryButton("Change PSK saved on app") {
                authenticate("Authenticate for PSK recovery") { ok ->
                    if (ok) showPskEditor(profile, recovery = true, onSaved)
                }
            }, LinearLayout.LayoutParams(-1, dp(48)).apply { bottomMargin = dp(8) })
            layout.addView(text(
                "The ESP-and-app change requires the existing PSK. The app-only option replaces this phone's saved copy and does not change the ESP.",
                12f,
                false,
            ).apply { setTextColor(Color.rgb(184, 186, 198)) }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
        } else if (!profile.supportsRemotePskUpdate) {
            layout.addView(text(
                "PSK changes here affect only this app. Update the matching ESPHome secret and firmware separately.",
                12f,
                false,
            ).apply { setTextColor(Color.rgb(184, 186, 198)) }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
        }
        layout.addView(sectionLabel("Connection"), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        layout.addView(cachedSwitch, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(4) })
        layout.addView(address, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        layout.addView(sectionLabel("History"), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(4) })
        layout.addView(locationSwitch, LinearLayout.LayoutParams(-1, -2))
        layout.addView(text(
            "When enabled, successful ${profile.displayName.lowercase()} presses add a location pin to the operation log.",
            12f,
            false,
        ).apply {
            setTextColor(Color.rgb(184, 186, 198))
        }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        if (profile.supportsBleOta) {
            layout.addView(sectionLabel("Firmware"), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(4) })
            layout.addView(primaryButton("Update ESP firmware (.bin)") {
                pendingFirmwareProfileId = profile.id
                firmwarePickerActive = true
                // Saving device settings rebuilds the UI and BLE clients. Close
                // this dialog before OTA so its Save action cannot interrupt
                // firmware preparation or an active transfer.
                settingsDialog.dismiss()
                firmwareFileLauncher.launch(arrayOf("application/octet-stream", "*/*"))
            }, LinearLayout.LayoutParams(-1, dp(48)).apply { topMargin = dp(4) })
        }
        layout.addView(primaryButton("Remove device") {
            AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
                .setTitle("Remove ${profile.displayName}?")
                .setMessage("This removes its card, saved PSK, address, and per-device settings from this phone. It does not change the ESP.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Remove") { _, _ -> removeDevice(profile) }
                .show()
        }, LinearLayout.LayoutParams(-1, dp(48)).apply { topMargin = dp(20) })
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(layout, FrameLayout.LayoutParams(-1, -2))
        }

        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("${profile.displayName} Settings")
            .setView(scroll)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create().also { dialog ->
                settingsDialog = dialog
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val newName = name.text.toString().trim()
                        val newAddress = configuredAddress.text.toString().trim().uppercase().ifEmpty { null }
                        when {
                            newName.isEmpty() -> name.error = "Name is required"
                            newAddress == null && profiles.any { it.id != profile.id && it.type == profile.type } -> configuredAddress.error = "Address is required while another device uses this firmware type"
                            newAddress != null && !newAddress.matches(Regex("[0-9A-F]{2}(:[0-9A-F]{2}){5}")) -> configuredAddress.error = "Use AA:BB:CC:DD:EE:FF"
                            newAddress != null && profiles.any { it.id != profile.id && it.defaultAddress == newAddress } -> configuredAddress.error = "That address is already configured"
                            else -> {
                                runtime.preferCached = cachedSwitch.isChecked
                                store.put(profile.preferCachedStoreKey, runtime.preferCached.toString())
                                val requestLocationPermission = locationSwitch.isChecked && !hasLocationPermission()
                                runtime.recordLocation = locationSwitch.isChecked && !requestLocationPermission
                                store.put(profile.recordLocationStoreKey, runtime.recordLocation.toString())
                                if (requestLocationPermission) pendingLocationDeviceId = profile.id
                                dialog.dismiss()
                                updateProfile(profile, newName, newAddress)
                                if (requestLocationPermission) {
                                    locationPermissionLauncher.launch(
                                        arrayOf(
                                            Manifest.permission.ACCESS_FINE_LOCATION,
                                            Manifest.permission.ACCESS_COARSE_LOCATION,
                                        ),
                                    )
                                }
                                onSaved()
                            }
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun showPskEditor(profile: BleDeviceProfile, recovery: Boolean, onSaved: () -> Unit = {}) {
        val runtime = runtimes.getValue(profile.id)
        val appOnly = !profile.supportsRemotePskUpdate
        val initialSetup = runtime.psk.isEmpty()
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(12))
        }
        val current = if (!appOnly && !recovery && runtime.psk.isNotEmpty()) pskInput("Existing PSK") else null
        val next = pskInput(if (initialSetup) "PSK" else "New PSK")
        val confirm = if (initialSetup) null else pskInput("Confirm new PSK")
        layout.addView(text(when {
            appOnly -> "This changes only the encrypted PSK saved on this app. It does not update the ESPHome device or its secrets."
            recovery -> "This replaces only the encrypted PSK saved on this app. Use it when the ESP was changed elsewhere or the old PSK is unavailable."
            runtime.psk.isEmpty() -> "Enter the PSK already installed on this device."
            profile.supportsRemotePskUpdate -> "The existing PSK is verified locally, then the authenticated car and this phone are updated together."
            else -> "First update ESPHome, then enter the existing and new PSKs here to update this phone's matching copy."
        }, 13f, false).apply { setTextColor(Color.rgb(184, 186, 198)) }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
        current?.let { layout.addView(it, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) }) }
        layout.addView(next, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        confirm?.let { layout.addView(it, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) }) }
        layout.addView(primaryButton("Generate secure 32-character PSK") {
            val generated = DevicePskGenerator.generate()
            next.setText(generated)
            confirm?.setText(generated)
            showGeneratedPsk(generated)
        }, LinearLayout.LayoutParams(-1, dp(48)))

        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle(when {
                appOnly -> "PSK saved on app"
                recovery -> "PSK saved on app"
                else -> "${profile.displayName} PSK"
            })
            .setView(layout)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val value = next.text.toString().trim()
                        when {
                            current != null && current.text.toString().trim() != runtime.psk -> current.error = "Existing PSK is incorrect"
                            !PskUpdateProtocol.validKey(value) -> next.error = "Use 1–128 UTF-8 bytes without NUL characters"
                            confirm != null && value != confirm.text.toString().trim() -> confirm.error = "PSKs do not match"
                            else -> {
                                dialog.dismiss()
                                if (!recovery && runtime.psk.isNotEmpty() && profile.supportsRemotePskUpdate) {
                                    requestCarPskUpdate(profile, value, onSaved)
                                } else {
                                    savePsk(profile, value)
                                    toast("Saved PSK updated on this phone")
                                    onSaved()
                                }
                            }
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun showAddDevice() {
        authenticate("Authenticate to add a BLE device") { ok ->
            if (!ok) return@authenticate
            val labels = arrayOf("ESPHome device", "Standalone device")
            AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
                .setTitle("Add device")
                .setItems(labels) { _, which ->
                    showAddDeviceDetails(if (which == 0) BleDeviceType.ESPHOME_ACCESS else BleDeviceType.CAR)
                }
                .show()
        }
    }

    private fun showAddDeviceDetails(type: BleDeviceType) {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(12))
        }
        val name = EditText(this).apply {
            hint = "Name"
            setText(if (type == BleDeviceType.CAR) "Car" else "Access Device")
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        }
        val address = EditText(this).apply {
            hint = "BLE address (optional)"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
        }
        layout.addView(text(
            "The name is your own label and does not need to match the ESP's Bluetooth name. The BLE address uniquely identifies the physical ESP. It is optional for the first device of this type, but required when two devices use the same firmware profile.",
            13f,
            false,
        ).apply { setTextColor(Color.rgb(184, 186, 198)) }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
        layout.addView(name, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        layout.addView(address)

        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle(if (type == BleDeviceType.CAR) "Add standalone device" else "Add ESPHome device")
            .setView(layout)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Add", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val deviceName = name.text.toString().trim()
                        val targetAddress = address.text.toString().trim().uppercase().ifEmpty { null }
                        when {
                            deviceName.isEmpty() -> name.error = "Name is required"
                            targetAddress == null && profiles.any { it.type == type } -> address.error = "Address is required for another device of this type"
                            profiles.filter { it.type == type }.any {
                                it.defaultAddress == null && runtimes[it.id]?.cachedAddress == null
                            } -> address.error = "Connect the existing device once so its address can be learned"
                            targetAddress != null && !targetAddress.matches(Regex("[0-9A-F]{2}(:[0-9A-F]{2}){5}")) -> address.error = "Use AA:BB:CC:DD:EE:FF"
                            profiles.any { it.defaultAddress != null && it.defaultAddress == targetAddress } -> address.error = "That address is already configured"
                            else -> {
                                // Once two cards share one firmware/service UUID,
                                // pin every card of that type to a learned address.
                                profiles.filter { it.type == type }.forEach { existing ->
                                    val learned = existing.defaultAddress ?: runtimes[existing.id]?.cachedAddress
                                    if (learned != null) {
                                        val existingIndex = profiles.indexOfFirst { it.id == existing.id }
                                        profiles[existingIndex] = existing.copy(defaultAddress = learned)
                                        runtimes.getValue(existing.id).preferCached = true
                                        store.put(existing.preferCachedStoreKey, "true")
                                    }
                                }
                                val profile = BleDeviceProfiles.create(type, displayName = deviceName, targetAddress = targetAddress)
                                profiles.add(profile)
                                runtimes[profile.id] = DeviceRuntime(
                                    cachedAddress = targetAddress,
                                    preferCached = targetAddress != null,
                                    message = "PSK required",
                                )
                                profileRepository.save(profiles)
                                dialog.dismiss()
                                rebuildUi()
                                showPskEditor(profile, recovery = false)
                            }
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun updateProfile(profile: BleDeviceProfile, name: String, address: String?) {
        val index = profiles.indexOfFirst { it.id == profile.id }
        if (index < 0) return
        val updated = profile.copy(displayName = name, defaultAddress = address)
        profiles[index] = updated
        runtimes.getValue(profile.id).apply {
            if (address != null) {
                cachedAddress = address
                store.put(profile.addressStoreKey, address)
            } else if (!preferCached) {
                cachedAddress = null
                store.remove(profile.addressStoreKey)
            }
        }
        profileRepository.save(profiles)
        rebuildUi()
    }

    private fun removeDevice(profile: BleDeviceProfile) {
        stopClient(profile.id)
        profiles.removeAll { it.id == profile.id }
        runtimes.remove(profile.id)
        listOf(
            profile.pskStoreKey,
            profile.addressStoreKey,
            profile.preferCachedStoreKey,
            profile.recordLocationStoreKey,
        ).forEach(store::remove)
        profileRepository.save(profiles)
        rebuildUi()
    }

    private fun rebuildUi() {
        stopAllClients()
        setContentView(buildUi())
        authOverlay.visibility = if (authenticated) View.GONE else View.VISIBLE
        if (authenticated) startForegroundClients()
    }

    private fun showAppSettings() {
        if (pendingPressId != null) {
            toast(if (pendingOtaImage != null) "Finish the firmware update before changing settings" else "Finish the current BLE action first")
            return
        }
        val options = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), 0)
        }
        val authSwitch = Switch(this).apply {
            text = "Require device authentication"
            setTextColor(Color.WHITE)
            isChecked = requireAuthentication
            setPadding(0, dp(8), 0, dp(8))
        }
        lateinit var settingsDialog: AlertDialog
        val persistSettings = {
            requireAuthentication = authSwitch.isChecked
            store.put("require_auth", requireAuthentication.toString())
        }
        options.addView(authSwitch)
        options.addView(sectionLabel("Devices"), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
        options.addView(primaryButton("Add device") {
            persistSettings()
            settingsDialog.dismiss()
            showAddDevice()
        }, LinearLayout.LayoutParams(-1, dp(48)))
        settingsDialog = AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("BLE Key Settings")
            .setView(options)
            .setPositiveButton("Done") { _, _ ->
                persistSettings()
            }
            .create()
        settingsDialog.show()
    }

    private fun showGeneratedPsk(generated: String) {
        val value = text(generated, 17f, true).apply {
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(dp(16), dp(18), dp(16), dp(18))
        }
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Save this PSK now")
            .setMessage("This is the only time BLE Key will display or offer to copy this generated PSK. It remains masked after this dialog closes. Return to the PSK dialog and tap Save to apply it.")
            .setView(value)
            .setNegativeButton("Done", null)
            .setPositiveButton("Copy PSK") { _, _ ->
                val clip = ClipData.newPlainText("BLE Key PSK", generated)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    clip.description.extras = PersistableBundle().apply {
                        putBoolean("android.content.extra.IS_SENSITIVE", true)
                    }
                }
                getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
                Toast.makeText(this, "PSK copied. Store it securely, then save the PSK dialog.", Toast.LENGTH_LONG).show()
            }
            .show()
    }

    private fun savePsk(profile: BleDeviceProfile, value: String, restartClient: Boolean = true) {
        if (runtimes.getValue(profile.id).psk == value) return
        runtimes.getValue(profile.id).psk = value
        store.put(profile.pskStoreKey, value)
        if (restartClient) {
            stopClient(profile.id)
            if (appForeground && authenticated) mainHandler.post { ensureClient(profile) }
        }
    }

    private fun authenticate(reason: String, result: (Boolean) -> Unit) {
        val allowed = if (Build.VERSION.SDK_INT >= 30) BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL else BiometricManager.Authenticators.BIOMETRIC_STRONG
        val keyguard = getSystemService(KeyguardManager::class.java)
        val route = AppPolicies.authenticationRoute(Build.VERSION.SDK_INT,
            BiometricManager.from(this).canAuthenticate(allowed) == BiometricManager.BIOMETRIC_SUCCESS, keyguard.isDeviceSecure)
        if (route == AppPolicies.AuthenticationRoute.CREDENTIAL) return authenticateCredential(reason, result)
        if (route == AppPolicies.AuthenticationRoute.UNAVAILABLE) {
            toast("Set a device PIN, password, or biometric before using protected actions")
            return result(false)
        }
        BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) = result(true)
                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (code == BiometricPrompt.ERROR_NEGATIVE_BUTTON && Build.VERSION.SDK_INT < 30 && keyguard.isDeviceSecure)
                        authenticateCredential(reason, result)
                    else result(false)
                }
            },
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("BLE Key")
                .setSubtitle(reason)
                .setAllowedAuthenticators(allowed)
                .apply { if (Build.VERSION.SDK_INT < 30) setNegativeButtonText(if (keyguard.isDeviceSecure) "Use device PIN" else "Cancel") }
                .build(),
        )
    }

    @Suppress("DEPRECATION")
    private fun authenticateCredential(reason: String, result: (Boolean) -> Unit) {
        val keyguard = getSystemService(KeyguardManager::class.java)
        val intent = if (keyguard.isDeviceSecure) keyguard.createConfirmDeviceCredentialIntent("BLE Key", reason) else null
        if (intent == null || credentialCallback != null) return result(false)
        credentialCallback = result
        try { credentialLauncher.launch(intent) }
        catch (_: Exception) { credentialCallback = null; result(false) }
    }

    private fun requiredPermissions(): Array<String> = if (Build.VERSION.SDK_INT >= 31) {
        arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    private fun hasPermissions() = requiredPermissions().all {
        ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
    }

    private fun hasLocationPermission() =
        ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

    @android.annotation.SuppressLint("MissingPermission")
    private fun captureOperationLocation(profile: BleDeviceProfile) {
        if (!runtimes.getValue(profile.id).recordLocation || !hasLocationPermission()) return
        val operationTime = System.currentTimeMillis()
        val manager = getSystemService(LocationManager::class.java)
        val provider = when {
            manager.isProviderEnabled(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
            manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER) -> LocationManager.NETWORK_PROVIDER
            else -> {
                EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Location not recorded: location services are disabled", deviceId = profile.id, deviceName = profile.displayName)
                return
            }
        }
        val save: (Location) -> Unit = { location ->
            EventLog.addLocation(this, location.latitude, location.longitude, location.accuracy, operationSession, operationTime, profile.id, profile.displayName)
            EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Saved operation location with +/-${location.accuracy.toInt()} m accuracy", deviceId = profile.id, deviceName = profile.displayName)
        }
        if (Build.VERSION.SDK_INT >= 30) {
            manager.getCurrentLocation(provider, CancellationSignal(), mainExecutor, save)
        } else {
            val listener = object : LocationListener {
                override fun onLocationChanged(location: Location) {
                    manager.removeUpdates(this)
                    save(location)
                }
                override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) = Unit
                override fun onProviderEnabled(provider: String) = Unit
                override fun onProviderDisabled(provider: String) = Unit
            }
            @Suppress("DEPRECATION")
            manager.requestSingleUpdate(provider, listener, Looper.getMainLooper())
        }
    }

    @Suppress("DEPRECATION")
    private fun vibrateSuccess() {
        if (!vibrator.hasVibrator()) return
        vibrator.cancel()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createOneShot(180, 220))
        } else {
            vibrator.vibrate(180)
        }
    }

    @Suppress("DEPRECATION")
    private fun vibrateFailure() {
        if (!vibrator.hasVibrator()) return
        vibrator.cancel()
        val timings = longArrayOf(0, 220, 140, 220)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            vibrator.vibrate(VibrationEffect.createWaveform(timings, intArrayOf(0, 255, 0, 255), -1))
        } else {
            vibrator.vibrate(timings, -1)
        }
    }

    private fun sectionLabel(value: String) = text(value, 14f, true).apply {
        setTextColor(Color.rgb(184, 186, 198))
        setPadding(0, dp(6), 0, dp(8))
    }

    private fun pskInput(hintText: String) = EditText(this).apply {
        hint = hintText
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        setTextColor(Color.WHITE)
        setHintTextColor(Color.GRAY)
    }

    private fun text(value: String, size: Float, bold: Boolean) = TextView(this).apply {
        text = value
        textSize = size
        setTextColor(Color.WHITE)
        gravity = Gravity.CENTER_VERTICAL
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun primaryButton(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 14f
        setTextColor(Color.WHITE)
        background = rounded(Color.rgb(64, 103, 172), 22f)
        setPadding(dp(10), 0, dp(10), 0)
        setOnClickListener { action() }
    }

    private fun iconButton(icon: Int, description: String, action: () -> Unit) = ImageButton(this).apply {
        setImageResource(icon)
        contentDescription = description
        setPadding(dp(12), dp(12), dp(12), dp(12))
        imageTintList = ColorStateList.valueOf(Color.WHITE)
        background = selectableBorderlessBackground()
        setOnClickListener { action() }
    }

    private fun rounded(color: Int, radiusDp: Float) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        setColor(color)
        cornerRadius = dp(radiusDp.toInt()).toFloat()
    }

    private fun selectableBorderlessBackground() = obtainStyledAttributes(
        intArrayOf(android.R.attr.selectableItemBackgroundBorderless),
    ).let { attributes ->
        val drawable = attributes.getDrawable(0)
        attributes.recycle()
        drawable
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
