package dev.jshstadler.carkey

import android.Manifest
import android.app.AlertDialog
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
    )

    private data class DeviceViews(
        val statusIcon: ImageView,
        val statusText: TextView,
        val actionButton: Button,
    )

    private val store by lazy { SecureStore(this) }
    private val bluetoothManager by lazy { getSystemService(BluetoothManager::class.java) }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val runtimes = mutableMapOf<String, DeviceRuntime>()
    private val deviceViews = mutableMapOf<String, DeviceViews>()
    private val clients = mutableMapOf<String, BleCarKeyClient>()

    private var appForeground = false
    private var pendingPressId: String? = null
    private var pressDispatched = false
    private var pendingPskValue: String? = null
    private var pendingPskOnSaved: (() -> Unit)? = null
    private var pendingOtaImage: ByteArray? = null
    private var pendingLocationDeviceId: String? = null
    private var operationGeneration = 0
    private var operationSession = UUID.randomUUID().toString()
    private var requireAuthentication = true
    private var authenticated = false
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
        val profile = pendingLocationDeviceId?.let(BleDeviceProfiles::byId)
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
        if (uri == null) return@registerForActivityResult
        val image = runCatching { contentResolver.openInputStream(uri)?.use { it.readBytes() } }.getOrNull()
        when {
            image == null -> toast("Could not read firmware file")
            image.isEmpty() || image.size > 0x1e0000 -> toast("Firmware must be 1 byte to 1,966,080 bytes")
            else -> AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
                .setTitle("Update car firmware?")
                .setMessage("Transfer ${(image.size + 1023) / 1024} KiB over BLE. Keep the phone near the car and do not remove car power. Only signed firmware from this project is accepted.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Update") { _, _ -> requestCarOta(image) }
                .show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_CarKey)
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK

        requireAuthentication = store.get("require_auth") != "false"
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
        operationGeneration++
        pendingPressId = null
        pendingPskValue = null
        pendingPskOnSaved = null
        stopAllClients()
        super.onDestroy()
    }

    override fun onStart() {
        super.onStart()
        appForeground = true
        startForegroundClients()
    }

    override fun onStop() {
        appForeground = false
        // Do not interrupt a firmware transfer if Android briefly backgrounds
        // the activity. Ordinary foreground connections are released here.
        if (pendingOtaImage == null) stopAllClients()
        super.onStop()
    }

    private fun loadDeviceSettings() {
        val legacyPsk = store.get("psk") ?: ""
        val legacyAddress = store.get("cached_address")
        val legacyPreferCached = store.get("prefer_cached") == "true"
        val legacyRecordLocation = store.get("record_location") == "true"

        BleDeviceProfiles.configured.forEach { profile ->
            val runtime = DeviceRuntime(
                psk = store.get(profile.pskStoreKey) ?: legacyPsk,
                cachedAddress = store.get(profile.addressStoreKey)
                    ?: if (profile.id == BleDeviceProfiles.CAR.id) legacyAddress else profile.defaultAddress,
                preferCached = store.get(profile.preferCachedStoreKey)?.toBooleanStrictOrNull()
                    ?: if (profile.id == BleDeviceProfiles.CAR.id) legacyPreferCached else profile.defaultAddress != null,
                recordLocation = store.get(profile.recordLocationStoreKey)?.toBooleanStrictOrNull()
                    ?: (profile.id == BleDeviceProfiles.CAR.id && legacyRecordLocation),
            )
            runtimes[profile.id] = runtime
            if (runtime.psk.isNotEmpty()) store.put(profile.pskStoreKey, runtime.psk)
            runtime.cachedAddress?.let { store.put(profile.addressStoreKey, it) }
            store.put(profile.preferCachedStoreKey, runtime.preferCached.toString())
            store.put(profile.recordLocationStoreKey, runtime.recordLocation.toString())
        }
    }

    private fun buildUi(): View {
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
        BleDeviceProfiles.configured.forEach { profile ->
            page.addView(buildDeviceCard(profile, surface), LinearLayout.LayoutParams(-1, dp(108)).apply {
                bottomMargin = dp(12)
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
            setImageResource(if (profile.id == "gate") R.drawable.ic_gate else R.drawable.ic_car)
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
        if (runtimes.values.all { it.psk.isEmpty() }) showInitialPskDialog()
        else startForegroundClients()
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

    private fun listenerFor(profile: BleDeviceProfile) = object : BleCarKeyClient.Listener {
        override fun onState(state: BleCarKeyClient.State, message: String) = runOnUiThread {
            EventLog.add(this@MainActivity, EventLog.Kind.DIAGNOSTIC, "${profile.displayName} ${state.name}: $message")
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
            EventLog.add(this@MainActivity, EventLog.Kind.DIAGNOSTIC, "${profile.displayName}: $message")
        }

        override fun onReadyChanged(ready: Boolean) = runOnUiThread {
            val runtime = runtimes.getValue(profile.id)
            runtime.ready = ready
            if (ready) runtime.message = "Ready"
            updateDeviceView(profile.id)
            if (ready && pendingPressId == profile.id && !pressDispatched) {
                pressDispatched = true
                runtime.message = when {
                    pendingOtaImage != null -> "Preparing firmware update..."
                    pendingPskValue != null -> "Updating car PSK..."
                    else -> "Sending command..."
                }
                updateDeviceView(profile.id)
                when {
                    pendingOtaImage != null -> clients[profile.id]?.startOta(pendingOtaImage!!)
                    pendingPskValue != null -> {
                        if (clients[profile.id]?.updatePsk(pendingPskValue!!) != true) {
                            finishPskUpdate(profile, false, "Car firmware does not support PSK updates")
                        }
                    }
                    else -> clients[profile.id]?.press()
                }
            }
        }

        override fun onDeviceAddress(address: String) {
            val runtime = runtimes.getValue(profile.id)
            runtime.cachedAddress = address
            store.put(profile.addressStoreKey, address)
        }

        override fun onCommandResult(success: Boolean, message: String) = runOnUiThread {
            finishOperation(profile, success, message)
        }

        override fun onPskUpdateResult(success: Boolean, message: String) = runOnUiThread {
            finishPskUpdate(profile, success, message)
        }

        override fun onOtaProgress(sent: Int, total: Int) = runOnUiThread {
            val percent = if (total == 0) 0 else sent * 100 / total
            runtimes.getValue(profile.id).message = "Updating firmware: $percent%"
            updateDeviceView(profile.id)
        }

        override fun onOtaResult(success: Boolean, message: String) = runOnUiThread {
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
        )
        if (success && message == "Pressed") {
            EventLog.addSessionPress(this, "${profile.displayName} remote button pressed", operationSession)
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

    private fun requestCarPskUpdate(newPsk: String, onSaved: () -> Unit) {
        val profile = BleDeviceProfiles.CAR
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
        runtime.message = if (runtime.ready) "Updating car PSK..." else "Connecting to update car PSK..."
        updateDeviceView(profile.id)

        if (runtime.ready) {
            pressDispatched = true
            if (clients[profile.id]?.updatePsk(newPsk) != true) {
                finishPskUpdate(profile, false, "Car firmware does not support PSK updates")
                return
            }
        } else {
            ensureClient(profile)
        }

        mainHandler.postDelayed({
            if (generation == operationGeneration && pendingPskValue != null) {
                finishPskUpdate(profile, false, "Car PSK update timed out")
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
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, message)
        if (success) {
            vibrateSuccess()
            toast("Car and phone PSK updated")
            onSaved?.invoke()
        } else {
            vibrateFailure()
            toast(message)
        }
    }

    private fun requestCarOta(image: ByteArray) {
        val profile = BleDeviceProfiles.CAR
        if (!hasPermissions()) {
            toast("Bluetooth permission is required")
            return
        }
        val runtime = runtimes.getValue(profile.id)
        if (runtime.psk.isEmpty()) {
            showDevicePskDialog(profile) { requestCarOta(image) }
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
        ensureClient(profile)

        mainHandler.postDelayed({
            if (generation == operationGeneration && pendingOtaImage != null) {
                finishOtaOperation(profile, false, "Firmware update timed out")
            }
        }, 7 * 60 * 1000L)
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
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Car firmware update ${if (success) "completed" else "failed"}: $message")
        if (success) vibrateSuccess() else vibrateFailure()
        mainHandler.postDelayed({
            stopClient(profile.id)
            if (appForeground) mainHandler.postDelayed({ ensureClient(profile) }, 2_000L)
        }, if (success) 300L else 1_500L)
    }

    private fun startForegroundClients() {
        if (!appForeground || !authenticated || !hasPermissions()) return
        BleDeviceProfiles.configured.forEach { profile ->
            if (runtimes.getValue(profile.id).psk.isNotEmpty()) ensureClient(profile)
        }
    }

    private fun ensureClient(profile: BleDeviceProfile) {
        if (!appForeground || !hasPermissions() || clients.containsKey(profile.id)) return
        val runtime = runtimes.getValue(profile.id)
        if (runtime.psk.isEmpty()) return
        runtime.state = BleCarKeyClient.State.CONNECTING
        runtime.message = "Connecting..."
        updateDeviceView(profile.id)
        val client = BleCarKeyClient(this, bluetoothManager, profile, listenerFor(profile))
        clients[profile.id] = client
        client.start(runtime.psk, runtime.cachedAddress ?: profile.defaultAddress, runtime.preferCached)
    }

    private fun stopClient(deviceId: String) {
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

    private fun updateAllDeviceViews() = BleDeviceProfiles.configured.forEach { updateDeviceView(it.id) }

    private fun updateDeviceView(deviceId: String) {
        val runtime = runtimes[deviceId] ?: return
        val views = deviceViews[deviceId] ?: return
        views.statusText.text = runtime.message
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

    private fun showInitialPskDialog() {
        val input = pskInput("Pre-shared key")
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Welcome to BLE Key")
            .setMessage("Enter the shared PSK. Car and Gate both use API v2; their saved keys can be changed independently later.")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("Save", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val value = input.text.toString().trim()
                        if (value.isEmpty()) input.error = "PSK is required"
                        else {
                            BleDeviceProfiles.configured.forEach { savePsk(it, value) }
                            dialog.dismiss()
                            startForegroundClients()
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun showDeviceSettingsAuthenticated(profile: BleDeviceProfile) {
        authenticate("Authenticate to edit ${profile.displayName} settings") { ok ->
            if (ok) showDeviceSettings(profile)
        }
    }

    private fun showDevicePskDialog(profile: BleDeviceProfile, onSaved: () -> Unit = {}) {
        authenticate("Authenticate to edit ${profile.displayName} PSK") { ok ->
            if (ok) showDeviceSettings(profile, onSaved)
        }
    }

    private fun showDeviceSettings(profile: BleDeviceProfile, onSaved: () -> Unit = {}) {
        val runtime = runtimes.getValue(profile.id)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(12))
        }
        val isGate = profile.id == BleDeviceProfiles.GATE.id
        val first = pskInput(if (isGate) "App copy of gate PSK" else "New PSK")
        val confirm = if (isGate) null else pskInput("Confirm new PSK")
        val updateCarEspSwitch = if (isGate) null else Switch(this).apply {
            text = "Also change the PSK on the car ESP"
            setTextColor(Color.WHITE)
            isChecked = runtime.psk.isNotEmpty()
            isEnabled = runtime.psk.isNotEmpty()
            setPadding(0, dp(8), 0, dp(8))
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
        layout.addView(text(
            if (isGate) {
                "The ESPHome build controls the gate PSK. This only changes the matching key saved by the app."
            } else if (runtime.psk.isEmpty()) {
                "Enter the PSK already installed on the car to pair this phone. Future changes can update both."
            } else {
                "Keep the switch enabled to update the car ESP first and then save the confirmed key on this phone. Disable it for an app-only correction."
            },
            13f,
            false,
        ).apply {
            setTextColor(Color.rgb(184, 186, 198))
        }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
        layout.addView(sectionLabel(if (isGate) "App key" else "New PSK"), LinearLayout.LayoutParams(-1, -2))
        layout.addView(first, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        confirm?.let {
            layout.addView(it, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(8) })
        }
        layout.addView(primaryButton("Generate secure 32-character PSK") {
            val generated = DevicePskGenerator.generate()
            first.setText(generated)
            first.setSelection(generated.length)
            confirm?.apply {
                setText(generated)
                setSelection(generated.length)
            }
            showGeneratedPsk(generated)
        }, LinearLayout.LayoutParams(-1, dp(48)).apply { bottomMargin = dp(8) })
        updateCarEspSwitch?.let {
            layout.addView(it, LinearLayout.LayoutParams(-1, -2))
            layout.addView(text(
                if (runtime.psk.isEmpty()) {
                    "Save the car's current PSK on this phone first; changing both becomes available afterward."
                } else {
                    "On: changes the PSK on both the car ESP and this phone. Off: changes this phone only."
                },
                12f,
                false,
            ).apply {
                setTextColor(Color.rgb(184, 186, 198))
            }, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(12) })
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
        if (profile.id == BleDeviceProfiles.CAR.id) {
            layout.addView(sectionLabel("Firmware"), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(4) })
            layout.addView(primaryButton("Update car firmware (.bin)") {
                firmwareFileLauncher.launch(arrayOf("application/octet-stream", "*/*"))
            }, LinearLayout.LayoutParams(-1, dp(48)).apply { topMargin = dp(4) })
        }
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
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val value = first.text.toString().trim()
                        when {
                            confirm != null && value.isNotEmpty() && value != confirm.text.toString().trim() -> confirm.error = "PSKs do not match"
                            else -> {
                                runtime.preferCached = cachedSwitch.isChecked
                                store.put(profile.preferCachedStoreKey, runtime.preferCached.toString())
                                val requestLocationPermission = locationSwitch.isChecked && !hasLocationPermission()
                                runtime.recordLocation = locationSwitch.isChecked && !requestLocationPermission
                                store.put(profile.recordLocationStoreKey, runtime.recordLocation.toString())
                                if (requestLocationPermission) pendingLocationDeviceId = profile.id
                                dialog.dismiss()
                                if (requestLocationPermission) {
                                    locationPermissionLauncher.launch(
                                        arrayOf(
                                            Manifest.permission.ACCESS_FINE_LOCATION,
                                            Manifest.permission.ACCESS_COARSE_LOCATION,
                                        ),
                                    )
                                }
                                when {
                                    value.isEmpty() || value == runtime.psk -> onSaved()
                                    updateCarEspSwitch?.isChecked == true -> requestCarPskUpdate(value, onSaved)
                                    else -> {
                                        savePsk(profile, value)
                                        onSaved()
                                    }
                                }
                            }
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun showAppSettings() {
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
        options.addView(authSwitch)
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("BLE Key Settings")
            .setView(options)
            .setPositiveButton("Done") { _, _ ->
                requireAuthentication = authSwitch.isChecked
                store.put("require_auth", requireAuthentication.toString())
            }
            .show()
    }

    private fun showGeneratedPsk(generated: String) {
        val value = text(generated, 17f, true).apply {
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(dp(16), dp(18), dp(16), dp(18))
        }
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Save this PSK now")
            .setMessage("This is the only time BLE Key will display or offer to copy this generated PSK. It remains masked after this dialog closes. Tap Save in device settings to apply it.")
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
                Toast.makeText(this, "PSK copied. Store it securely, then tap Save.", Toast.LENGTH_LONG).show()
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
        val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(allowed) != BiometricManager.BIOMETRIC_SUCCESS) {
            result(true)
            return
        }
        BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) = result(true)
                override fun onAuthenticationError(code: Int, message: CharSequence) = result(false)
            },
        ).authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("BLE Key")
                .setSubtitle(reason)
                .setAllowedAuthenticators(allowed)
                .build(),
        )
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
                EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Location not recorded: location services are disabled")
                return
            }
        }
        val save: (Location) -> Unit = { location ->
            EventLog.addLocation(this, location.latitude, location.longitude, location.accuracy, operationSession, operationTime)
            EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Saved operation location with +/-${location.accuracy.toInt()} m accuracy")
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
