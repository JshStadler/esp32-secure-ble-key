package dev.jshstadler.carkey

import android.Manifest
import android.app.AlertDialog
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Looper
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.*
import java.util.UUID
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity

class MainActivity : FragmentActivity(), BleCarKeyClient.Listener {
    private val store by lazy { SecureStore(this) }
    private val client by lazy {
        BleCarKeyClient(this, getSystemService(BluetoothManager::class.java), this)
    }

    private lateinit var statusTitle: TextView
    private lateinit var statusMessage: TextView
    private lateinit var statusIcon: ImageView
    private lateinit var actionButton: FrameLayout
    private lateinit var actionIcon: ImageView
    private lateinit var actionLabel: TextView
    private lateinit var connectButton: Button
    private lateinit var scanFallbackButton: Button
    private lateinit var authOverlay: LinearLayout
    private var state = BleCarKeyClient.State.DISCONNECTED
    private var psk = ""
    private var cachedAddress: String? = null
    private var preferCached = false
    private var requireAuthentication = true
    private var recordLocation = false
    private var authenticated = false
    private var scanFallbackOffered = false
    private var foregroundSession = UUID.randomUUID().toString()

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        if (result.values.all { it }) startOrConfigure()
        else updateState(BleCarKeyClient.State.DISCONNECTED, "Bluetooth permission is required")
    }
    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        val granted = result[Manifest.permission.ACCESS_FINE_LOCATION] == true ||
            result[Manifest.permission.ACCESS_COARSE_LOCATION] == true
        recordLocation = granted
        store.put("record_location", granted.toString())
        toast(if (granted) "Location recording enabled" else "Location recording remains disabled")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_CarKey)
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK
        psk = store.get("psk") ?: ""
        cachedAddress = store.get("cached_address")
        preferCached = store.get("prefer_cached") == "true"
        requireAuthentication = store.get("require_auth") != "false"
        recordLocation = store.get("record_location") == "true" && hasLocationPermission()
        setContentView(buildUi())
        requestPermissionsAndStart()
        if (requireAuthentication) authenticate("Authenticate to access Car Key") { ok ->
            authenticated = ok
            authOverlay.visibility = if (ok) View.GONE else View.VISIBLE
        } else {
            authenticated = true
            authOverlay.visibility = View.GONE
        }
    }

    override fun onResume() {
        super.onResume()
        if (psk.isNotEmpty() && state == BleCarKeyClient.State.DISCONNECTED && hasPermissions()) {
            client.start(psk, cachedAddress, preferCached)
        }
    }

    override fun onStart() {
        super.onStart()
        foregroundSession = UUID.randomUUID().toString()
    }

    override fun onDestroy() {
        client.stop(true)
        super.onDestroy()
    }

    private fun buildUi(): View {
        val background = Color.BLACK
        val surface = Color.rgb(31, 34, 48)
        val primary = Color.rgb(64, 103, 172)
        val root = FrameLayout(this).apply { setBackgroundColor(background) }
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(0, bars.top, 0, bars.bottom)
            insets
        }
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), 0, dp(24), dp(24))
        }
        root.addView(page, FrameLayout.LayoutParams(-1, -1))

        val bar = LinearLayout(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        bar.addView(text("Car Key", 22f, true), LinearLayout.LayoutParams(0, dp(64), 1f))
        bar.addView(
            iconButton(R.drawable.ic_logs, "Logs") { startActivity(Intent(this, LogActivity::class.java)) },
            LinearLayout.LayoutParams(dp(48), dp(48)),
        )
        bar.addView(iconButton(R.drawable.ic_settings, "App settings") { showAppSettings() })
        page.addView(bar, LinearLayout.LayoutParams(-1, dp(72)))

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(18), dp(18), dp(12), dp(18))
            this.background = rounded(surface, 18f)
            elevation = dp(2).toFloat()
        }
        statusIcon = ImageView(this).apply {
            setImageResource(R.drawable.ic_bluetooth)
            imageTintList = ColorStateList.valueOf(Color.rgb(219, 68, 75))
            setPadding(dp(3), dp(3), dp(3), dp(3))
        }
        card.addView(statusIcon, LinearLayout.LayoutParams(dp(36), dp(36)))
        val statusStack = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, dp(10), 0)
        }
        statusTitle = text("Disconnected", 16f, true)
        statusMessage = text("Not connected", 13f, false).apply { setTextColor(Color.rgb(184, 186, 198)) }
        statusStack.addView(statusTitle)
        statusStack.addView(statusMessage)
        card.addView(statusStack, LinearLayout.LayoutParams(0, -2, 1f))
        connectButton = Button(this).apply {
            text = "Connect"
            isAllCaps = false
            textSize = 14f
            setTextColor(Color.WHITE)
            this.background = rounded(Color.TRANSPARENT, 22f, Color.rgb(118, 147, 205))
            setPadding(dp(16), 0, dp(16), 0)
            setOnClickListener {
                if (state == BleCarKeyClient.State.CONNECTED) client.stop()
                else if (psk.isNotEmpty()) client.start(psk, cachedAddress, preferCached)
            }
        }
        card.addView(connectButton, LinearLayout.LayoutParams(-2, dp(44)))
        page.addView(card, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })

        val center = FrameLayout(this)
        actionButton = FrameLayout(this).apply {
            isEnabled = false
            isClickable = true
            isFocusable = true
            this.background = rounded(primary, 120f)
            elevation = dp(6).toFloat()
            alpha = 0.48f
            setOnClickListener {
                isEnabled = false
                alpha = 0.65f
                actionLabel.text = "Sending…"
                client.press()
            }
        }
        val actionContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
        }
        actionIcon = ImageView(this).apply { setImageResource(R.drawable.ic_touch) }
        actionLabel = text("Press", 20f, true).apply {
            gravity = Gravity.CENTER
            setPadding(0, dp(8), 0, 0)
        }
        actionContent.addView(actionIcon, LinearLayout.LayoutParams(dp(52), dp(52)))
        actionContent.addView(actionLabel)
        actionButton.addView(actionContent, FrameLayout.LayoutParams(-1, -1))
        center.addView(actionButton, FrameLayout.LayoutParams(dp(208), dp(208), Gravity.CENTER))
        page.addView(center, LinearLayout.LayoutParams(-1, 0, 1f))

        scanFallbackButton = Button(this).apply {
            text = "Scan for device"
            isAllCaps = false
            textSize = 15f
            setTextColor(Color.WHITE)
            this.background = rounded(primary, 28f)
            visibility = View.GONE
            setOnClickListener {
                scanFallbackOffered = false
                visibility = View.GONE
                client.scanFallback()
            }
        }
        page.addView(scanFallbackButton, LinearLayout.LayoutParams(-1, dp(56)))

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
            addView(Button(context).apply {
                text = "Authenticate"
                isAllCaps = false
                setTextColor(Color.WHITE)
                this.background = rounded(primary, 26f)
                setOnClickListener {
                    authenticate("Authenticate to access Car Key") { ok ->
                        authenticated = ok
                        if (ok) authOverlay.visibility = View.GONE
                    }
                }
            }, LinearLayout.LayoutParams(dp(180), dp(52)))
        }
        root.addView(authOverlay, FrameLayout.LayoutParams(-1, -1))
        return root
    }

    private fun requestPermissionsAndStart() {
        if (hasPermissions()) startOrConfigure()
        else permissionLauncher.launch(requiredPermissions())
    }

    private fun startOrConfigure() {
        if (psk.isEmpty()) showInitialPskDialog()
        else client.start(psk, cachedAddress, preferCached)
    }

    private fun requiredPermissions(): Array<String> = if (Build.VERSION.SDK_INT >= 31) {
        arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    private fun hasPermissions() = requiredPermissions().all {
        ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
    }

    private fun showInitialPskDialog() {
        val input = pskInput("Pre-shared key")
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Welcome")
            .setMessage("Enter the same PSK configured in the ESP32 firmware.")
            .setView(input)
            .setCancelable(false)
            .setPositiveButton("Save", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val value = input.text.toString().trim()
                        if (value.isEmpty()) input.error = "PSK is required"
                        else {
                            savePsk(value)
                            dialog.dismiss()
                            client.start(psk, cachedAddress, preferCached)
                        }
                    }
                }
                dialog.show()
            }
    }

    private fun openPskSettings() {
        authenticate("Authenticate to access PSK settings") { ok -> if (ok) showPskDialog() }
    }

    private fun showPskDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), 0, dp(20), 0)
        }
        val first = pskInput("New PSK")
        val confirm = pskInput("Confirm new PSK")
        val updateDevice = CheckBox(this).apply {
            text = "Also update connected device"
            setTextColor(Color.WHITE)
            isChecked = state == BleCarKeyClient.State.CONNECTED
            isEnabled = state == BleCarKeyClient.State.CONNECTED
        }
        layout.addView(first)
        layout.addView(confirm)
        layout.addView(updateDevice)
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("PSK Settings")
            .setView(layout)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                        val value = first.text.toString().trim()
                        when {
                            value.isEmpty() -> first.error = "PSK is required"
                            value != confirm.text.toString().trim() -> confirm.error = "PSKs do not match"
                            updateDevice.isChecked && !client.updatePsk(value) -> toast("A fresh challenge is not available")
                            else -> {
                                savePsk(value)
                                toast(if (updateDevice.isChecked) "PSK update sent" else "PSK saved locally")
                                dialog.dismiss()
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
        val cachedSwitch = Switch(this).apply {
            text = "Use cached device address"
            setTextColor(Color.WHITE)
            isChecked = preferCached
            isEnabled = cachedAddress != null
            setPadding(0, dp(8), 0, dp(8))
        }
        val locationSwitch = Switch(this).apply {
            text = "Record operation locations"
            setTextColor(Color.WHITE)
            isChecked = recordLocation
            setPadding(0, dp(8), 0, dp(8))
        }
        options.addView(authSwitch)
        options.addView(cachedSwitch)
        options.addView(locationSwitch)
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("App Settings")
            .setView(options)
            .setNeutralButton("PSK Settings", null)
            .setPositiveButton("Done") { _, _ ->
                requireAuthentication = authSwitch.isChecked
                preferCached = cachedSwitch.isChecked
                if (locationSwitch.isChecked && !hasLocationPermission()) {
                    locationPermissionLauncher.launch(
                        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION),
                    )
                } else {
                    recordLocation = locationSwitch.isChecked
                    store.put("record_location", recordLocation.toString())
                }
                store.put("require_auth", requireAuthentication.toString())
                store.put("prefer_cached", preferCached.toString())
            }
            .create().also { dialog ->
                dialog.setOnShowListener {
                    dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                        dialog.dismiss()
                        openPskSettings()
                    }
                }
                dialog.show()
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
                .setTitle("Car Key")
                .setSubtitle(reason)
                .setAllowedAuthenticators(allowed)
                .build(),
        )
    }

    private fun savePsk(value: String) {
        psk = value
        store.put("psk", value)
    }

    override fun onState(state: BleCarKeyClient.State, message: String) = runOnUiThread {
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "${state.name}: $message")
        updateState(state, message)
    }

    override fun onDiagnostic(message: String) {
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, message)
    }

    override fun onReadyChanged(ready: Boolean) = runOnUiThread {
        actionButton.isEnabled = ready && state == BleCarKeyClient.State.CONNECTED
        actionButton.alpha = if (actionButton.isEnabled) 1f else 0.48f
        if (ready) {
            actionLabel.text = "Press"
            actionIcon.setImageResource(R.drawable.ic_touch)
            actionButton.background = rounded(Color.rgb(64, 103, 172), 120f)
        }
    }

    override fun onDeviceAddress(address: String) {
        cachedAddress = address
        store.put("cached_address", address)
    }

    override fun onCommandResult(success: Boolean, message: String) = runOnUiThread {
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Command result: $message")
        if (success && message == "Command sent") {
            EventLog.addSessionPress(this, "Car-key operation completed successfully", foregroundSession)
            captureOperationLocation()
        }
        statusMessage.text = message
        actionLabel.text = if (success) "Sent" else "Failed"
        actionIcon.setImageResource(if (success) R.drawable.ic_check else R.drawable.ic_error)
        actionButton.background = rounded(if (success) Color.rgb(30, 140, 82) else Color.rgb(170, 45, 55), 120f)
        actionButton.alpha = 1f
        actionButton.postDelayed({
            actionLabel.text = "Press"
            actionIcon.setImageResource(R.drawable.ic_touch)
            actionButton.background = rounded(Color.rgb(64, 103, 172), 120f)
            actionButton.alpha = if (actionButton.isEnabled) 1f else 0.48f
        }, 2_000)
    }

    private fun updateState(newState: BleCarKeyClient.State, message: String) {
        state = newState
        statusTitle.text = when (newState) {
            BleCarKeyClient.State.DISCONNECTED -> "Disconnected"
            BleCarKeyClient.State.SCANNING -> "Scanning…"
            BleCarKeyClient.State.CONNECTING -> "Connecting…"
            BleCarKeyClient.State.CONNECTED -> "Connected"
        }
        statusMessage.text = message
        statusIcon.imageTintList = ColorStateList.valueOf(
            when (newState) {
                BleCarKeyClient.State.CONNECTED -> Color.GREEN
                BleCarKeyClient.State.SCANNING, BleCarKeyClient.State.CONNECTING -> Color.rgb(255, 170, 30)
                else -> Color.RED
            },
        )
        connectButton.text = if (newState == BleCarKeyClient.State.CONNECTED) "Disconnect" else "Connect"
        if (message.contains("scan fallback")) scanFallbackOffered = true
        if (newState == BleCarKeyClient.State.CONNECTED) scanFallbackOffered = false
        connectButton.visibility = if (
            newState == BleCarKeyClient.State.SCANNING ||
            newState == BleCarKeyClient.State.CONNECTING ||
            scanFallbackOffered
        ) View.INVISIBLE else View.VISIBLE
        actionButton.isEnabled = false
        actionButton.alpha = 0.48f
        scanFallbackButton.visibility = if (scanFallbackOffered) View.VISIBLE else View.GONE
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

    private fun iconButton(icon: Int, description: String, action: () -> Unit) = ImageButton(this).apply {
        setImageResource(icon)
        contentDescription = description
        setPadding(dp(12), dp(12), dp(12), dp(12))
        imageTintList = ColorStateList.valueOf(Color.WHITE)
        background = selectableBorderlessBackground()
        setOnClickListener { action() }
    }

    private fun rounded(color: Int, radiusDp: Float, strokeColor: Int? = null) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        setColor(color)
        cornerRadius = dp(radiusDp.toInt()).toFloat()
        if (strokeColor != null) setStroke(dp(1), strokeColor)
    }

    private fun selectableBorderlessBackground() = obtainStyledAttributes(
        intArrayOf(android.R.attr.selectableItemBackgroundBorderless),
    ).let { attributes ->
        val drawable = attributes.getDrawable(0)
        attributes.recycle()
        drawable
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    private fun hasLocationPermission() =
        ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED

    @android.annotation.SuppressLint("MissingPermission")
    private fun captureOperationLocation() {
        if (!recordLocation || !hasLocationPermission()) return
        val operationSession = foregroundSession
        val operationTime = System.currentTimeMillis()
        val manager = getSystemService(LocationManager::class.java)
        val provider = when {
            manager.isProviderEnabled(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
            manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER) -> LocationManager.NETWORK_PROVIDER
            else -> {
                EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Location not recorded: device location services are disabled")
                return
            }
        }
        val save: (Location) -> Unit = { location ->
            EventLog.addLocation(this, location.latitude, location.longitude, location.accuracy, operationSession, operationTime)
            EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Saved operation location with ±${location.accuracy.toInt()} m accuracy")
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

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
