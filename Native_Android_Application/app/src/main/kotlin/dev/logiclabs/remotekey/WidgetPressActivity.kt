package dev.logiclabs.remotekey

import android.Manifest
import android.app.KeyguardManager
import android.appwidget.AppWidgetManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.UUID

/** A brief authentication/permission surface, never the main dashboard. */
class WidgetPressActivity : FragmentActivity() {
    private var launched = false
    private var authenticating = false
    private val widgetId get() = intent.getIntExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, AppWidgetManager.INVALID_APPWIDGET_ID)
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
        if (result.values.all { it }) authorize() else reject("Not sent — allow Bluetooth in Remote Key")
    }
    private val credential = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) send(true) else reject("Not sent — authentication canceled")
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Recreating a transient action must never recreate its authorization.
        if (Build.VERSION.SDK_INT < 31 || savedInstanceState != null || PressWidgetProvider.deviceId(this, widgetId) == null) { finish(); return }
        if (PressWidgetProvider.isBusy(PressWidgetProvider.deviceId(this, widgetId)!!)) { finish(); return }
        val required = if (Build.VERSION.SDK_INT >= 31)
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        if (required.any { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED })
            permissions.launch(required)
        else authorize()
    }
    private fun authorize() {
        if (authenticating || launched) return
        authenticating = true
        val keyguard = getSystemService(KeyguardManager::class.java)
        if (SecureStore(this).get("require_auth") == "false" && !keyguard.isDeviceLocked) { send(); return }
        val allowed = if (Build.VERSION.SDK_INT >= 30) BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL else BiometricManager.Authenticators.BIOMETRIC_STRONG
        fun useCredential() {
            @Suppress("DEPRECATION")
            val prompt = if (keyguard.isDeviceSecure) keyguard.createConfirmDeviceCredentialIntent("Remote Key", "Authenticate to press the widget device") else null
            if (prompt == null) reject("Not sent — set a device PIN or biometric") else credential.launch(prompt)
        }
        when (AppPolicies.authenticationRoute(Build.VERSION.SDK_INT,
            BiometricManager.from(this).canAuthenticate(allowed) == BiometricManager.BIOMETRIC_SUCCESS, keyguard.isDeviceSecure)) {
            AppPolicies.AuthenticationRoute.UNAVAILABLE -> reject("Not sent — set a device PIN or biometric")
            AppPolicies.AuthenticationRoute.CREDENTIAL -> useCredential()
            else -> BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { send(true) }
                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    if (Build.VERSION.SDK_INT < 30 && code == BiometricPrompt.ERROR_NEGATIVE_BUTTON && keyguard.isDeviceSecure) useCredential()
                    else reject("Not sent — authentication canceled")
                }
            }).authenticate(BiometricPrompt.PromptInfo.Builder().setTitle("Remote Key")
                .setSubtitle("Authenticate to press the widget device").setAllowedAuthenticators(allowed)
                .apply { if (Build.VERSION.SDK_INT < 30) setNegativeButtonText("Use device PIN") }.build())
        }
    }
    private fun send(authenticated: Boolean = false) {
        if (launched) return
        launched = true
        if (BluetoothAvailability.read(this, getSystemService(android.bluetooth.BluetoothManager::class.java)) != BluetoothAvailability.AVAILABLE) {
            reject("Not sent — turn on Bluetooth in Remote Key"); return
        }
        val service = Intent(this, WidgetPressService::class.java)
            .putExtra("widget_id", widgetId).putExtra("request_id", UUID.randomUUID().toString())
            .putExtra("requested_at", SystemClock.elapsedRealtime())
            .putExtra("authenticated", authenticated)
        try { ContextCompat.startForegroundService(this, service) }
        catch (_: RuntimeException) { reject("Not sent — unable to start Bluetooth"); return }
        finish()
    }
    private fun reject(message: String) {
        PressWidgetProvider.render(this, widgetId, message)
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }
}
