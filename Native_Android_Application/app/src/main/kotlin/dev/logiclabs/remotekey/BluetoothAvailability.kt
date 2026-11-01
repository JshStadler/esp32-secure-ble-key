package dev.logiclabs.remotekey

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

/** The phone's Bluetooth state, separate from any individual device connection. */
enum class BluetoothAvailability(val message: String?, val actionLabel: String? = null) {
    AVAILABLE(null),
    OFF("Bluetooth is off", "Turn on Bluetooth"),
    TURNING_ON("Bluetooth is turning on…"),
    TURNING_OFF("Bluetooth is turning off…"),
    PERMISSION_REQUIRED("Bluetooth permission is required", "Allow Bluetooth"),
    UNSUPPORTED("Bluetooth LE is not available on this phone");

    companion object {
        @SuppressLint("MissingPermission")
        fun read(context: Context, manager: BluetoothManager?): BluetoothAvailability {
            val adapter = manager?.adapter ?: return UNSUPPORTED
            if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) return UNSUPPORTED
            val permissions = if (Build.VERSION.SDK_INT >= 31) {
                arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN)
            } else {
                arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }
            if (permissions.any { ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }) {
                return PERMISSION_REQUIRED
            }
            return try {
                when (adapter.state) {
                    BluetoothAdapter.STATE_ON -> AVAILABLE
                    BluetoothAdapter.STATE_TURNING_ON -> TURNING_ON
                    BluetoothAdapter.STATE_TURNING_OFF -> TURNING_OFF
                    else -> OFF
                }
            } catch (_: SecurityException) {
                PERMISSION_REQUIRED
            }
        }
    }
}
