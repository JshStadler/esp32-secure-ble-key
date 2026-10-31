package dev.logiclabs.remotekey

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.*
import androidx.core.content.ContextCompat

/** Optional location failures must never affect a completed BLE operation. */
internal object OperationLocationRecorder {
    @android.annotation.SuppressLint("MissingPermission")
    fun capture(context: Context, profile: BleDeviceProfile, session: String) {
        fun log(message: String) = EventLog.add(context, EventLog.Kind.DIAGNOSTIC, message, deviceId = profile.id, deviceName = profile.displayName)
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) return
        val time = System.currentTimeMillis()
        val manager = context.getSystemService(LocationManager::class.java) ?: return
        try {
            val provider = listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER).firstOrNull { manager.isProviderEnabled(it) }
                ?: run { log("Location not recorded: provider unavailable"); return }
            val save: (Location?) -> Unit = { location ->
                if (location == null) log("Location not recorded: no current fix available")
                else {
                    EventLog.addLocation(context, location.latitude, location.longitude, location.accuracy, session, time, profile.id, profile.displayName)
                    log("Saved operation location with +/-${location.accuracy.toInt()} m accuracy")
                }
            }
            if (Build.VERSION.SDK_INT >= 30) {
                val cancel = CancellationSignal()
                Handler(Looper.getMainLooper()).postDelayed({ cancel.cancel() }, 15_000)
                manager.getCurrentLocation(provider, cancel, ContextCompat.getMainExecutor(context), save)
            } else {
                val listener = object : LocationListener {
                    override fun onLocationChanged(location: Location) { manager.removeUpdates(this); save(location) }
                    override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
                    override fun onProviderEnabled(provider: String) {}
                    override fun onProviderDisabled(provider: String) {}
                }
                @Suppress("DEPRECATION")
                manager.requestSingleUpdate(provider, listener, Looper.getMainLooper())
                Handler(Looper.getMainLooper()).postDelayed({ runCatching { manager.removeUpdates(listener) } }, 15_000)
            }
        } catch (_: SecurityException) { log("Location not recorded: Android denied location access") }
        catch (_: IllegalArgumentException) { log("Location not recorded: provider unavailable") }
    }
}
