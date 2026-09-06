package dev.jshstadler.carkey

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.*
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

/** Keeps the process eligible for BLE while the short background lease is active. */
class BackgroundConnectionService : Service() {
    internal class Lease(val busy: () -> Boolean, val disconnect: () -> Unit) {
        val period = BackgroundGracePeriod(SystemClock.elapsedRealtime())
        fun check() = period.expired(SystemClock.elapsedRealtime(), busy())
    }
    companion object {
        private var lease: Lease? = null
        internal fun begin(context: Context, next: Lease) {
            lease?.period?.cancel()
            lease = next
            try { ContextCompat.startForegroundService(context, Intent(context, BackgroundConnectionService::class.java)) }
            catch (_: RuntimeException) {
                lease = null
                next.disconnect()
            }
        }
        internal fun finish(context: Context, checkDeadline: Boolean) {
            val old = lease
            lease = null
            if (checkDeadline && old?.check() == true) old.disconnect()
            old?.period?.cancel()
            context.stopService(Intent(context, BackgroundConnectionService::class.java))
        }
    }
    private val handler = Handler(Looper.getMainLooper())
    private var ownedLease: Lease? = null
    private val tick = object : Runnable {
        override fun run() {
            val current = lease
            if (current == null) { stopSelf(); return }
            if (current.check()) {
                lease = null
                current.disconnect()
                stopSelf()
            } else handler.postDelayed(this, 1_000)
        }
    }
    override fun onBind(intent: Intent?) = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ownedLease = lease
        val channel = "brief_ble_connection"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(channel, "Brief background connection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, channel)
            .setSmallIcon(R.drawable.ic_key_notification)
            .setContentTitle("BLE Key connected")
            .setContentText(if (lease?.busy() == true) "Firmware update in progress" else "Keeping connections ready for 2 minutes")
            .setContentIntent(open).setOngoing(true).setSilent(true).build()
        try { startForeground(260, notification) }
        catch (_: RuntimeException) {
            val failed = ownedLease
            finish(this, false)
            failed?.disconnect()
            stopSelf()
            return START_NOT_STICKY
        }
        handler.removeCallbacks(tick)
        handler.post(tick)
        return START_NOT_STICKY
    }
    override fun onTaskRemoved(rootIntent: Intent?) {
        val current = lease
        lease = null
        current?.disconnect()
        stopSelf()
    }
    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        if (lease != null && lease === ownedLease) {
            val current = lease
            lease = null
            current?.disconnect()
        }
        ownedLease = null
        super.onDestroy()
    }
}
