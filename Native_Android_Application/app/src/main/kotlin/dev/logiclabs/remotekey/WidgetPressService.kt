package dev.logiclabs.remotekey

import android.app.*
import android.appwidget.AppWidgetManager
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.os.*
import androidx.core.app.NotificationCompat

/** Owns a short-lived widget connection independently of the dashboard activity. */
class WidgetPressService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val window = WidgetPressWindow()
    private val requests = WidgetRequestLedger()
    private var client: BleCarKeyClient? = null
    private var profile: BleDeviceProfile? = null
    private var key: String? = null
    private var generation = 0
    private var lastStartId = 0
    private var actionWidgetId = AppWidgetManager.INVALID_APPWIDGET_ID
    private var actionAuthenticated = false
    private var ready = false
    private var session = ""
    private var message = "Connecting…"
    private val store by lazy { SecureStore(this) }
    override fun onBind(intent: Intent?) = null
    private fun now() = SystemClock.elapsedRealtime()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        if (!foreground()) { end("Not sent — unable to start Bluetooth"); return START_NOT_STICKY }
        when (intent?.action) {
            "cancel" -> { if (window.busy && !window.dispatched) end("Canceled before sending"); return START_NOT_STICKY }
            "close" -> { if (!window.busy) end("Tap to press"); return START_NOT_STICKY }
        }
        val requestId = intent?.getStringExtra("request_id")
        val requestedAt = intent?.getLongExtra("requested_at", -1) ?: -1
        // No redelivery, delayed intent, or duplicate activity callback can authorize a press.
        if (!requests.accept(requestId, requestedAt, now())) {
            if (!window.active) end("Not sent — expired request")
            return START_NOT_STICKY
        }
        if (window.busy) return START_NOT_STICKY // Never queue extra gate/car actions.
        val widgetId = intent?.getIntExtra("widget_id", AppWidgetManager.INVALID_APPWIDGET_ID) ?: AppWidgetManager.INVALID_APPWIDGET_ID
        val id = PressWidgetProvider.deviceId(this, widgetId)
        val target = DeviceProfileRepository(store).load().firstOrNull { it.id == id }
        val psk = target?.let { store.get(it.pskStoreKey) }
        val error = when {
            target == null -> "Not sent — configure this widget again"
            psk.isNullOrBlank() -> "Not sent — set the device key in Remote Key"
            store.get("${target.pskStoreKey}_pending_change") != null -> "Not sent — recover the key change in Remote Key"
            else -> BluetoothAvailability.read(this, getSystemService(BluetoothManager::class.java)).message
        }
        if (error != null) {
            PressWidgetProvider.render(this, widgetId, error)
            if (!window.active) stopSelf(lastStartId)
            return START_NOT_STICKY
        }
        target!!; psk!!
        if (profile != target || key != psk || client?.isRunning != true) {
            closeClient("Tap to press")
            profile = target; key = psk
        }
        session = requestId!!
        actionWidgetId = widgetId
        actionAuthenticated = intent?.getBooleanExtra("authenticated", false) == true
        window.tap(now())
        publish(if (ready) "Sending…" else "Connecting…")
        scheduleCheck()
        if (client == null) connect(target, psk)
        else dispatchIfReady()
        return START_NOT_STICKY
    }
    private val tick = object : Runnable {
        override fun run() {
            val timeout = window.timeout(now())
            when {
                timeout != null -> { finishRequest(false, timeout); return }
                window.expired(now()) -> { end("Tap to press"); return }
            }
            if (window.active) scheduleCheck()
        }
    }
    private fun scheduleCheck() {
        handler.removeCallbacks(tick)
        handler.postDelayed(tick, window.nextCheckDelay(now()))
    }
    private fun connect(target: BleDeviceProfile, psk: String) {
        val owned = ++generation
        fun current() = owned == generation && client != null
        val listener = object : BleCarKeyClient.Listener {
            override fun onState(state: BleCarKeyClient.State, message: String) {
                if (!current()) return
                log("${state.name}: $message")
                if (state != BleCarKeyClient.State.CONNECTED) ready = false
                if (state == BleCarKeyClient.State.DISCONNECTED) {
                    if (window.busy) finishRequest(false, if (window.dispatched) "Unable to confirm — check the device" else "Not sent — $message")
                    else end("Tap to reconnect")
                } else if (state == BleCarKeyClient.State.RETRYING && !window.busy) end("Tap to reconnect")
            }
            override fun onReadyChanged(value: Boolean) {
                if (!current()) return
                ready = value
                dispatchIfReady()
            }
            override fun onDeviceAddress(address: String) { if (current()) store.put(target.addressStoreKey, address) }
            override fun onDeviceState(state: String) {}
            override fun onCommandResult(success: Boolean, message: String) { if (current()) finishRequest(success, message) }
            override fun onDiagnostic(message: String) { if (current()) log(message) }
            override fun onPskUpdateResult(success: Boolean, message: String) {}
            override fun onOtaProgress(sent: Int, total: Int) {}
            override fun onOtaResult(success: Boolean, message: String) {}
        }
        client = BleCarKeyClient(this, getSystemService(BluetoothManager::class.java), target, listener)
        client!!.start(psk, store.get(target.addressStoreKey) ?: target.defaultAddress,
            store.get(target.preferCachedStoreKey)?.toBooleanStrictOrNull() ?: (target.defaultAddress != null))
    }
    private fun dispatchIfReady() {
        if (!ready || !window.busy || window.dispatched) return
        window.timeout(now())?.let { finishRequest(false, it); return }
        val target = profile ?: return
        val currentProfile = DeviceProfileRepository(store).load().firstOrNull { it.id == target.id }
        if (PressWidgetProvider.deviceId(this, actionWidgetId) != target.id || currentProfile != target ||
            store.get(target.pskStoreKey) != key || store.get("${target.pskStoreKey}_pending_change") != null ||
            (store.get("require_auth") != "false" && !actionAuthenticated)) {
            finishRequest(false, "Not sent — device setup changed; tap again")
            return
        }
        if (window.claim(now())) {
            scheduleCheck()
            publish("Sending…")
            client?.press()
        }
    }
    private fun finishRequest(success: Boolean, result: String) {
        if (!window.busy) return
        val wasSent = window.dispatched
        window.complete(now())
        scheduleCheck()
        log("Widget action: $result")
        val target = profile ?: return
        if (success && wasSent) {
            EventLog.addSessionPress(this, "${target.displayName} remote button pressed (widget)", session, target.id, target.displayName)
            if (store.get(target.recordLocationStoreKey) == "true") OperationLocationRecorder.capture(this, target, session)
            publish("Pressed • ready for 30s")
        } else end(if (wasSent) "Unable to confirm — check the device" else result)
    }
    private fun log(value: String) {
        val target = profile ?: return
        EventLog.add(this, EventLog.Kind.DIAGNOSTIC, "Widget ${target.displayName}: $value", deviceId = target.id, deviceName = target.displayName)
    }
    private fun publish(value: String) {
        message = value
        profile?.let { PressWidgetProvider.publish(this, it.id, value, window.busy) }
        foreground()
    }
    private fun foreground(): Boolean {
        val channel = "widget_ble_connection"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(channel, "Widget Bluetooth connection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, channel).setSmallIcon(R.drawable.ic_key_notification)
            .setContentTitle(profile?.displayName ?: "Remote Key widget").setContentText(message)
            .setContentIntent(open).setOngoing(true).setSilent(true)
        if (!window.dispatched) {
            val action = if (window.busy) "cancel" else "close"
            val pending = if (Build.VERSION.SDK_INT >= 26) PendingIntent.getForegroundService(this, 1,
                Intent(this, WidgetPressService::class.java).setAction(action), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            else PendingIntent.getService(this, 1, Intent(this, WidgetPressService::class.java).setAction(action), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            notification.addAction(0, if (window.busy) "Cancel" else "Disconnect", pending)
        }
        return try { startForeground(261, notification.build()); true } catch (_: RuntimeException) { false }
    }
    private fun closeClient(status: String) {
        generation++ // Invalidate ownership before synchronous teardown callbacks.
        val old = client; client = null; ready = false
        old?.stop()
        profile?.let { PressWidgetProvider.publish(this, it.id, status) }
        profile = null; key = null
    }
    private fun end(status: String) {
        window.cancel()
        handler.removeCallbacks(tick)
        closeClient(status)
        stopSelf(lastStartId)
    }
    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        window.cancel()
        closeClient("Tap to press")
        super.onDestroy()
    }
}
