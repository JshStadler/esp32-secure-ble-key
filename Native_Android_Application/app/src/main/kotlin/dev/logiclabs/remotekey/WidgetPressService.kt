package dev.logiclabs.remotekey

import android.app.*
import android.appwidget.AppWidgetManager
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.Context
import android.net.Uri
import android.os.*
import androidx.core.app.NotificationCompat

/** A foreground owner for independent, short-lived device sessions. All callbacks use the main looper. */
class WidgetPressService : Service() {
    companion object {
        internal fun cancellationIntent(context: Context, profileId: String, requestId: String) =
            Intent(context, WidgetPressService::class.java).setAction("cancel")
                .setData(Uri.parse("remotekey://widget-action/cancel/$requestId"))
                .putExtra("cancel_profile_id", profileId).putExtra("cancel_request_id", requestId)
    }
    internal interface Connection {
        val isRunning: Boolean
        fun start(key: String, address: String?, preferCached: Boolean)
        fun press()
        fun stop()
    }
    private val handler = Handler(Looper.getMainLooper())
    private val requests = WidgetRequestLedger()
    private val sessions = linkedMapOf<String, DeviceSession>()
    private val store by lazy { SecureStore(this) }
    // Dependencies keep session lifecycle and dispatch testable without a physical radio or keystore.
    internal var readSetting: (String) -> String? = { store.get(it) }
    internal var loadProfiles: () -> List<BleDeviceProfile> = { DeviceProfileRepository(store).load() }
    internal var createConnection: (BleDeviceProfile, BleCarKeyClient.Listener) -> Connection = { target, listener ->
        val ble = BleCarKeyClient(this, getSystemService(BluetoothManager::class.java), target, listener)
        object : Connection {
            override val isRunning get() = ble.isRunning
            override fun start(key: String, address: String?, preferCached: Boolean) = ble.start(key, address, preferCached)
            override fun press() = ble.press()
            override fun stop() = ble.stop()
        }
    }
    private var lastStartId = 0
    override fun onBind(intent: Intent?) = null
    private fun now() = SystemClock.elapsedRealtime()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        if (!foreground()) {
            sessions.values.toList().forEach { it.end("Not sent — unable to start Bluetooth", updateService = false) }
            stopSelf(lastStartId)
            return START_NOT_STICKY
        }
        when (intent?.action) {
            "cancel" -> {
                val owner = sessions[intent.getStringExtra("cancel_profile_id")]
                if (owner?.window?.cancelPending(intent.getStringExtra("cancel_request_id")) == true) {
                    owner.log("Widget request canceled before sending")
                    owner.end("Canceled before sending")
                }
                stopIfIdle()
                return START_NOT_STICKY
            }
            "close" -> {
                val owner = sessions[intent.getStringExtra("cancel_profile_id")]
                if (owner != null && !owner.window.busy && owner.session == intent.getStringExtra("cancel_request_id"))
                    owner.end("Tap to press")
                stopIfIdle()
                return START_NOT_STICKY
            }
        }
        val requestId = intent?.getStringExtra("request_id")
        val requestedAt = intent?.getLongExtra("requested_at", -1) ?: -1
        if (!requests.accept(requestId, requestedAt, now())) { stopIfIdle(); return START_NOT_STICKY }
        val widgetId = intent?.getIntExtra("widget_id", AppWidgetManager.INVALID_APPWIDGET_ID) ?: AppWidgetManager.INVALID_APPWIDGET_ID
        val id = PressWidgetProvider.deviceId(this, widgetId)
        // One in-flight action per device; another device's request never blocks or replaces it.
        if (sessions[id]?.window?.busy == true) return START_NOT_STICKY
        val target = loadProfiles().firstOrNull { it.id == id }
        val psk = target?.let { readSetting(it.pskStoreKey) }
        val error = when {
            target == null -> "Not sent — configure this widget again"
            intent?.getStringExtra("device_snapshot") != target.toString() -> "Not sent — widget changed; tap again"
            psk.isNullOrBlank() -> "Not sent — set the device key in Remote Key"
            readSetting("${target.pskStoreKey}_pending_change") != null -> "Not sent — recover the key change in Remote Key"
            else -> BluetoothAvailability.read(this, getSystemService(BluetoothManager::class.java)).message
        }
        if (error != null) {
            PressWidgetProvider.render(this, widgetId, error)
            stopIfIdle()
            return START_NOT_STICKY
        }
        target!!; psk!!
        var owner = sessions[target.id]
        if (owner != null && (owner.profile != target || owner.key != psk || owner.client?.isRunning != true)) {
            owner.end("Tap to press", updateService = false)
            owner = null
        }
        if (owner == null) {
            owner = DeviceSession(target, psk)
            sessions[target.id] = owner
        }
        owner.start(widgetId, requestId!!, intent?.getBooleanExtra("authenticated", false) == true)
        return START_NOT_STICKY
    }

    private inner class DeviceSession(val profile: BleDeviceProfile, val key: String) {
        val window = WidgetPressWindow()
        var client: Connection? = null
        var session = ""
        var message = "Connecting…"
        private var generation = 0
        private var widgetId = AppWidgetManager.INVALID_APPWIDGET_ID
        private var authenticated = false
        private var ready = false
        private var feedbackReset: Runnable? = null
        private fun current() = sessions[profile.id] === this
        fun start(widget: Int, requestId: String, authorized: Boolean) {
            clearFeedback()
            session = requestId; widgetId = widget; authenticated = authorized
            if (!window.tap(now(), requestId)) return
            publish(if (ready) "Sending…" else "Connecting…")
            scheduleCheck()
            if (client == null) connect() else dispatchIfReady()
        }
        private val tick = object : Runnable {
            override fun run() {
                if (!current()) return
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
        private fun connect() {
            val owned = ++generation
            fun live() = current() && owned == generation && client != null
            val listener = object : BleCarKeyClient.Listener {
                override fun onState(state: BleCarKeyClient.State, message: String) {
                    if (!live()) return
                    log("${state.name}: $message")
                    PressWidgetProvider.connection(this@WidgetPressService, profile.id, "widget", state == BleCarKeyClient.State.CONNECTED)
                    if (state != BleCarKeyClient.State.CONNECTED) ready = false
                    if (state == BleCarKeyClient.State.DISCONNECTED) {
                        if (window.busy) finishRequest(false, if (window.dispatched) "Unable to confirm — check the device" else "Not sent — $message")
                        else end("Tap to reconnect")
                    } else if (state == BleCarKeyClient.State.RETRYING && !window.busy) end("Tap to reconnect")
                }
                override fun onReadyChanged(ready: Boolean) { if (live()) { this@DeviceSession.ready = ready; dispatchIfReady() } }
                override fun onDeviceAddress(address: String) { if (live()) store.put(profile.addressStoreKey, address) }
                override fun onDeviceState(state: String) {}
                override fun onCommandResult(success: Boolean, message: String) { if (live()) finishRequest(success, message) }
                override fun onDiagnostic(message: String) { if (live()) log(message) }
                override fun onPskUpdateResult(success: Boolean, message: String) {}
                override fun onOtaProgress(sent: Int, total: Int) {}
                override fun onOtaResult(success: Boolean, message: String) {}
            }
            client = createConnection(profile, listener)
            client!!.start(key, readSetting(profile.addressStoreKey) ?: profile.defaultAddress,
                readSetting(profile.preferCachedStoreKey)?.toBooleanStrictOrNull() ?: (profile.defaultAddress != null))
        }
        private fun dispatchIfReady() {
            if (!current() || !ready || !window.busy || window.dispatched) return
            window.timeout(now())?.let { finishRequest(false, it); return }
            if (PressWidgetProvider.deviceId(this@WidgetPressService, widgetId) != profile.id ||
                loadProfiles().firstOrNull { it.id == profile.id } != profile || readSetting(profile.pskStoreKey) != key ||
                readSetting("${profile.pskStoreKey}_pending_change") != null ||
                (readSetting("require_auth") != "false" && !authenticated)) {
                finishRequest(false, "Not sent — device setup changed; tap again")
                return
            }
            if (window.claim(now())) { scheduleCheck(); publish("Sending…"); client?.press() }
        }
        private fun finishRequest(success: Boolean, result: String) {
            if (!window.busy) return
            val wasSent = window.dispatched
            val duration = BackgroundConnectionDuration.fromSaved(readSetting(BackgroundConnectionDuration.STORE_KEY))
            window.complete(now(), duration.milliseconds)
            log("Widget action: $result")
            if (success && wasSent) {
                EventLog.addSessionPress(this@WidgetPressService, "${profile.displayName} remote button pressed (widget)", session, profile.id, profile.displayName)
                if (readSetting(profile.recordLocationStoreKey) == "true") OperationLocationRecorder.capture(this@WidgetPressService, profile, session)
                if (duration == BackgroundConnectionDuration.OFF) {
                    publish("Pressed • disconnected")
                    window.cancel()
                    closeClient()
                } else {
                    publish("Pressed • ready for ${duration.label}")
                    scheduleCheck()
                }
                val owned = generation
                val completedSession = session
                feedbackReset = Runnable {
                    feedbackReset = null
                    if (!current() || owned != generation || completedSession != session || window.busy) return@Runnable
                    if (duration == BackgroundConnectionDuration.OFF) end("Tap to press")
                    else publish("Ready • ${duration.label}")
                }.also { handler.postDelayed(it, 3_000) }
            } else end(if (wasSent) "Unable to confirm — check the device" else result)
        }
        fun log(value: String) = EventLog.add(this@WidgetPressService, EventLog.Kind.DIAGNOSTIC,
            "Widget ${profile.displayName}: $value", deviceId = profile.id, deviceName = profile.displayName)
        private fun publish(value: String) {
            message = value
            PressWidgetProvider.publish(this@WidgetPressService, profile.id, value, window.busy, window.cancellationId)
            foreground()
        }
        private fun clearFeedback() { feedbackReset?.let(handler::removeCallbacks); feedbackReset = null }
        private fun closeClient() {
            generation++ // Invalidate ownership before synchronous teardown callbacks.
            val old = client; client = null; ready = false
            old?.stop()
            PressWidgetProvider.connection(this@WidgetPressService, profile.id, "widget", false)
        }
        fun end(status: String, updateService: Boolean = true) {
            if (!current()) return
            sessions.remove(profile.id)
            window.cancel()
            handler.removeCallbacks(tick)
            clearFeedback()
            closeClient()
            PressWidgetProvider.publish(this@WidgetPressService, profile.id, status)
            if (updateService) { if (sessions.isEmpty()) stopIfIdle() else foreground() }
        }
    }
    private fun stopIfIdle() { if (sessions.isEmpty()) stopSelf(lastStartId) }
    private fun foreground(): Boolean {
        val channel = "widget_ble_connection"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(channel, "Widget Bluetooth connection", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val owners = sessions.values.toList()
        val text = owners.joinToString(" • ") { "${it.profile.displayName}: ${it.message}" }.ifEmpty { "Connecting…" }
        val notification = NotificationCompat.Builder(this, channel).setSmallIcon(R.drawable.ic_key_notification)
            .setContentTitle(if (owners.size == 1) owners.single().profile.displayName else "Remote Key widgets")
            .setContentText(text).setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(open).setOngoing(true).setSilent(true)
        owners.filter { !it.window.dispatched }.take(3).forEach { owner ->
            val action = if (owner.window.busy) "cancel" else "close"
            val actionIntent = cancellationIntent(this, owner.profile.id, owner.session).setAction(action)
                .setData(Uri.parse("remotekey://widget-action/$action/${owner.session}"))
            val pending = if (Build.VERSION.SDK_INT >= 26) PendingIntent.getForegroundService(this, 1,
                actionIntent, PendingIntent.FLAG_IMMUTABLE)
            else PendingIntent.getService(this, 1, actionIntent, PendingIntent.FLAG_IMMUTABLE)
            notification.addAction(0, "${if (owner.window.busy) "Cancel" else "Disconnect"} ${owner.profile.displayName}", pending)
        }
        return try { startForeground(261, notification.build()); true } catch (_: RuntimeException) { false }
    }
    override fun onDestroy() {
        sessions.values.toList().forEach { it.end("Tap to press", updateService = false) }
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
