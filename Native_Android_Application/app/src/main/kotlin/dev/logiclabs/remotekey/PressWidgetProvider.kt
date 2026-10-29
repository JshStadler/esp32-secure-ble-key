package dev.logiclabs.remotekey

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.graphics.drawable.Icon
import android.widget.RemoteViews
import android.view.View
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

class PressWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        ids.forEach { render(context, it) }
    }
    override fun onDeleted(context: Context, ids: IntArray) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        ids.forEach { prefs.edit().remove(it.toString()).remove("${it}_icon").apply() }
    }
    override fun onAppWidgetOptionsChanged(context: Context, manager: AppWidgetManager, id: Int, options: android.os.Bundle) {
        render(context, id)
    }
    companion object {
        private const val PREFS = "press_widgets"
        private data class Status(val message: String, val busy: Boolean, val cancellationId: String?, val expires: Long)
        private val statuses = mutableMapOf<String, Status>()
        private val connections = mutableMapOf<String, MutableSet<String>>()
        private val resets = mutableMapOf<String, Runnable>()
        private val handler = Handler(Looper.getMainLooper())
        internal fun isConnected(profileId: String) = connections[profileId]?.isNotEmpty() == true
        fun connection(context: Context, profileId: String, owner: String, connected: Boolean) {
            val owners = connections.getOrPut(profileId) { mutableSetOf() }
            val changed = if (connected) owners.add(owner) else owners.remove(owner)
            if (owners.isEmpty()) connections.remove(profileId)
            if (changed) refresh(context, profileId)
        }
        private fun refresh(context: Context, profileId: String) {
            AppWidgetManager.getInstance(context).getAppWidgetIds(ComponentName(context, PressWidgetProvider::class.java))
                .filter { deviceId(context, it) == profileId }.forEach { render(context, it) }
        }
        internal fun currentMessage(profileId: String): String {
            val status = statuses[profileId]?.takeIf { it.expires > SystemClock.elapsedRealtime() }
            return status?.message?.takeUnless { (it == "Tap to press" && isConnected(profileId)) || (it.startsWith("Ready") && !isConnected(profileId)) }
                ?: if (isConnected(profileId)) "Connected" else "Tap to press"
        }
        private fun record(context: Context, profileId: String, message: String, busy: Boolean, cancellationId: String?) {
            resets.remove(profileId)?.let(handler::removeCallbacks)
            val result = WidgetStatusText.tone(message) in listOf(WidgetStatusText.Tone.CONFIRMED, WidgetStatusText.Tone.ERROR)
            val status = Status(message, busy, cancellationId, if (result) SystemClock.elapsedRealtime() + 3_000 else Long.MAX_VALUE)
            statuses[profileId] = status
            if (result) {
                val app = context.applicationContext
                resets[profileId] = Runnable {
                    resets.remove(profileId)
                    if (statuses[profileId] === status) { statuses.remove(profileId); refresh(app, profileId) }
                }.also { handler.postDelayed(it, 3_000) }
            }
        }
        internal fun isBusy(profileId: String) = statuses[profileId]?.busy == true
        fun refreshAll(context: Context) {
            AppWidgetManager.getInstance(context).getAppWidgetIds(ComponentName(context, PressWidgetProvider::class.java))
                .forEach { render(context, it) }
        }
        fun deviceId(context: Context, widgetId: Int): String? {
            val info = AppWidgetManager.getInstance(context).getAppWidgetInfo(widgetId) ?: return null
            if (info.provider != ComponentName(context, PressWidgetProvider::class.java)) return null
            return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(widgetId.toString(), null)
        }
        internal fun icon(context: Context, widgetId: Int, type: BleDeviceType?): PressWidgetIcon =
            PressWidgetIcon.saved(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("${widgetId}_icon", null), type)
        internal fun configure(context: Context, widgetId: Int, profileId: String, icon: PressWidgetIcon) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(widgetId.toString(), profileId).putString("${widgetId}_icon", icon.name).apply()
            render(context, widgetId)
        }
        fun publish(context: Context, profileId: String, message: String, busy: Boolean = false, cancellationId: String? = null) {
            record(context, profileId, message, busy, cancellationId)
            refresh(context, profileId)
        }
        fun render(context: Context, widgetId: Int, message: String? = null, busy: Boolean? = null) {
            val profileId = deviceId(context, widgetId)
            if (profileId != null && message != null) record(context, profileId, message, busy ?: false, null)
            val profile = DeviceProfileRepository(SecureStore(context)).load().firstOrNull { it.id == profileId }
            val current = statuses[profileId]
            val displayedMessage = message ?: profileId?.let(::currentMessage) ?: "Tap to press"
            val working = busy ?: current?.busy ?: false
            val options = AppWidgetManager.getInstance(context).getAppWidgetOptions(widgetId)
            val compact = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT) < 150 ||
                options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH) < 150
            AppWidgetManager.getInstance(context).updateAppWidget(widgetId,
                views(context, widgetId, profile, displayedMessage, working, compact,
                    if (message == null && working) current?.cancellationId else null, profileId?.let(::isConnected) == true))
        }
        internal fun views(context: Context, widgetId: Int, profile: BleDeviceProfile?, displayedMessage: String,
            working: Boolean, compact: Boolean, cancellationId: String? = null, connected: Boolean = false): RemoteViews {
            val tone = WidgetStatusText.tone(displayedMessage, connected)
            val intent = if (profile == null) Intent(context, PressWidgetConfigureActivity::class.java)
                else Intent(context, WidgetPressActivity::class.java)
            intent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
            intent.data = Uri.parse("remotekey://widget/$widgetId/${if (profile == null) "configure" else "press"}")
            val canCancel = working && profile != null && cancellationId != null && android.os.Build.VERSION.SDK_INT >= 26
            val click = if (canCancel) PendingIntent.getForegroundService(context, widgetId,
                WidgetPressService.cancellationIntent(context, profile!!.id, cancellationId!!), PendingIntent.FLAG_IMMUTABLE)
            else PendingIntent.getActivity(context, widgetId, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            return RemoteViews(context.packageName, R.layout.press_widget).apply {
                val compactFeedback = compact && profile != null && WidgetStatusText.replacesCompactName(displayedMessage)
                setTextViewText(R.id.widget_name, profile?.displayName ?: "Remote Key")
                setInt(R.id.widget_name, "setMaxLines", if (compact) 1 else 2)
                setTextViewTextSize(R.id.widget_name, android.util.TypedValue.COMPLEX_UNIT_SP, if (compactFeedback) 12f else 14f)
                setViewVisibility(R.id.widget_status, if (compact) View.GONE else View.VISIBLE)
                if (compactFeedback) setTextViewText(R.id.widget_name, WidgetStatusText.compactLabel(displayedMessage))
                setInt(R.id.widget_press, "setBackgroundResource", tone.background)
                setImageViewIcon(R.id.widget_icon, Icon.createWithResource(context, icon(context, widgetId, profile?.type).drawable).setTint(tone.accent))
                setTextColor(R.id.widget_status, tone.accent)
                setTextViewText(R.id.widget_status, if (profile == null) "Choose a device" else WidgetStatusText.label(displayedMessage))
                // The launcher caches RemoteViews across process death. A cached
                // disabled target could otherwise stay unusable after a crash.
                // Waiting taps cancel their specific request; sent-command taps are ignored.
                setBoolean(R.id.widget_press, "setEnabled", true)
                setOnClickPendingIntent(R.id.widget_press, click)
                val action = if (canCancel) "Tap to cancel before sending" else if (working) "Already sending; cannot cancel" else "Tap to press"
                setContentDescription(R.id.widget_press, "${profile?.displayName ?: "Remote Key"}: $displayedMessage. $action")
            }
        }
    }
}
