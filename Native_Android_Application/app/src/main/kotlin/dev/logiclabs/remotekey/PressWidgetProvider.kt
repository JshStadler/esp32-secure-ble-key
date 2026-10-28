package dev.logiclabs.remotekey

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.RemoteViews
import android.view.View

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
        private val statuses = mutableMapOf<String, Pair<String, Boolean>>()
        internal fun isBusy(profileId: String) = statuses[profileId]?.second == true
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
        fun publish(context: Context, profileId: String, message: String, busy: Boolean = false) {
            statuses[profileId] = message to busy
            AppWidgetManager.getInstance(context).getAppWidgetIds(ComponentName(context, PressWidgetProvider::class.java))
                .filter { deviceId(context, it) == profileId }.forEach { render(context, it, message, busy) }
        }
        fun render(context: Context, widgetId: Int, message: String? = null, busy: Boolean? = null) {
            val profileId = deviceId(context, widgetId)
            val profile = DeviceProfileRepository(SecureStore(context)).load().firstOrNull { it.id == profileId }
            val current = statuses[profileId]
            val displayedMessage = message ?: current?.first ?: "Tap to press"
            val working = busy ?: current?.second ?: false
            val options = AppWidgetManager.getInstance(context).getAppWidgetOptions(widgetId)
            val compact = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT) < 150 ||
                options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH) < 150
            val intent = if (profile == null) Intent(context, PressWidgetConfigureActivity::class.java)
                else Intent(context, WidgetPressActivity::class.java)
            intent.putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, widgetId)
            intent.data = Uri.parse("remotekey://widget/$widgetId/${if (profile == null) "configure" else "press"}")
            val click = PendingIntent.getActivity(context, widgetId, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val views = RemoteViews(context.packageName, R.layout.press_widget).apply {
                setTextViewText(R.id.widget_name, profile?.displayName ?: "Remote Key")
                setInt(R.id.widget_name, "setMaxLines", if (compact) 1 else 2)
                setViewVisibility(R.id.widget_status, if (compact) View.GONE else View.VISIBLE)
                if (compact && working) setTextViewText(R.id.widget_name, "Working…")
                setImageViewResource(R.id.widget_icon, icon(context, widgetId, profile?.type).drawable)
                setTextViewText(R.id.widget_status, if (profile == null) "Choose a device" else WidgetStatusText.label(displayedMessage))
                // The launcher caches RemoteViews across process death. A cached
                // disabled target could otherwise stay unusable after a crash.
                // Live busy taps are rejected by the activity and service.
                setBoolean(R.id.widget_press, "setEnabled", true)
                setOnClickPendingIntent(R.id.widget_press, click)
                setContentDescription(R.id.widget_press, "${profile?.displayName ?: "Remote Key"}: $displayedMessage. ${if (working) "Working" else "Tap to press"}")
            }
            AppWidgetManager.getInstance(context).updateAppWidget(widgetId, views)
        }
    }
}
