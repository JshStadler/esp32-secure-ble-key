package dev.logiclabs.remotekey

import android.app.Service
import android.appwidget.AppWidgetManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.view.View
import android.widget.Button
import android.widget.TextView
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class WidgetAndroidTest {
    @Test fun normalWidgetsUseBlackWhenDisconnectedAndBlueWhenConnected() {
        val context = RuntimeEnvironment.getApplication()
        listOf(false, true).forEach { connected ->
            val message = if (connected) "Connected" else "Tap to press"
            val view = PressWidgetProvider.views(context, 123, BleDeviceProfiles.GATE, message, false, false, connected = connected)
                .apply(context, android.widget.FrameLayout(context))
            view.measure(View.MeasureSpec.makeMeasureSpec(180, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(160, View.MeasureSpec.EXACTLY))
            view.layout(0, 0, 180, 160)
            val bitmap = android.graphics.Bitmap.createBitmap(180, 160, android.graphics.Bitmap.Config.ARGB_8888)
            view.draw(android.graphics.Canvas(bitmap))
            assertEquals(android.graphics.Color.parseColor(if (connected) "#213854" else "#000000"), bitmap.getPixel(20, 20))
            val file = java.io.File(System.getProperty("blekey.layoutReportsDir"), "widget-connected-$connected.png").apply { parentFile?.mkdirs() }
            file.outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
            bitmap.recycle()
        }
    }
    @Test fun resultsClearAfterThreeSecondsAndTheRemainingConnectionDeterminesTheColour() {
        val context = RuntimeEnvironment.getApplication()
        PressWidgetProvider.connection(context, "gate", "app", true)
        PressWidgetProvider.connection(context, "gate", "widget", true)
        PressWidgetProvider.publish(context, "gate", "Pressed • ready for 2 minutes")
        PressWidgetProvider.connection(context, "gate", "widget", false)
        assertTrue(PressWidgetProvider.currentMessage("gate").startsWith("Pressed"))
        shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(3))
        assertEquals("Connected", PressWidgetProvider.currentMessage("gate"))
        assertEquals(WidgetStatusText.Tone.CONNECTED, WidgetStatusText.tone("Connected", PressWidgetProvider.isConnected("gate")))
        PressWidgetProvider.connection(context, "gate", "app", false)
        PressWidgetProvider.publish(context, "gate", "Not sent — connection timed out")
        shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(3))
        assertEquals("Tap to press", PressWidgetProvider.currentMessage("gate"))
        assertEquals(WidgetStatusText.Tone.IDLE, WidgetStatusText.tone("Tap to press", PressWidgetProvider.isConnected("gate")))
    }
    @Test fun anOldFeedbackResetCannotClearANewerPendingPress() {
        val context = RuntimeEnvironment.getApplication()
        PressWidgetProvider.publish(context, "gate", "Not sent — connection timed out")
        shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(2))
        PressWidgetProvider.publish(context, "gate", "Connecting…", true, "new-request")
        shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(2))
        assertEquals("Connecting…", PressWidgetProvider.currentMessage("gate"))
        assertTrue(PressWidgetProvider.isBusy("gate"))
    }
    @Test fun aCachedWaitingWidgetCanOnlyCancelTheRequestItDisplayed() {
        val context = RuntimeEnvironment.getApplication()
        val host = android.widget.FrameLayout(context)
        val first = PressWidgetProvider.views(context, 123, BleDeviceProfiles.GATE, "Connecting…", true, true, "request-a").apply(context, host)
        val second = PressWidgetProvider.views(context, 123, BleDeviceProfiles.GATE, "Connecting…", true, true, "request-b").apply(context, host)
        assertTrue(first.contentDescription.toString().contains("Tap to cancel before sending"))
        assertTrue(first.performClick())
        val oldCancel = shadowOf(context).nextStartedService
        assertEquals("cancel", oldCancel.action)
        assertEquals("request-a", oldCancel.getStringExtra("cancel_request_id"))
        assertEquals("gate", oldCancel.getStringExtra("cancel_profile_id"))
        assertTrue(second.performClick())
        val newCancel = shadowOf(context).nextStartedService
        assertEquals("request-b", newCancel.getStringExtra("cancel_request_id"))
        assertNotEquals(oldCancel.data, newCancel.data)
        assertNull(shadowOf(context).nextStartedActivity)
    }
    @Test fun tappingAnOldWaitingWidgetAfterProcessDeathCannotStartABlePress() {
        val controller = Robolectric.buildService(WidgetPressService::class.java)
        try {
            val service = controller.create().get()
            assertEquals(Service.START_NOT_STICKY, service.onStartCommand(
                WidgetPressService.cancellationIntent(service, "gate", "expired-request"), 0, 1))
            assertTrue(shadowOf(service).isStoppedBySelf)
        } finally { controller.destroy() }
    }
    @Test fun actualRemoteViewsShowDistinctProgressAndConfirmationOnCompactAndLargeWidgets() {
        val context = RuntimeEnvironment.getApplication()
        val phases = listOf("Connecting…", "Sending…", "Pressed • ready for 2 minutes", "Ready • 2 minutes", "Unable to confirm — check the device", "Not sent — connection timed out", "Canceled before sending")
        listOf(1f, 2f).forEach { scale ->
            RuntimeEnvironment.setQualifiers("w360dp-h640dp-mdpi")
            RuntimeEnvironment.setFontScale(scale)
            listOf(true, false).forEach { compact ->
                phases.forEachIndexed { index, message ->
                    val views = PressWidgetProvider.views(context, 123, BleDeviceProfiles.GATE, message, index < 2, compact)
                    val view = views.apply(context, android.widget.FrameLayout(context))
                    val width = if (compact) 96 else 180
                    val height = if (compact) 112 else 160
                    view.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY))
                    view.layout(0, 0, width, height)
                    val name = view.findViewById<TextView>(R.id.widget_name)
                    val status = view.findViewById<TextView>(R.id.widget_status)
                    assertEquals(if (compact && WidgetStatusText.replacesCompactName(message)) WidgetStatusText.compactLabel(message) else "Gate", name.text.toString())
                    if (compact) assertEquals("Compact feedback ($message, font $scale) must be readable", 0, name.layout.getEllipsisCount(0))
                    assertEquals(if (compact) View.GONE else View.VISIBLE, status.visibility)
                    assertEquals(WidgetStatusText.tone(message).accent, status.currentTextColor)
                    assertTrue(name.bottom <= height - view.paddingBottom)
                    if (!compact) assertTrue(status.bottom <= height - view.paddingBottom)
                    val bitmap = android.graphics.Bitmap.createBitmap(width, height, android.graphics.Bitmap.Config.ARGB_8888)
                    view.draw(android.graphics.Canvas(bitmap))
                    val file = java.io.File(System.getProperty("blekey.layoutReportsDir"), "widget-feedback-$compact-$scale-$index.png").apply { parentFile?.mkdirs() }
                    file.outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
                    bitmap.recycle()
                }
            }
        }
    }
    @Test fun launcherCanApplyProductionRemoteViewsAndKeepEachWidgetConfigurationSeparate() {
        val context = RuntimeEnvironment.getApplication()
        val manager = AppWidgetManager.getInstance(context)
        val shadow = shadowOf(manager)
        val first = shadow.createWidget(PressWidgetProvider::class.java, R.layout.press_widget)
        val second = shadow.createWidget(PressWidgetProvider::class.java, R.layout.press_widget)
        listOf(first, second).forEach { id ->
            shadow.putWidgetInfo(id, android.appwidget.AppWidgetProviderInfo().apply {
                provider = ComponentName(context, PressWidgetProvider::class.java)
            })
        }
        PressWidgetProvider.configure(context, first, "gate", PressWidgetIcon.DOOR)
        PressWidgetProvider.configure(context, second, "car", PressWidgetIcon.CAR)
        assertEquals("gate", PressWidgetProvider.deviceId(context, first))
        assertEquals("car", PressWidgetProvider.deviceId(context, second))
        assertEquals(PressWidgetIcon.DOOR, PressWidgetProvider.icon(context, first, BleDeviceType.ESPHOME_ACCESS))
        assertEquals(PressWidgetIcon.CAR, PressWidgetProvider.icon(context, second, BleDeviceType.CAR))
        manager.updateAppWidgetOptions(first, android.os.Bundle().apply {
            putInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH, 180)
            putInt(AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT, 160)
        })
        PressWidgetProvider.render(context, first)
        val view = shadow.getViewFor(first)
        assertNotNull(view.findViewById<android.widget.ImageView>(R.id.widget_icon).drawable)
        assertTrue(view.findViewById<View>(R.id.widget_press).isEnabled)
        // This host applies the smallest responsive fallback before measuring.
        // Larger layouts and their text are exercised at explicit sizes above.
        assertEquals(View.GONE, view.findViewById<View>(R.id.widget_status).visibility)
    }
    @Test @Config(sdk = [28]) fun widgetsAreNotOfferedWhereBackgroundScanNeedsAdditionalPermissions() {
        assertFalse(RuntimeEnvironment.getApplication().resources.getBoolean(R.bool.press_widget_supported))
    }
    @Test fun widgetsAreOfferedOnModernAndroid() {
        assertTrue(RuntimeEnvironment.getApplication().resources.getBoolean(R.bool.press_widget_supported))
    }
    @Test fun widgetActionAndServiceAreNotExternallyExported() {
        val context = RuntimeEnvironment.getApplication()
        val pm = context.packageManager
        assertFalse(pm.getActivityInfo(ComponentName(context, WidgetPressActivity::class.java), 0).exported)
        assertFalse(pm.getServiceInfo(ComponentName(context, WidgetPressService::class.java), 0).exported)
        assertFalse(pm.getReceiverInfo(ComponentName(context, PressWidgetProvider::class.java), 0).exported)
    }
    @Test fun anInvalidWidgetCannotAuthorizeACommand() {
        Robolectric.buildActivity(WidgetPressActivity::class.java,
            Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, 999)).use { controller ->
            val activity = controller.create().get()
            assertTrue(activity.isFinishing)
            assertNull(shadowOf(activity).nextStartedService)
        }
    }
    @Test fun recreatedActionsDoNotStartTheForegroundServiceAgain() {
        Robolectric.buildActivity(WidgetPressActivity::class.java).use { controller ->
            val activity = controller.create(android.os.Bundle()).get()
            assertTrue(activity.isFinishing)
            assertNull(shadowOf(activity).nextStartedService)
        }
    }
    @Test fun aMissingOrRedeliveredServiceRequestCannotCreateBleWork() {
        val controller = Robolectric.buildService(WidgetPressService::class.java)
        try {
            val service = controller.create().get()
            assertEquals(Service.START_NOT_STICKY, service.onStartCommand(null, 0, 1))
            assertTrue(shadowOf(service).isStoppedBySelf)
        } finally { controller.destroy() }
    }
    @Test fun widgetActionFitsAtLargeTextSizes() {
        listOf(1f, 1.5f, 2f).forEach { scale ->
            RuntimeEnvironment.setQualifiers("w360dp-h640dp-mdpi")
            RuntimeEnvironment.setFontScale(scale)
            val context = android.view.ContextThemeWrapper(RuntimeEnvironment.getApplication(), R.style.Theme_CarKey)
            val view = android.view.LayoutInflater.from(context).inflate(R.layout.press_widget, null)
            val action = view.findViewById<View>(R.id.widget_press)
            val name = view.findViewById<TextView>(R.id.widget_name).apply { text = "ESPHome device" }
            view.findViewById<android.widget.ImageView>(R.id.widget_icon).setImageResource(PressWidgetIcon.GATE.drawable)
            view.findViewById<TextView>(R.id.widget_status).text = WidgetStatusText.label("Pressed • ready for 30s")
            view.measure(View.MeasureSpec.makeMeasureSpec(180, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(160, View.MeasureSpec.EXACTLY))
            view.layout(0, 0, 180, 160)
            assertEquals(160, action.height)
            assertTrue(action.height >= 48)
            assertTrue(name.layout.height <= name.height - name.compoundPaddingTop - name.compoundPaddingBottom)
            val status = view.findViewById<TextView>(R.id.widget_status)
            assertTrue(status.bottom <= 160 - view.paddingBottom)
            val bitmap = android.graphics.Bitmap.createBitmap(180, 160, android.graphics.Bitmap.Config.ARGB_8888)
            view.draw(android.graphics.Canvas(bitmap))
            val file = java.io.File(System.getProperty("blekey.layoutReportsDir"), "widget-$scale.png").apply { parentFile?.mkdirs() }
            file.outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
            bitmap.recycle()
        }
    }
    @Test fun compactIconWidgetFitsAtLargeTextSizes() {
        RuntimeEnvironment.setQualifiers("w360dp-h640dp-mdpi")
        RuntimeEnvironment.setFontScale(2f)
        val context = android.view.ContextThemeWrapper(RuntimeEnvironment.getApplication(), R.style.Theme_CarKey)
        val view = android.view.LayoutInflater.from(context).inflate(R.layout.press_widget, null)
        view.findViewById<TextView>(R.id.widget_status).visibility = View.GONE
        val name = view.findViewById<TextView>(R.id.widget_name).apply { text = "Gate"; maxLines = 1 }
        view.measure(View.MeasureSpec.makeMeasureSpec(72, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(96, View.MeasureSpec.EXACTLY))
        view.layout(0, 0, 72, 96)
        assertTrue(name.bottom <= view.height - view.paddingBottom)
        assertTrue(name.layout.height <= name.height - name.compoundPaddingTop - name.compoundPaddingBottom)
    }
    @Test fun singleCellLayoutFitsAt48DpWithLargeTextAndKeepsProgressAndCancellation() {
        RuntimeEnvironment.setQualifiers("w360dp-h640dp-mdpi")
        RuntimeEnvironment.setFontScale(2f)
        val context = RuntimeEnvironment.getApplication()
        val phases = listOf("Tap to press", "Connected", "Connecting…", "Sending…", "Pressed • ready for 30s", "Not sent — connection timed out")
        phases.forEachIndexed { index, message ->
            val waiting = message.startsWith("Connecting")
            val busy = waiting || message.startsWith("Sending")
            val view = PressWidgetProvider.views(context, 123, BleDeviceProfiles.GATE, message, busy, true,
                if (waiting) "one-cell-request" else null, connected = message == "Connected", iconOnly = true)
                .apply(context, android.widget.FrameLayout(context))
            view.measure(View.MeasureSpec.makeMeasureSpec(48, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(48, View.MeasureSpec.EXACTLY))
            view.layout(0, 0, 48, 48)
            assertEquals(View.GONE, view.findViewById<TextView>(R.id.widget_name).visibility)
            assertEquals(View.GONE, view.findViewById<TextView>(R.id.widget_status).visibility)
            val icon = view.findViewById<View>(R.id.widget_icon)
            assertTrue(icon.left >= view.paddingLeft && icon.right <= 48 - view.paddingRight)
            assertTrue(icon.top >= view.paddingTop && icon.bottom <= 48 - view.paddingBottom)
            val badge = view.findViewById<android.widget.ImageView>(R.id.widget_badge)
            assertEquals(if (index >= 2) View.VISIBLE else View.GONE, badge.visibility)
            if (badge.visibility == View.VISIBLE) {
                assertNotNull(badge.drawable)
                assertTrue(badge.right <= 48 - view.paddingRight && badge.bottom <= 48 - view.paddingBottom)
            }
            assertTrue(view.contentDescription.toString().contains(message))
            if (waiting) {
                assertTrue(view.performClick())
                val cancel = shadowOf(context).nextStartedService
                assertEquals("cancel", cancel.action)
                assertEquals("gate", cancel.getStringExtra("cancel_profile_id"))
                assertEquals("one-cell-request", cancel.getStringExtra("cancel_request_id"))
            }
            val bitmap = android.graphics.Bitmap.createBitmap(48, 48, android.graphics.Bitmap.Config.ARGB_8888)
            view.draw(android.graphics.Canvas(bitmap))
            val file = java.io.File(System.getProperty("blekey.layoutReportsDir"), "widget-1x1-$index.png").apply { parentFile?.mkdirs() }
            file.outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
            bitmap.recycle()
        }
    }
}
