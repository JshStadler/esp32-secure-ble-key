package dev.logiclabs.remotekey

import android.app.AlertDialog
import android.app.Activity
import android.appwidget.AppWidgetManager
import android.content.ComponentName
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.view.View
import android.widget.FrameLayout
import android.widget.TextView
import androidx.core.graphics.ColorUtils
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.shadows.ShadowAlertDialog

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class WidgetColourTest {
    private fun widget(): Int {
        val app = RuntimeEnvironment.getApplication()
        val manager = shadowOf(AppWidgetManager.getInstance(app))
        return manager.createWidget(PressWidgetProvider::class.java, R.layout.press_widget).also { id ->
            manager.putWidgetInfo(id, android.appwidget.AppWidgetProviderInfo().apply {
                provider = ComponentName(app, PressWidgetProvider::class.java)
            })
            PressWidgetProvider.configure(app, id, "gate", PressWidgetIcon.GATE)
        }
    }
    @Test fun customColourSurvivesUpdatesButNeverOverridesLiveStatusColours() {
        val context = RuntimeEnvironment.getApplication()
        val first = widget(); val second = widget()
        PressWidgetProvider.configure(context, first, "gate", PressWidgetIcon.DOOR, "#ffffff")
        assertEquals("#FFFFFF", PressWidgetProvider.background(context, first))
        assertEquals("#000000", PressWidgetProvider.background(context, second))
        listOf(false, true).forEach { iconOnly ->
            val size = if (iconOnly) 48 else 180
            val host = FrameLayout(context)
            val view = PressWidgetProvider.views(context, first, BleDeviceProfiles.GATE, "Tap to press", false, iconOnly, iconOnly = iconOnly).apply(context, host)
            val phases = listOf("Tap to press" to "#FFFFFF", "Connected" to "#213854", "Connecting…" to "#3D3020", "Tap to press" to "#FFFFFF")
            phases.forEachIndexed { index, (message, colour) ->
                PressWidgetProvider.views(context, first, BleDeviceProfiles.GATE, message, message.startsWith("Connecting"), iconOnly,
                    connected = message == "Connected", iconOnly = iconOnly).reapply(context, view)
                view.measure(View.MeasureSpec.makeMeasureSpec(size, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(size, View.MeasureSpec.EXACTLY))
                view.layout(0, 0, size, size)
                val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
                view.draw(Canvas(bitmap))
                assertEquals("$message ($iconOnly)", Color.parseColor(colour), bitmap.getPixel(size / 2, 6))
                assertEquals("Corners stay rounded", Color.TRANSPARENT, bitmap.getPixel(0, 0))
                if (message == "Tap to press") {
                    assertTrue(ColorUtils.calculateContrast(view.findViewById<TextView>(R.id.widget_name).currentTextColor, Color.WHITE) >= 4.5)
                    assertTrue(ColorUtils.calculateContrast(view.findViewById<TextView>(R.id.widget_status).currentTextColor, Color.WHITE) >= 4.5)
                }
                val file = java.io.File(System.getProperty("blekey.layoutReportsDir"), "widget-colour-$iconOnly-$index.png").apply { parentFile?.mkdirs() }
                file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }; bitmap.recycle()
            }
        }
        PressWidgetProvider().onDeleted(context, intArrayOf(first))
        assertEquals("#000000", PressWidgetProvider.background(context, first))
    }
    @Test fun editingAWidgetOnlySavesValidColoursOnExplicitSave() {
        val app = RuntimeEnvironment.getApplication()
        val id = widget()
        fun edit(save: Boolean) {
            val controller = Robolectric.buildActivity(PressWidgetConfigureActivity::class.java,
                Intent(app, PressWidgetConfigureActivity::class.java).putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, id))
            controller.get().loadProfiles = { listOf(BleDeviceProfiles.GATE, BleDeviceProfiles.CAR) }
            try {
                val activity = controller.create().start().resume().get()
                shadowOf(android.os.Looper.getMainLooper()).idle()
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                val form = PressWidgetConfigureActivity::class.java.getDeclaredField("form").apply { isAccessible = true }.get(activity) as WidgetConfigurationView
                assertEquals("gate", form.selectedProfile.id)
                assertEquals(PressWidgetIcon.GATE, form.selectedIcon)
                form.colourInput.setText("#zzzzzz")
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
                assertFalse(activity.isFinishing)
                assertNotNull(form.colourInput.error)
                assertEquals("#000000", PressWidgetProvider.background(app, id))
                form.colourInput.setText("#d0e4ff")
                assertEquals(Color.BLACK, form.preview.currentTextColor)
                assertEquals("#000000", PressWidgetProvider.background(app, id))
                dialog.getButton(if (save) AlertDialog.BUTTON_POSITIVE else AlertDialog.BUTTON_NEGATIVE).performClick()
                shadowOf(android.os.Looper.getMainLooper()).idle()
                assertEquals(if (save) Activity.RESULT_OK else Activity.RESULT_CANCELED, shadowOf(activity).resultCode)
                assertNull(shadowOf(activity).nextStartedService)
            } finally { controller.pause().stop().destroy() }
        }
        edit(false)
        assertEquals("#000000", PressWidgetProvider.background(app, id))
        edit(true)
        assertEquals("#D0E4FF", PressWidgetProvider.background(app, id))
    }
}
