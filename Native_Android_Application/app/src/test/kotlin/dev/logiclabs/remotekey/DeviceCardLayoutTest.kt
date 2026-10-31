package dev.logiclabs.remotekey

import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.view.ContextThemeWrapper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Robolectric
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class DeviceCardLayoutTest {
    @Test fun actualDashboardDoesNotConstrainTheCardHeightAtLargeScaling() {
        RuntimeEnvironment.setQualifiers("w320dp-h480dp-mdpi")
        RuntimeEnvironment.setFontScale(2f)
        Robolectric.buildActivity(MainActivity::class.java).use { controller ->
            val activity = controller.create().get()
            val profilesField = MainActivity::class.java.getDeclaredField("profiles").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val profiles = profilesField.get(activity) as MutableList<BleDeviceProfile>
            profiles.add(BleDeviceProfiles.create(BleDeviceType.ESPHOME_ACCESS, displayName = "ESPHome device"))
            val build = MainActivity::class.java.getDeclaredMethod("buildUi").apply { isAccessible = true }
            val root = build.invoke(activity) as View
            root.measure(View.MeasureSpec.makeMeasureSpec(320, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(480, View.MeasureSpec.EXACTLY))
            root.layout(0, 0, 320, 480)
            val card = descendants(root).filterIsInstance<DeviceCardLayout>().single()
            val status = descendants(card).filterIsInstance<TextView>().first { it.text == "Idle" }
            status.text = "Closed • Connected"
            root.measure(View.MeasureSpec.makeMeasureSpec(320, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(480, View.MeasureSpec.EXACTLY))
            root.layout(0, 0, 320, 480)
            val action = descendants(card).filterIsInstance<Button>().single()
            assertEquals(LinearLayout.VERTICAL, card.orientation)
            assertTrue(card.height > 108)
            assertTrue(status.layout.height <= status.height - status.compoundPaddingTop - status.compoundPaddingBottom)
            assertTrue(action.bottom <= card.height - card.paddingBottom)
            savePreview(card, "dashboard-card-2.0")
        }
    }

    @Test fun narrowCardsAtLargeTextSizesKeepAllStatusLinesAndActionVisible() {
        listOf(1f, 1.3f, 1.5f, 2f).forEach { scale ->
            listOf(280, 320, 380).forEach { width ->
                val fixture = card(scale, width)
                assertFullyVisible(fixture)
                if (scale == 2f && width == 280) {
                    assertEquals(LinearLayout.VERTICAL, fixture.card.orientation)
                    assertTrue(fixture.action.top >= fixture.details.bottom)
                }
                if (width == 320) savePreview(fixture, scale)
            }
        }
    }

    @Test fun ordinarySizeKeepsTheCompactSideBySideAction() {
        val fixture = card(1f, 380)
        assertEquals(LinearLayout.HORIZONTAL, fixture.card.orientation)
        assertFullyVisible(fixture)
        assertTrue(fixture.action.left >= fixture.details.right)
    }

    @Test fun changingStatusRemeasuresTheCardInsteadOfClippingExtraLines() {
        val fixture = card(2f, 280)
        val oldHeight = fixture.card.height
        fixture.status.text = "Reconnecting…\nLast state: Closed\nUnable to confirm — check the device"
        measure(fixture.card, fixture.width)
        assertTrue(fixture.card.height > oldHeight)
        assertFullyVisible(fixture)
    }

    private data class Fixture(val card: DeviceCardLayout, val details: LinearLayout,
        val labels: LinearLayout, val title: TextView, val status: TextView, val action: Button, val width: Int)

    private fun card(scale: Float, widthDp: Int): Fixture {
        val app = RuntimeEnvironment.getApplication()
        val configuration = Configuration(app.resources.configuration).apply { fontScale = scale }
        val context = ContextThemeWrapper(app.createConfigurationContext(configuration), R.style.Theme_CarKey)
        fun dp(value: Int) = (value * context.resources.displayMetrics.density).toInt()
        val details = LinearLayout(context).apply { gravity = android.view.Gravity.CENTER_VERTICAL }
        details.addView(ImageView(context).apply { setImageResource(R.drawable.ic_gate) }, LinearLayout.LayoutParams(dp(48), dp(48)))
        val labels = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14), 0, dp(8), 0) }
        val title = TextView(context).apply { text = "ESPHome device"; textSize = 17f; setTextColor(Color.WHITE) }
        val status = TextView(context).apply { text = "Closed • Connected"; textSize = 13f; setTextColor(Color.LTGRAY) }
        labels.addView(title); labels.addView(status)
        details.addView(labels, LinearLayout.LayoutParams(0, -2, 1f))
        val action = Button(context).apply { text = "Cancel"; isAllCaps = false; textSize = 14f; setPadding(dp(12), dp(10), dp(12), dp(10)) }
        val card = DeviceCardLayout(context, details, action, status).apply { setBackgroundColor(Color.rgb(31, 34, 48)) }
        measure(card, dp(widthDp))
        return Fixture(card, details, labels, title, status, action, dp(widthDp))
    }

    private fun measure(view: View, width: Int) {
        view.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED))
        view.layout(0, 0, view.measuredWidth, view.measuredHeight)
    }

    private fun assertFullyVisible(f: Fixture) {
        assertTrue(f.title.layout.height <= f.title.height - f.title.compoundPaddingTop - f.title.compoundPaddingBottom)
        assertTrue(f.status.layout.height <= f.status.height - f.status.compoundPaddingTop - f.status.compoundPaddingBottom)
        assertEquals(f.status.layout.lineCount, f.status.layout.getLineForOffset(f.status.length()) + 1)
        assertTrue(f.labels.bottom <= f.details.height)
        assertTrue(f.details.bottom <= f.card.height - f.card.paddingBottom)
        assertTrue(f.action.right <= f.card.width - f.card.paddingRight)
        assertTrue(f.action.bottom <= f.card.height - f.card.paddingBottom)
        assertTrue(f.action.layout.height <= f.action.height - f.action.compoundPaddingTop - f.action.compoundPaddingBottom)
    }

    private fun savePreview(f: Fixture, scale: Float) {
        savePreview(f.card, "card-$scale")
    }

    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()

    private fun savePreview(view: View, name: String) {
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        view.draw(Canvas(bitmap))
        val file = File(System.getProperty("blekey.layoutReportsDir"), "$name.png").apply { parentFile?.mkdirs() }
        file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }
}
