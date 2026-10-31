package dev.logiclabs.remotekey

import android.app.AlertDialog
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.util.TypedValue
import android.view.View
import android.view.ViewGroup
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
class AppAppearanceTest {
    private fun children(view: View): List<View> = listOf(view) + if (view is ViewGroup)
        (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()

    @Test fun defaultFollowsSystemAndManualThemesOverrideBothSystemModes() {
        val app = RuntimeEnvironment.getApplication()
        assertEquals(Appearance(), AppAppearance.read(app))
        listOf(false, true).forEach { systemDark ->
            RuntimeEnvironment.setQualifiers("w360dp-h800dp-${if (systemDark) "night" else "notnight"}-mdpi")
            AppTheme.entries.forEach { choice ->
                AppAppearance.save(app, Appearance(choice, AppAccent.TEAL))
                Robolectric.buildActivity(LogActivity::class.java).setup().use { controller ->
                    val activity = controller.get()
                    val expectedDark = choice == AppTheme.DARK || choice == AppTheme.SYSTEM && systemDark
                    assertEquals("$systemDark / $choice", expectedDark, AppAppearance.isDark(activity))
                    val colors = AppAppearance.colors(activity)
                    assertEquals(if (expectedDark) Color.BLACK else Color.parseColor("#F7F8FC"), colors.background)
                    val attribute = TypedValue()
                    activity.theme.resolveAttribute(android.R.attr.colorAccent, attribute, true)
                    assertEquals(colors.accent, attribute.data)
                    assertTrue(ColorUtils.calculateContrast(colors.text, colors.background) >= 4.5)
                    assertTrue(ColorUtils.calculateContrast(colors.secondary, colors.surface) >= 4.5)
                    val texts = children(activity.findViewById(android.R.id.content)).filterIsInstance<TextView>()
                    assertTrue(texts.any { it.text == "Logs" && it.currentTextColor == colors.text })
                    assertTrue(texts.any { it.text == "Export" && it.currentTextColor == colors.accent })
                }
            }
        }
    }

    @Test fun everyAccentHasReadableTextAndColoursNativeDialogButtonsInBothThemes() {
        val app = RuntimeEnvironment.getApplication()
        listOf(false, true).forEach { dark ->
            RuntimeEnvironment.setQualifiers("w360dp-h800dp-${if (dark) "night" else "notnight"}-mdpi")
            AppAccent.entries.forEach { accent ->
                AppAppearance.save(app, Appearance(AppTheme.SYSTEM, accent))
                Robolectric.buildActivity(LogActivity::class.java).setup().use { controller ->
                    val activity = controller.get(); val colors = AppAppearance.colors(activity)
                    assertTrue("$accent text", ColorUtils.calculateContrast(colors.onAccent, colors.accent) >= 4.5)
                    assertTrue("$accent links", ColorUtils.calculateContrast(colors.accent, colors.surface) >= 4.5)
                    val dialog = AppAppearance.dialog(activity).setTitle("Device health").setMessage("Connected")
                        .setPositiveButton("Done", null).show()
                    assertEquals(colors.accent, dialog.getButton(AlertDialog.BUTTON_POSITIVE).currentTextColor)
                    dialog.dismiss()
                }
            }
        }
    }

    @Test fun actualDashboardSettingsAndLogsRenderInBothThemesAtLargeFontSizes() {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app.packageManager).setSystemFeature(android.content.pm.PackageManager.FEATURE_BLUETOOTH_LE, true)
        shadowOf(app).grantPermissions(android.Manifest.permission.BLUETOOTH_SCAN, android.Manifest.permission.BLUETOOTH_CONNECT)
        shadowOf(android.bluetooth.BluetoothAdapter.getDefaultAdapter()).setEnabled(true)
        listOf(false, true).forEach { dark ->
            RuntimeEnvironment.setQualifiers("w360dp-h800dp-${if (dark) "night" else "notnight"}-mdpi")
            RuntimeEnvironment.setFontScale(2f)
            AppAppearance.save(app, Appearance(AppTheme.SYSTEM, AppAccent.PURPLE))
            Robolectric.buildActivity(MainActivity::class.java).setup().use { controller ->
                val activity = controller.get()
                fun field(name: String) = MainActivity::class.java.getDeclaredField(name).apply { isAccessible = true }
                field("authenticated").set(activity, true)
                @Suppress("UNCHECKED_CAST")
                val profiles = field("profiles").get(activity) as MutableList<BleDeviceProfile>
                profiles.clear(); profiles.add(BleDeviceProfiles.GATE)
                val runtimeType = MainActivity::class.java.declaredClasses.single { it.simpleName == "DeviceRuntime" }
                @Suppress("UNCHECKED_CAST")
                val runtimes = field("runtimes").get(activity) as MutableMap<String, Any>
                runtimes["gate"] = runtimeType.getDeclaredConstructor().apply { isAccessible = true }.newInstance().also { runtime ->
                    mapOf("ready" to true, "state" to BleCarKeyClient.State.CONNECTED, "deviceState" to "Closed").forEach { (name, value) ->
                        runtimeType.getDeclaredField(name).apply { isAccessible = true }.set(runtime, value)
                    }
                }
                val ui = MainActivity::class.java.getDeclaredMethod("buildUi").apply { isAccessible = true }.invoke(activity) as View
                field("authOverlay").get(activity).let { (it as View).visibility = View.GONE }
                activity.setContentView(ui)
                render(ui, "dashboard-$dark")
                MainActivity::class.java.getDeclaredMethod("showAppSettings").apply { isAccessible = true }.invoke(activity)
                val settings = ShadowAlertDialog.getLatestAlertDialog()
                render(settings.window!!.decorView, "settings-$dark")
                val appearance = children(settings.window!!.decorView).filterIsInstance<TextView>().single { it.text == "Theme and accent colour" }
                assertTrue(appearance.isEnabled)
                settings.dismiss()
                // Open the actual appearance panel without the settings button's
                // unrelated encrypted-credential writes (no Android Keystore here).
                MainActivity::class.java.getDeclaredMethod("showAppearanceSettings").apply { isAccessible = true }.invoke(activity)
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                val picker = children(dialog.window!!.decorView).filterIsInstance<AppearanceSettingsView>().single()
                assertEquals(Appearance(AppTheme.SYSTEM, AppAccent.PURPLE), picker.selection)
                picker.themePicker.setSelection(AppTheme.DARK.ordinal)
                picker.accentPicker.setSelection(AppAccent.ORANGE.ordinal)
                dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
                shadowOf(android.os.Looper.getMainLooper()).idle()
                assertEquals("Cancel does not persist", Appearance(AppTheme.SYSTEM, AppAccent.PURPLE), AppAppearance.read(app))
                MainActivity::class.java.getDeclaredMethod("showAppearanceSettings").apply { isAccessible = true }.invoke(activity)
                val saveDialog = ShadowAlertDialog.getLatestAlertDialog()
                val savePicker = children(saveDialog.window!!.decorView).filterIsInstance<AppearanceSettingsView>().single()
                savePicker.themePicker.setSelection(AppTheme.DARK.ordinal)
                savePicker.accentPicker.setSelection(AppAccent.ORANGE.ordinal)
                saveDialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
                shadowOf(android.os.Looper.getMainLooper()).idle()
                assertEquals("Apply persists", Appearance(AppTheme.DARK, AppAccent.ORANGE), AppAppearance.read(app))
            }
            AppAppearance.save(app, Appearance(AppTheme.SYSTEM, AppAccent.PURPLE))
            Robolectric.buildActivity(LogActivity::class.java).setup().use { render(it.get().window.decorView, "logs-$dark") }
        }
    }
    private fun render(view: View, name: String) {
        view.measure(View.MeasureSpec.makeMeasureSpec(360, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(800, View.MeasureSpec.EXACTLY))
        view.layout(0, 0, 360, 800)
        val bitmap = Bitmap.createBitmap(360, 800, Bitmap.Config.ARGB_8888)
        view.draw(Canvas(bitmap))
        val file = java.io.File(System.getProperty("blekey.layoutReportsDir"), "appearance-$name.png").apply { parentFile?.mkdirs() }
        file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }; bitmap.recycle()
    }
}
