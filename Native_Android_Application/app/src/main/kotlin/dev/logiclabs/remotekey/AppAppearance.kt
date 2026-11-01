package dev.logiclabs.remotekey

import android.app.AlertDialog
import android.content.Context
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import androidx.core.graphics.ColorUtils
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity

internal enum class AppTheme(val label: String) {
    SYSTEM("Follow system"), LIGHT("Light"), DARK("Dark");
    companion object { fun saved(value: String?) = entries.firstOrNull { it.name == value } ?: SYSTEM }
}

internal enum class AppAccent(val label: String, val overlay: Int, val color: Int) {
    BLUE("Blue", R.style.Accent_Blue, R.color.accent_blue),
    TEAL("Teal", R.style.Accent_Teal, R.color.accent_teal),
    GREEN("Green", R.style.Accent_Green, R.color.accent_green),
    PURPLE("Purple", R.style.Accent_Purple, R.color.accent_purple),
    ORANGE("Orange", R.style.Accent_Orange, R.color.accent_orange),
    ROSE("Rose", R.style.Accent_Rose, R.color.accent_rose);
    companion object { fun saved(value: String?) = entries.firstOrNull { it.name == value } ?: BLUE }
}

internal data class Appearance(val theme: AppTheme = AppTheme.SYSTEM, val accent: AppAccent = AppAccent.BLUE)

internal data class AppColors(val background: Int, val surface: Int, val text: Int, val secondary: Int,
    val muted: Int, val accent: Int, val onAccent: Int, val warningSurface: Int, val warning: Int,
    val success: Int, val error: Int)

internal object AppAppearance {
    private const val PREFS = "appearance"
    fun read(context: Context): Appearance {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return Appearance(AppTheme.saved(prefs.getString("theme", null)), AppAccent.saved(prefs.getString("accent", null)))
    }
    fun save(context: Context, value: Appearance) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("theme", value.theme.name).putString("accent", value.accent.name).apply()
    }
    fun isDark(context: Context) = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
    fun colors(context: Context): AppColors {
        fun color(id: Int) = context.getColor(id)
        val accent = color(read(context).accent.color)
        return AppColors(color(R.color.app_background), color(R.color.app_surface), color(R.color.app_text),
            color(R.color.app_secondary), color(R.color.app_muted), accent,
            if (ColorUtils.calculateContrast(Color.WHITE, accent) >= 4.5) Color.WHITE else Color.BLACK,
            color(R.color.app_warning_surface), color(R.color.app_warning), color(R.color.app_success), color(R.color.app_error))
    }
    fun dialog(context: Context): AlertDialog.Builder {
        return AlertDialog.Builder(context, R.style.Theme_CarKey_Dialog).apply {
            this.context.theme.applyStyle(read(context).accent.overlay, true)
        }
    }
}

/** Share the effective night configuration with dialogs, controls and all screens. */
open class ThemedActivity : FragmentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(newBase)
        val night = when (AppAppearance.read(newBase).theme) {
            AppTheme.SYSTEM -> return
            AppTheme.LIGHT -> Configuration.UI_MODE_NIGHT_NO
            AppTheme.DARK -> Configuration.UI_MODE_NIGHT_YES
        }
        applyOverrideConfiguration(Configuration().apply { uiMode = night })
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        theme.applyStyle(AppAppearance.read(this).accent.overlay, true)
        super.onCreate(savedInstanceState)
        val colors = AppAppearance.colors(this)
        @Suppress("DEPRECATION")
        window.statusBarColor = colors.background
        @Suppress("DEPRECATION")
        window.navigationBarColor = colors.background
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = !AppAppearance.isDark(this@ThemedActivity)
            isAppearanceLightNavigationBars = !AppAppearance.isDark(this@ThemedActivity)
        }
    }
}
