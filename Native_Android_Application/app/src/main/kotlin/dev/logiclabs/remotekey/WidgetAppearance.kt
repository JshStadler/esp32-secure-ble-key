package dev.logiclabs.remotekey

import android.graphics.Color
import androidx.core.graphics.ColorUtils

/** An opaque idle colour; live connection and operation colours stay distinct. */
internal object WidgetBackground {
    const val DEFAULT = "#000000"
    val presets = linkedMapOf("Black" to DEFAULT, "Dark gray" to "#303036",
        "Slate" to "#263238", "Purple" to "#352744", "White" to "#FFFFFF")
    fun normalize(value: String?): String? = value?.trim()?.removePrefix("#")
        ?.takeIf { it.matches(Regex("[0-9a-fA-F]{6}")) }?.uppercase(java.util.Locale.ROOT)?.let { "#$it" }
    fun color(value: String?) = Color.parseColor(normalize(value) ?: DEFAULT)
    fun foreground(background: Int) = if (ColorUtils.calculateContrast(Color.WHITE, background) >= 4.5)
        Color.WHITE else Color.BLACK
    fun accent(background: Int) = WidgetStatusText.Tone.IDLE.accent.takeIf {
        ColorUtils.calculateContrast(it, background) >= 4.5
    } ?: foreground(background)
}
