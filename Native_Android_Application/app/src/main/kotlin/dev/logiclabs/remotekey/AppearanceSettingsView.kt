package dev.logiclabs.remotekey

import android.content.Context
import android.widget.ArrayAdapter
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView

internal class AppearanceSettingsView(context: Context, initial: Appearance) : LinearLayout(context) {
    val themePicker = Spinner(context)
    val accentPicker = Spinner(context)
    val selection get() = Appearance(AppTheme.entries[themePicker.selectedItemPosition], AppAccent.entries[accentPicker.selectedItemPosition])
    init {
        orientation = VERTICAL
        fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
        setPadding(dp(20), dp(8), dp(20), dp(12))
        fun label(value: String) = TextView(context).apply {
            text = value; textSize = 16f; setTextColor(AppAppearance.colors(context).text)
            setPadding(0, dp(12), 0, dp(4))
        }
        addView(label("Theme"))
        themePicker.adapter = ArrayAdapter(context, android.R.layout.simple_spinner_dropdown_item, AppTheme.entries.map { it.label })
        themePicker.contentDescription = "App theme"
        themePicker.minimumHeight = dp(48)
        themePicker.setSelection(AppTheme.entries.indexOf(initial.theme))
        addView(themePicker, LayoutParams(-1, -2))
        addView(label("Accent colour"))
        accentPicker.adapter = ArrayAdapter(context, android.R.layout.simple_spinner_dropdown_item, AppAccent.entries.map { it.label })
        accentPicker.contentDescription = "App accent colour"
        accentPicker.minimumHeight = dp(48)
        accentPicker.setSelection(AppAccent.entries.indexOf(initial.accent))
        addView(accentPicker, LayoutParams(-1, -2))
        addView(label("Follow system switches between light and dark with your phone. Widget inactive colours are configured separately in each widget's settings.").apply {
            textSize = 13f; setTextColor(AppAppearance.colors(context).secondary)
        })
    }
}
