package dev.logiclabs.remotekey

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.text.Editable
import android.text.InputFilter
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*

/** Draft settings only: Cancel never mutates an existing widget. */
internal class WidgetConfigurationView(context: Context, private val profiles: List<BleDeviceProfile>,
    profileId: String?, icon: PressWidgetIcon, colour: String) : ScrollView(context) {
    val devicePicker = Spinner(context)
    val iconPicker = Spinner(context)
    val colourInput = EditText(context)
    val preview = TextView(context)
    val selectedProfile get() = profiles[devicePicker.selectedItemPosition]
    val selectedIcon get() = PressWidgetIcon.entries[iconPicker.selectedItemPosition]
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    init {
        val colors = AppAppearance.colors(context)
        val body = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(20), dp(8), dp(20), dp(12))
        }
        fun label(value: String) = TextView(context).apply {
            text = value; textSize = 16f; setTextColor(colors.text); setPadding(0, dp(12), 0, dp(4))
        }
        body.addView(label("Device"))
        devicePicker.adapter = ArrayAdapter(context, android.R.layout.simple_spinner_dropdown_item, profiles.map { it.displayName })
        devicePicker.minimumHeight = dp(48); devicePicker.contentDescription = "Widget device"
        devicePicker.setSelection(profiles.indexOfFirst { it.id == profileId }.coerceAtLeast(0))
        body.addView(devicePicker, LinearLayout.LayoutParams(-1, -2))
        body.addView(label("Icon"))
        iconPicker.adapter = object : ArrayAdapter<PressWidgetIcon>(context, android.R.layout.simple_spinner_item, PressWidgetIcon.entries) {
            private fun row(position: Int): View = LinearLayout(context).apply {
                gravity = Gravity.CENTER_VERTICAL; setPadding(dp(8), dp(8), dp(8), dp(8))
                addView(ImageView(context).apply {
                    setImageResource(PressWidgetIcon.entries[position].drawable)
                    imageTintList = ColorStateList.valueOf(colors.accent); importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                }, LinearLayout.LayoutParams(dp(28), dp(28)))
                addView(TextView(context).apply {
                    text = PressWidgetIcon.entries[position].label; textSize = 18f; setTextColor(colors.text)
                    setPadding(dp(16), 0, 0, 0)
                }, LinearLayout.LayoutParams(-1, -2))
            }
            override fun getView(position: Int, convertView: View?, parent: ViewGroup) = row(position)
            override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup) = row(position)
        }
        iconPicker.minimumHeight = dp(48); iconPicker.contentDescription = "Widget icon"
        iconPicker.setSelection(PressWidgetIcon.entries.indexOf(icon))
        body.addView(iconPicker, LinearLayout.LayoutParams(-1, -2))
        body.addView(label("Inactive background colour"))
        colourInput.apply {
            setText(colour); hint = "#RRGGBB"; isSingleLine = true; textSize = 18f
            setTextColor(colors.text); setHintTextColor(colors.muted)
            filters = arrayOf(InputFilter.LengthFilter(7)); contentDescription = "Inactive widget colour, hex RGB"
        }
        body.addView(colourInput, LinearLayout.LayoutParams(-1, -2))
        body.addView(Button(context).apply {
            text = "Choose a preset"; isAllCaps = false
            setOnClickListener {
                AppAppearance.dialog(context).setTitle("Inactive background colour")
                    .setItems(WidgetBackground.presets.keys.toTypedArray()) { _, index ->
                        colourInput.setText(WidgetBackground.presets.values.elementAt(index))
                    }.setNegativeButton("Cancel", null).show()
            }
        }, LinearLayout.LayoutParams(-1, -2))
        preview.apply { text = "Inactive widget preview"; textSize = 16f; gravity = Gravity.CENTER; setPadding(dp(16), dp(20), dp(16), dp(20)) }
        body.addView(preview, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        body.addView(label("Connected stays blue; waiting and result colours still show status. Your chosen colour applies when disconnected.").apply {
            textSize = 13f; setTextColor(colors.secondary)
        })
        fun updatePreview() {
            val valid = WidgetBackground.normalize(colourInput.text.toString()) ?: return
            val color = WidgetBackground.color(valid)
            preview.background = GradientDrawable().apply { setColor(color); cornerRadius = dp(20).toFloat() }
            preview.setTextColor(WidgetBackground.foreground(color))
            colourInput.error = null
        }
        colourInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = updatePreview()
            override fun afterTextChanged(s: Editable?) {}
        })
        updatePreview()
        addView(body)
    }
    fun validatedColour(): String? = WidgetBackground.normalize(colourInput.text.toString()).also {
        if (it == null) { colourInput.error = "Enter six hex digits, for example #303036"; colourInput.requestFocus() }
    }
}
