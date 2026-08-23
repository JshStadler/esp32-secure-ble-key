package dev.jshstadler.carkey

import android.graphics.Color
import android.graphics.Typeface
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LogActivity : FragmentActivity() {
    private enum class Mode { DIAGNOSTIC, PRESSES, LOCATIONS }
    private data class DeviceFilter(val id: String?, val label: String)
    private lateinit var content: LinearLayout
    private lateinit var diagnosticButton: Button
    private lateinit var pressesButton: Button
    private lateinit var locationsButton: Button
    private lateinit var deviceFilters: List<DeviceFilter>
    private var selectedDeviceId: String? = null
    private var selected = Mode.LOCATIONS

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK
        setContentView(buildUi())
        show(Mode.LOCATIONS)
    }

    private fun buildUi(): FrameLayout {
        val root = FrameLayout(this).apply { setBackgroundColor(Color.BLACK) }
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(0, bars.top, 0, bars.bottom)
            insets
        }
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), 0, dp(20), dp(16))
        }
        val top = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        top.addView(ImageButton(this).apply {
            setImageResource(R.drawable.ic_back)
            imageTintList = ContextCompat.getColorStateList(context, android.R.color.white)
            setBackgroundColor(Color.TRANSPARENT)
            contentDescription = "Back"
            setOnClickListener { finish() }
        }, LinearLayout.LayoutParams(dp(48), dp(56)))
        top.addView(label("Logs", 22f, true), LinearLayout.LayoutParams(0, dp(64), 1f))
        top.addView(Button(this).apply {
            text = "Export"
            isAllCaps = false
            setTextColor(Color.rgb(142, 180, 255))
            setBackgroundColor(Color.TRANSPARENT)
            setOnClickListener { shareLogs() }
        })
        top.addView(Button(this).apply {
            text = "Clear"
            isAllCaps = false
            setTextColor(Color.rgb(142, 180, 255))
            setBackgroundColor(Color.TRANSPARENT)
            setOnClickListener { confirmClear() }
        })
        page.addView(top)

        val tabs = LinearLayout(this)
        diagnosticButton = tab("Diagnostics") { show(Mode.DIAGNOSTIC) }
        pressesButton = tab("Operations") { show(Mode.PRESSES) }
        locationsButton = tab("Locations") { show(Mode.LOCATIONS) }
        tabs.addView(diagnosticButton, LinearLayout.LayoutParams(0, dp(48), 1f))
        tabs.addView(pressesButton, LinearLayout.LayoutParams(0, dp(48), 1f))
        tabs.addView(locationsButton, LinearLayout.LayoutParams(0, dp(48), 1f))
        page.addView(tabs)

        deviceFilters = buildDeviceFilters()
        val filterSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@LogActivity,
                android.R.layout.simple_spinner_dropdown_item,
                deviceFilters.map { it.label },
            )
            setPadding(dp(8), dp(6), dp(8), dp(6))
            contentDescription = "Filter logs by device"
        }
        page.addView(filterSpinner, LinearLayout.LayoutParams(-1, dp(52)).apply { topMargin = dp(8) })

        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(12), 0, dp(12))
        }
        page.addView(ScrollView(this).apply { addView(content) }, LinearLayout.LayoutParams(-1, 0, 1f))
        filterSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                selectedDeviceId = deviceFilters[position].id
                show(selected)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }
        root.addView(page, FrameLayout.LayoutParams(-1, -1))
        return root
    }

    private fun buildDeviceFilters(): List<DeviceFilter> {
        val devices = linkedMapOf<String, String>()
        runCatching { DeviceProfileRepository(SecureStore(this)).load() }.getOrDefault(emptyList()).forEach {
            devices[it.id] = it.displayName
        }
        val logged = EventLog.read(this, EventLog.Kind.DIAGNOSTIC) + EventLog.read(this, EventLog.Kind.PRESS)
        logged.forEach { entry ->
            if (entry.deviceId != null && !devices.containsKey(entry.deviceId)) {
                devices[entry.deviceId] = entry.deviceName ?: "Removed device"
            }
        }
        EventLog.readLocations(this).forEach { entry ->
            if (entry.deviceId != null && !devices.containsKey(entry.deviceId)) {
                devices[entry.deviceId] = entry.deviceName ?: "Removed device"
            }
        }
        return listOf(DeviceFilter(null, "All devices")) +
            devices.map { (id, name) -> DeviceFilter(id, name) }
    }

    private fun show(mode: Mode) {
        selected = mode
        diagnosticButton.alpha = if (mode == Mode.DIAGNOSTIC) 1f else 0.55f
        pressesButton.alpha = if (mode == Mode.PRESSES) 1f else 0.55f
        locationsButton.alpha = if (mode == Mode.LOCATIONS) 1f else 0.55f
        content.removeAllViews()
        if (mode == Mode.LOCATIONS) {
            showLocations()
            return
        }
        val kind = if (mode == Mode.DIAGNOSTIC) EventLog.Kind.DIAGNOSTIC else EventLog.Kind.PRESS
        val entries = EventLog.read(this, kind).filter { selectedDeviceId == null || it.deviceId == selectedDeviceId }
        if (entries.isEmpty()) {
            content.addView(label(if (kind == EventLog.Kind.DIAGNOSTIC) "No diagnostic events in the last 24 hours." else "No successful operations in the last 7 days.", 14f, false).apply {
                setTextColor(Color.GRAY)
                setPadding(dp(8), dp(24), dp(8), dp(24))
            })
            return
        }
        val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
        val dayFormat = SimpleDateFormat("EEEE, d MMMM yyyy", Locale.getDefault())
        var currentDay = ""
        entries.forEach { entry ->
            val day = dayFormat.format(Date(entry.timestamp))
            if (day != currentDay) {
                currentDay = day
                addDayDivider(day)
            }
            content.addView(label(timeFormat.format(Date(entry.timestamp)), 12f, false).apply {
                setTextColor(Color.rgb(142, 180, 255))
                setPadding(dp(8), dp(12), dp(8), 0)
            })
            content.addView(label(entry.message, 14f, false).apply {
                setTextColor(Color.LTGRAY)
                setPadding(dp(8), dp(3), dp(8), dp(12))
            })
        }
    }

    private fun showLocations() {
        val entries = EventLog.readLocations(this).filter { selectedDeviceId == null || it.deviceId == selectedDeviceId }
        if (entries.isEmpty()) {
            content.addView(label("No saved operation locations. Enable location recording in Device Settings.", 14f, false).apply {
                setTextColor(Color.GRAY)
                setPadding(dp(8), dp(24), dp(8), dp(24))
            })
            return
        }
        val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        val dayFormat = SimpleDateFormat("EEEE, d MMMM yyyy", Locale.getDefault())
        var currentDay = ""
        entries.forEach { entry ->
            val day = dayFormat.format(Date(entry.timestamp))
            if (day != currentDay) {
                currentDay = day
                addDayDivider(day)
            }
            val row = LinearLayout(this).apply {
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(8), dp(8), dp(4), dp(8))
            }
            val devicePrefix = if (selectedDeviceId == null && entry.deviceName != null) "${entry.deviceName} • " else ""
            row.addView(label("$devicePrefix${timeFormat.format(Date(entry.timestamp))}\n${"%.6f".format(entry.latitude)}, ${"%.6f".format(entry.longitude)}  (±${entry.accuracy.toInt()} m)", 14f, false).apply {
                setTextColor(Color.rgb(142, 180, 255))
            }, LinearLayout.LayoutParams(0, -2, 1f))
            row.addView(ImageButton(this).apply {
                setImageResource(R.drawable.ic_map)
                setBackgroundColor(Color.TRANSPARENT)
                contentDescription = "Open location in Maps"
                setPadding(dp(12), dp(12), dp(12), dp(12))
                setOnClickListener {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("geo:${entry.latitude},${entry.longitude}?q=${entry.latitude},${entry.longitude}(Car Key operation)")))
                }
            }, LinearLayout.LayoutParams(dp(52), dp(52)))
            content.addView(row)
        }
    }

    private fun addDayDivider(day: String) {
        content.addView(label(day, 13f, true).apply {
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.rgb(31, 34, 48))
            setPadding(dp(10), dp(7), dp(10), dp(7))
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
    }

    private fun confirmClear() {
        val name = when (selected) {
            Mode.DIAGNOSTIC -> "diagnostic logs"
            Mode.PRESSES -> "operation history"
            Mode.LOCATIONS -> "saved locations"
        }
        val filterName = deviceFilters.firstOrNull { it.id == selectedDeviceId }?.label ?: "All devices"
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Clear $name for $filterName?")
            .setMessage("This cannot be undone.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                when (selected) {
                    Mode.DIAGNOSTIC -> EventLog.clear(this, EventLog.Kind.DIAGNOSTIC, selectedDeviceId)
                    Mode.PRESSES -> EventLog.clear(this, EventLog.Kind.PRESS, selectedDeviceId)
                    Mode.LOCATIONS -> EventLog.clearLocations(this, selectedDeviceId)
                }
                show(selected)
            }
            .show()
    }

    private fun shareLogs() {
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, "Car Key ${selected.name.lowercase()}")
                    putExtra(Intent.EXTRA_TEXT, buildExport())
                },
                "Share Car Key logs",
            ),
        )
    }

    private fun buildExport(): String {
        val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
        return buildString {
            appendLine("Car Key ${selected.name.lowercase()} exported ${format.format(Date())}")
            appendLine("Device filter: ${deviceFilters.firstOrNull { it.id == selectedDeviceId }?.label ?: "All devices"}")
            appendLine()
            when (selected) {
                Mode.DIAGNOSTIC -> {
                    appendLine("=== DIAGNOSTICS — LAST 24 HOURS ===")
                    EventLog.read(this@LogActivity, EventLog.Kind.DIAGNOSTIC).filter { selectedDeviceId == null || it.deviceId == selectedDeviceId }.reversed().forEach { appendLine("${format.format(Date(it.timestamp))}  ${it.message}") }
                }
                Mode.PRESSES -> {
                    appendLine("=== SUCCESSFUL OPERATIONS — LAST 7 DAYS ===")
                    EventLog.read(this@LogActivity, EventLog.Kind.PRESS).filter { selectedDeviceId == null || it.deviceId == selectedDeviceId }.reversed().forEach { appendLine("${format.format(Date(it.timestamp))}  ${it.message}") }
                }
                Mode.LOCATIONS -> {
                    appendLine("=== SAVED LOCATIONS — LATEST 30 ===")
                    EventLog.readLocations(this@LogActivity).filter { selectedDeviceId == null || it.deviceId == selectedDeviceId }.reversed().forEach { appendLine("${format.format(Date(it.timestamp))}  ${it.latitude},${it.longitude} accuracy=${it.accuracy}m") }
                }
            }
        }
    }

    private fun tab(title: String, action: () -> Unit) = Button(this).apply {
        text = title
        isAllCaps = false
        setTextColor(Color.WHITE)
        setBackgroundColor(Color.rgb(31, 34, 48))
        setOnClickListener { action() }
    }

    private fun label(value: String, size: Float, bold: Boolean) = TextView(this).apply {
        text = value
        textSize = size
        setTextColor(Color.WHITE)
        gravity = Gravity.CENTER_VERTICAL
        if (bold) setTypeface(typeface, Typeface.BOLD)
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
