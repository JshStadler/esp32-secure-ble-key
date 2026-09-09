package dev.logiclabs.remotekey

import android.graphics.Color
import android.graphics.Typeface
import android.app.AlertDialog
import android.app.DatePickerDialog
import android.content.Intent
import android.content.ClipData
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.text.Editable
import android.text.TextWatcher
import android.widget.*
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.fragment.app.FragmentActivity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.Calendar
import java.util.UUID
import java.util.TimeZone
import java.io.File

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
    private var selectedDay: LogDay? = null
    private var search = ""
    private lateinit var dateButton: Button
    private lateinit var countLabel: TextView
    private var visibleEntries = emptyList<EventLog.Entry>()
    private var visibleLocations = emptyList<EventLog.LocationEntry>()
    private var pendingExport: String? = null
    private val saveExport = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val source = pendingExport?.let { File(cacheDir, "log-exports/$it") }
        pendingExport = null
        if (uri != null && source != null) {
            runCatching {
                contentResolver.openOutputStream(uri)?.use { output -> source.inputStream().use { it.copyTo(output) } }
                    ?: error("Could not open destination")
            }.onSuccess { toast("Logs saved") }.onFailure { toast("Could not save logs: ${it.localizedMessage}") }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        selected = savedInstanceState?.getString("mode")?.let { Mode.valueOf(it) } ?: Mode.LOCATIONS
        selectedDeviceId = savedInstanceState?.getString("device")
        savedInstanceState?.getIntArray("day")?.let { selectedDay = LogDay(it[0], it[1], it[2]) }
        search = savedInstanceState?.getString("search").orEmpty()
        pendingExport = savedInstanceState?.getString("export")
        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK
        setContentView(buildUi())
        show(selected)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("mode", selected.name)
        outState.putString("device", selectedDeviceId)
        selectedDay?.let { outState.putIntArray("day", intArrayOf(it.year, it.month, it.day)) }
        outState.putString("search", search)
        outState.putString("export", pendingExport)
        super.onSaveInstanceState(outState)
    }

    private fun currentFilter() = LogFilter(selectedDeviceId, selectedDay, search)
    private fun dayLabel() = selectedDay?.let {
        SimpleDateFormat("EEE, d MMM yyyy", Locale.getDefault()).format(Date(it.bounds().first))
    } ?: "All dates"
    private fun deviceLabel() = deviceFilters.firstOrNull { it.id == selectedDeviceId }?.label ?: "All devices"
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

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
            setOnClickListener { exportLogs() }
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
        filterSpinner.setSelection(deviceFilters.indexOfFirst { it.id == selectedDeviceId }.coerceAtLeast(0))

        val dates = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        dateButton = tab(if (selectedDay == null) getString(R.string.log_choose_day) else dayLabel()) { pickDay() }
            .apply { contentDescription = "Choose log date" }
        dates.addView(dateButton, LinearLayout.LayoutParams(0, dp(48), 1f))
        dates.addView(Button(this).apply {
            setText(R.string.log_all_dates); isAllCaps = false
            setOnClickListener { selectedDay = null; dateButton.setText(R.string.log_choose_day); show(selected) }
        }, LinearLayout.LayoutParams(-2, dp(48)))
        page.addView(dates)
        page.addView(EditText(this).apply {
            hint = "Search logs"; setTextColor(Color.WHITE); setHintTextColor(Color.GRAY)
            isSingleLine = true; textSize = 14f; setText(search)
            contentDescription = "Search logs"
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { search = s.toString(); show(selected) }
                override fun afterTextChanged(s: Editable?) = Unit
            })
        }, LinearLayout.LayoutParams(-1, dp(48)))
        countLabel = label("", 12f, false).apply { setTextColor(Color.GRAY) }
        page.addView(countLabel)

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

    private fun pickDay() {
        val calendar = Calendar.getInstance()
        selectedDay?.let { calendar.set(it.year, it.month, it.day) }
        DatePickerDialog(this, { _, year, month, day ->
            selectedDay = LogDay(year, month, day)
            dateButton.text = dayLabel()
            show(selected)
        }, calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH), calendar.get(Calendar.DAY_OF_MONTH)).apply {
            datePicker.maxDate = System.currentTimeMillis()
        }.show()
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
        val filter = currentFilter()
        visibleEntries = if (mode == Mode.LOCATIONS) emptyList() else
            EventLog.read(this, if (mode == Mode.DIAGNOSTIC) EventLog.Kind.DIAGNOSTIC else EventLog.Kind.PRESS)
                .filter { filter.matches(it.timestamp, it.deviceId, it.message) }
        visibleLocations = if (mode != Mode.LOCATIONS) emptyList() else EventLog.readLocations(this)
            .filter { filter.matches(it.timestamp, it.deviceId, EventLog.locationText(it)) }.sortedByDescending { it.timestamp }
        val retention = when (mode) {
            Mode.DIAGNOSTIC -> "Diagnostics retained for 24 hours"
            Mode.PRESSES -> "Operations retained for 7 days"
            Mode.LOCATIONS -> "Latest 30 saved locations"
        }
        countLabel.text = getString(R.string.log_entry_count, visibleEntries.size + visibleLocations.size, retention)
        if (mode == Mode.LOCATIONS) {
            showLocations()
            return
        }
        val entries = visibleEntries
        if (entries.isEmpty()) {
            content.addView(label("No entries match these filters.", 14f, false).apply {
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
        val entries = visibleLocations
        if (entries.isEmpty()) {
            content.addView(label("No saved locations match these filters. Location recording can be enabled in Device Settings.", 14f, false).apply {
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
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("geo:${entry.latitude},${entry.longitude}?q=${entry.latitude},${entry.longitude}(Remote Key operation)")))
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
        val filter = currentFilter()
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Clear matching $name?")
            .setMessage("${deviceLabel()} • ${dayLabel()}\nSearch: ${search.ifBlank { "Any text" }}\nOnly matching entries will be removed. This cannot be undone.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear") { _, _ ->
                when (selected) {
                    Mode.DIAGNOSTIC -> EventLog.clear(this, EventLog.Kind.DIAGNOSTIC, filter)
                    Mode.PRESSES -> EventLog.clear(this, EventLog.Kind.PRESS, filter)
                    Mode.LOCATIONS -> EventLog.clearLocations(this, filter)
                }
                show(selected)
            }
            .show()
    }

    private fun exportLogs() {
        val snapshot = buildExport()
        val filename = "remote-key-${selected.name.lowercase()}-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}.txt"
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Export ${visibleEntries.size + visibleLocations.size} matching entries")
            .setItems(arrayOf("Save text file…", "Share text file…")) { _, choice ->
                runCatching {
                    val directory = File(cacheDir, "log-exports").apply { mkdirs() }
                    directory.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 86_400_000 }
                        ?.forEach { it.delete() }
                    val file = File(directory, "${UUID.randomUUID()}-$filename").apply { writeText(snapshot) }
                    if (choice == 0) { pendingExport = file.name; saveExport.launch(filename) }
                    else shareLogs(file)
                }.onFailure { toast("Could not export logs: ${it.localizedMessage}") }
            }.show()
    }

    private fun shareLogs(file: File) {
        val uri = FileProvider.getUriForFile(this, "$packageName.logexports", file)
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, "Remote Key ${selected.name.lowercase()}")
                    putExtra(Intent.EXTRA_STREAM, uri)
                    clipData = ClipData.newUri(contentResolver, "Filtered logs", uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                },
                "Share Remote Key logs",
            ),
        )
    }

    private fun buildExport(): String {
        val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
        return buildString {
            appendLine("Remote Key ${selected.name.lowercase()} exported ${format.format(Date())}")
            appendLine("Device filter: ${deviceFilters.firstOrNull { it.id == selectedDeviceId }?.label ?: "All devices"}")
            appendLine("Date filter: ${dayLabel()} (${TimeZone.getDefault().id})")
            appendLine("Search: ${search.ifBlank { "Any text" }}")
            appendLine("Entries: ${visibleEntries.size + visibleLocations.size}")
            appendLine()
            when (selected) {
                Mode.DIAGNOSTIC -> {
                    appendLine("=== DIAGNOSTICS — LAST 24 HOURS ===")
                    visibleEntries.reversed().forEach { appendLine("${format.format(Date(it.timestamp))}  ${it.message}") }
                }
                Mode.PRESSES -> {
                    appendLine("=== SUCCESSFUL OPERATIONS — LAST 7 DAYS ===")
                    visibleEntries.reversed().forEach { appendLine("${format.format(Date(it.timestamp))}  ${it.message}") }
                }
                Mode.LOCATIONS -> {
                    appendLine("=== SAVED LOCATIONS — LATEST 30 ===")
                    visibleLocations.reversed().forEach { appendLine("${format.format(Date(it.timestamp))}  ${EventLog.locationText(it)}") }
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
