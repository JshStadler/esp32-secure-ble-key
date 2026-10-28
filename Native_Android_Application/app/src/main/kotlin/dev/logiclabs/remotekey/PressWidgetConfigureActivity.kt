package dev.logiclabs.remotekey

import android.app.AlertDialog
import android.appwidget.AppWidgetManager
import android.content.Intent
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.FragmentActivity

class PressWidgetConfigureActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        val id = intent.getIntExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, AppWidgetManager.INVALID_APPWIDGET_ID)
        val info = AppWidgetManager.getInstance(this).getAppWidgetInfo(id)
        if (info?.provider?.className != PressWidgetProvider::class.java.name) { finish(); return }
        val profiles = DeviceProfileRepository(SecureStore(this)).load()
        val dialog = AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog)
            .setTitle("Choose a widget device")
            .setNegativeButton("Cancel") { _, _ -> finish() }
            .setOnCancelListener { finish() }
        if (profiles.isEmpty()) {
            dialog.setMessage("Add a device and its key in Remote Key first, then add this widget again.")
                .setPositiveButton("Open Remote Key") { _, _ -> startActivity(Intent(this, MainActivity::class.java)); finish() }
        } else {
            dialog.setItems(profiles.map { it.displayName }.toTypedArray()) { _, index ->
                chooseIcon(id, profiles[index])
            }
        }
        dialog.show()
    }
    private fun chooseIcon(id: Int, profile: BleDeviceProfile) {
        val icons = PressWidgetIcon.entries
        val adapter = object : ArrayAdapter<PressWidgetIcon>(this, android.R.layout.simple_list_item_1, icons) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
                return LinearLayout(context).apply {
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(24), dp(12), dp(24), dp(12))
                    addView(ImageView(context).apply {
                        setImageResource(icons[position].drawable)
                        imageTintList = android.content.res.ColorStateList.valueOf(Color.rgb(142, 180, 255))
                        contentDescription = icons[position].label
                    }, LinearLayout.LayoutParams(dp(36), dp(36)))
                    addView(TextView(context).apply {
                        text = icons[position].label; textSize = 18f; setTextColor(Color.WHITE)
                        setPadding(dp(20), 0, 0, 0)
                    }, LinearLayout.LayoutParams(-1, -2))
                }
            }
        }
        AlertDialog.Builder(this, R.style.Theme_CarKey_Dialog).setTitle("Choose an icon for ${profile.displayName}")
            .setAdapter(adapter) { _, index ->
                PressWidgetProvider.configure(this, id, profile.id, icons[index])
                setResult(RESULT_OK, Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, id))
                finish()
            }.setNegativeButton("Cancel") { _, _ -> finish() }.setOnCancelListener { finish() }.show()
    }
}
