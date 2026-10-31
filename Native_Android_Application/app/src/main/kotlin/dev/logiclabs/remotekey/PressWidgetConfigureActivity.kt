package dev.logiclabs.remotekey

import android.app.AlertDialog
import android.appwidget.AppWidgetManager
import android.content.Intent
import android.content.ComponentName
import android.os.Bundle

class PressWidgetConfigureActivity : ThemedActivity() {
    internal var loadProfiles: () -> List<BleDeviceProfile> = { DeviceProfileRepository(SecureStore(this)).load() }
    private var form: WidgetConfigurationView? = null
    private var configurationDialog: AlertDialog? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        val id = intent.getIntExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, AppWidgetManager.INVALID_APPWIDGET_ID)
        val info = AppWidgetManager.getInstance(this).getAppWidgetInfo(id)
        if (info?.provider != ComponentName(this, PressWidgetProvider::class.java)) { finish(); return }
        val profiles = loadProfiles()
        if (profiles.isEmpty()) {
            configurationDialog = AppAppearance.dialog(this).setTitle("Widget settings")
                .setMessage("Add a device and its key in Remote Key first, then add this widget again.")
                .setPositiveButton("Open Remote Key") { _, _ -> startActivity(Intent(this, MainActivity::class.java)); finish() }
                .setNegativeButton("Cancel") { _, _ -> finish() }.setOnCancelListener { finish() }.show()
            return
        }
        val profileId = savedInstanceState?.getString("device") ?: PressWidgetProvider.deviceId(this, id)
        val profile = profiles.firstOrNull { it.id == profileId } ?: profiles.first()
        val picker = WidgetConfigurationView(this, profiles, profileId,
            PressWidgetIcon.saved(savedInstanceState?.getString("icon") ?: PressWidgetProvider.icon(this, id, profile.type).name, profile.type),
            savedInstanceState?.getString("colour") ?: PressWidgetProvider.background(this, id))
        form = picker
        val dialog = AppAppearance.dialog(this).setTitle("Widget settings").setView(picker)
            .setPositiveButton("Save", null).setNegativeButton("Cancel") { _, _ -> finish() }
            .setOnCancelListener { finish() }.create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val colour = picker.validatedColour() ?: return@setOnClickListener
                if (AppWidgetManager.getInstance(this).getAppWidgetInfo(id)?.provider != info.provider ||
                    loadProfiles().none { it.id == picker.selectedProfile.id }) { finish(); return@setOnClickListener }
                PressWidgetProvider.configure(this, id, picker.selectedProfile.id, picker.selectedIcon, colour)
                setResult(RESULT_OK, Intent().putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, id))
                dialog.dismiss()
                finish()
            }
        }
        dialog.show()
        configurationDialog = dialog
    }
    override fun onSaveInstanceState(outState: Bundle) {
        form?.let {
            outState.putString("device", it.selectedProfile.id)
            outState.putString("icon", it.selectedIcon.name)
            outState.putString("colour", it.colourInput.text.toString())
        }
        super.onSaveInstanceState(outState)
    }
    override fun onDestroy() {
        configurationDialog?.dismiss()
        super.onDestroy()
    }
}
