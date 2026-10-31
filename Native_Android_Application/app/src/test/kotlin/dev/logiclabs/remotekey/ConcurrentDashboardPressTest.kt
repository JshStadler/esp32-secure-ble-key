package dev.logiclabs.remotekey

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.os.Looper
import android.widget.Button
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ConcurrentDashboardPressTest {
    private fun field(owner: Any, name: String): Any? = owner.javaClass.getDeclaredField(name).apply { isAccessible = true }.get(owner)
    private fun set(owner: Any, name: String, value: Any) = owner.javaClass.getDeclaredField(name).apply { isAccessible = true }.set(owner, value)
    private fun invoke(activity: MainActivity, name: String): Any? = MainActivity::class.java.getDeclaredMethod(name).apply { isAccessible = true }.invoke(activity)
    private fun withDashboard(test: (MainActivity, Map<String, Button>, DevicePressRequests) -> Unit) {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app.packageManager).setSystemFeature(android.content.pm.PackageManager.FEATURE_BLUETOOTH_LE, true)
        shadowOf(app).grantPermissions(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        shadowOf(BluetoothAdapter.getDefaultAdapter()).setEnabled(true)
        assertEquals(BluetoothAvailability.AVAILABLE, BluetoothAvailability.read(app, app.getSystemService(android.bluetooth.BluetoothManager::class.java)))
        val controller = Robolectric.buildActivity(MainActivity::class.java).create().start().resume()
        val activity = controller.get()
        try {
            set(activity, "authenticated", true)
            set(activity, "initialSetupPending", false)
            @Suppress("UNCHECKED_CAST")
            val profiles = field(activity, "profiles") as MutableList<BleDeviceProfile>
            profiles.addAll(listOf(BleDeviceProfiles.GATE, BleDeviceProfiles.CAR))
            @Suppress("UNCHECKED_CAST")
            val runtimes = field(activity, "runtimes") as MutableMap<String, Any>
            val runtimeType = MainActivity::class.java.declaredClasses.single { it.simpleName == "DeviceRuntime" }
            profiles.forEach { profile ->
                val runtime = runtimeType.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
                set(runtime, "psk", "0123456789abcdef0123456789abcdef")
                runtimes[profile.id] = runtime
            }
            activity.setContentView(invoke(activity, "buildUi") as android.view.View)
            @Suppress("UNCHECKED_CAST")
            val views = field(activity, "deviceViews") as Map<String, Any>
            val buttons = views.mapValues { field(it.value, "actionButton") as Button }
            test(activity, buttons, field(activity, "presses") as DevicePressRequests)
        } finally { controller.pause().stop().destroy() }
    }
    @Test fun pendingGateDoesNotDisableCarAndCancelOnlyClearsGate() = withDashboard { _, buttons, presses ->
        buttons.getValue("gate").performClick()
        assertNotNull(presses["gate"])
        assertTrue(buttons.getValue("car").isEnabled)
        buttons.getValue("car").performClick()
        assertNotNull(presses["car"])
        assertEquals("Cancel", buttons.getValue("gate").text)
        assertEquals("Cancel", buttons.getValue("car").text)
        buttons.getValue("gate").performClick()
        assertNull(presses["gate"])
        assertNotNull(presses["car"])
        assertEquals("Cancel", buttons.getValue("car").text)
        assertTrue(buttons.getValue("gate").isEnabled)
    }
    @Test fun eachDashboardTapRetainsItsOwnDeadlineWhileAppIsInBackground() = withDashboard { activity, buttons, presses ->
        buttons.getValue("gate").performClick()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        buttons.getValue("car").performClick()
        // The requests remain live when Home/Recents hides the dashboard.
        invoke(activity, "onPause")
        invoke(activity, "onStop")
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        assertNull(presses["gate"])
        assertNotNull(presses["car"])
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        assertNull(presses["car"])
    }
    @Test fun turningOffBluetoothCancelsBothDashboardRequests() = withDashboard { activity, buttons, presses ->
        buttons.getValue("gate").performClick()
        buttons.getValue("car").performClick()
        shadowOf(BluetoothAdapter.getDefaultAdapter()).setEnabled(false)
        activity.sendBroadcast(android.content.Intent(BluetoothAdapter.ACTION_STATE_CHANGED)
            .putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_OFF))
        shadowOf(Looper.getMainLooper()).idle()
        assertFalse(presses.busy)
        assertFalse(buttons.getValue("car").isEnabled)
        assertFalse(buttons.getValue("gate").isEnabled)
    }
    @Test fun oldFirmwareCleanupCannotDisconnectANewerPress() = withDashboard { activity, buttons, presses ->
        set(activity, "maintenanceDeviceId", "car")
        set(activity, "pendingOtaImage", byteArrayOf(1))
        MainActivity::class.java.getDeclaredMethod("finishOtaOperation", BleDeviceProfile::class.java,
            Boolean::class.javaPrimitiveType, String::class.java).apply { isAccessible = true }
            .invoke(activity, BleDeviceProfiles.CAR, false, "Firmware update failed")
        buttons.getValue("car").performClick()
        @Suppress("UNCHECKED_CAST")
        val clients = field(activity, "clients") as Map<String, BleCarKeyClient>
        val newClient = clients["car"]
        assertNotNull(newClient)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(2))
        assertSame(newClient, clients["car"])
        assertNotNull(presses["car"])
    }
}
