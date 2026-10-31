package dev.logiclabs.remotekey

import android.Manifest
import android.app.Service
import android.appwidget.AppWidgetManager
import android.bluetooth.BluetoothAdapter
import android.content.ComponentName
import android.content.Intent
import android.os.Looper
import android.os.SystemClock
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
class ConcurrentWidgetPressTest {
    private class FakeConnection(val listener: BleCarKeyClient.Listener) : WidgetPressService.Connection {
        var stopped = false
        var presses = 0
        override val isRunning get() = !stopped
        override fun start(key: String, address: String?, preferCached: Boolean) {}
        override fun press() { presses++ }
        override fun stop() { stopped = true }
        fun ready() { listener.onState(BleCarKeyClient.State.CONNECTED, "Connected"); listener.onReadyChanged(true) }
        fun complete() = listener.onCommandResult(true, "Pressed")
    }
    private fun withService(test: (WidgetPressService, (BleDeviceProfile, String) -> Intent, MutableMap<String, FakeConnection>) -> Unit) {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app.packageManager).setSystemFeature(android.content.pm.PackageManager.FEATURE_BLUETOOTH_LE, true)
        shadowOf(app).grantPermissions(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        shadowOf(BluetoothAdapter.getDefaultAdapter()).setEnabled(true)
        assertEquals(BluetoothAvailability.AVAILABLE, BluetoothAvailability.read(app, app.getSystemService(android.bluetooth.BluetoothManager::class.java)))
        val controller = Robolectric.buildService(WidgetPressService::class.java).create()
        val service = controller.get()
        val profiles = listOf(BleDeviceProfiles.GATE, BleDeviceProfiles.CAR)
        val widgets = profiles.associate { profile ->
            val manager = AppWidgetManager.getInstance(app)
            val widget = shadowOf(manager).createWidget(PressWidgetProvider::class.java, R.layout.press_widget)
            shadowOf(manager).putWidgetInfo(widget, android.appwidget.AppWidgetProviderInfo().apply {
                provider = ComponentName(app, PressWidgetProvider::class.java)
            })
            PressWidgetProvider.configure(app, widget, profile.id, PressWidgetIcon.KEY)
            profile.id to widget
        }
        val connections = mutableMapOf<String, FakeConnection>()
        service.loadProfiles = { profiles }
        service.readSetting = { setting -> when (setting) {
            "require_auth" -> "false"
            BackgroundConnectionDuration.STORE_KEY -> BackgroundConnectionDuration.THIRTY_SECONDS.name
            BleDeviceProfiles.GATE.pskStoreKey, BleDeviceProfiles.CAR.pskStoreKey -> "0123456789abcdef0123456789abcdef"
            else -> null
        } }
        service.createConnection = { profile, listener -> FakeConnection(listener).also { connections[profile.id] = it } }
        val intent: (BleDeviceProfile, String) -> Intent = { profile, id ->
            Intent(app, WidgetPressService::class.java).putExtra("widget_id", widgets.getValue(profile.id))
                .putExtra("request_id", id).putExtra("requested_at", SystemClock.elapsedRealtime())
                .putExtra("device_snapshot", profile.toString())
        }
        try { test(service, intent, connections) } finally { controller.destroy() }
    }
    @Test fun gateAndCarConnectAndSendIndependentlyAndIgnoreDuplicateRequests() = withService { service, intent, connections ->
        val gate = intent(BleDeviceProfiles.GATE, "gate-a")
        service.onStartCommand(gate, 0, 1)
        service.onStartCommand(intent(BleDeviceProfiles.CAR, "car-a"), 0, 2)
        assertEquals(setOf("gate", "car"), connections.keys)
        assertTrue(PressWidgetProvider.isBusy("gate"))
        assertTrue(PressWidgetProvider.isBusy("car"))
        connections.getValue("car").ready()
        connections.getValue("car").ready()
        assertEquals(1, connections.getValue("car").presses)
        service.onStartCommand(gate, 0, 3)
        assertFalse(connections.getValue("car").stopped)
        connections.getValue("gate").ready()
        assertEquals(1, connections.getValue("gate").presses)
        connections.getValue("car").complete()
        assertTrue(PressWidgetProvider.isBusy("gate"))
        assertFalse(PressWidgetProvider.isBusy("car"))
        assertFalse(shadowOf(service).isStoppedBySelf)
    }
    @Test fun cancelingGateDoesNotCancelCarAndStaleCallbacksCannotAffectItsReplacement() = withService { service, intent, connections ->
        service.onStartCommand(intent(BleDeviceProfiles.GATE, "gate-old"), 0, 1)
        service.onStartCommand(intent(BleDeviceProfiles.CAR, "car-a"), 0, 2)
        val old = connections.getValue("gate")
        service.onStartCommand(WidgetPressService.cancellationIntent(service, "gate", "gate-old"), 0, 3)
        assertTrue(old.stopped)
        assertTrue(PressWidgetProvider.isBusy("car"))
        assertFalse(connections.getValue("car").stopped)
        service.onStartCommand(intent(BleDeviceProfiles.GATE, "gate-new"), 0, 4)
        service.onStartCommand(WidgetPressService.cancellationIntent(service, "gate", "gate-old"), 0, 5)
        old.ready(); old.complete()
        assertEquals(0, old.presses)
        assertTrue(PressWidgetProvider.isBusy("gate"))
        connections.getValue("gate").ready()
        assertEquals(1, connections.getValue("gate").presses)
        connections.getValue("car").ready()
        assertEquals(1, connections.getValue("car").presses)
    }
    @Test fun eachDeviceHasItsOwnConnectionTimeout() = withService { service, intent, connections ->
        service.onStartCommand(intent(BleDeviceProfiles.GATE, "gate-a"), 0, 1)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        service.onStartCommand(intent(BleDeviceProfiles.CAR, "car-a"), 0, 2)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        assertTrue(connections.getValue("gate").stopped)
        assertFalse(connections.getValue("car").stopped)
        assertTrue(PressWidgetProvider.isBusy("car"))
        connections.getValue("car").ready()
        assertEquals(1, connections.getValue("car").presses)
    }
    @Test fun aSentPressCannotBeCanceledAndOtherDeviceCanStillBeCanceled() = withService { service, intent, connections ->
        service.onStartCommand(intent(BleDeviceProfiles.GATE, "gate-a"), 0, 1)
        service.onStartCommand(intent(BleDeviceProfiles.CAR, "car-a"), 0, 2)
        connections.getValue("gate").ready()
        service.onStartCommand(WidgetPressService.cancellationIntent(service, "gate", "gate-a"), 0, 3)
        assertFalse(connections.getValue("gate").stopped)
        assertTrue(PressWidgetProvider.isBusy("gate"))
        service.onStartCommand(WidgetPressService.cancellationIntent(service, "car", "car-a"), 0, 4)
        assertTrue(connections.getValue("car").stopped)
        connections.getValue("gate").complete()
        assertEquals(1, connections.getValue("gate").presses)
        assertTrue(PressWidgetProvider.currentMessage("gate").startsWith("Pressed"))
    }
    @Test fun disconnectOffReleasesOnlyTheCompletedDevice() = withService { service, intent, connections ->
        val previous = service.readSetting
        service.readSetting = { if (it == BackgroundConnectionDuration.STORE_KEY) "OFF" else previous(it) }
        service.onStartCommand(intent(BleDeviceProfiles.GATE, "gate-a"), 0, 1)
        service.onStartCommand(intent(BleDeviceProfiles.CAR, "car-a"), 0, 2)
        connections.getValue("gate").ready(); connections.getValue("gate").complete()
        assertTrue(connections.getValue("gate").stopped)
        assertFalse(connections.getValue("car").stopped)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(3))
        assertTrue(PressWidgetProvider.isBusy("car"))
        assertFalse(shadowOf(service).isStoppedBySelf)
        connections.getValue("car").ready()
        assertEquals(1, connections.getValue("car").presses)
    }
    @Test fun completingAndExpiringOneWarmConnectionKeepsTheOtherDeviceAlive() = withService { service, intent, connections ->
        service.onStartCommand(intent(BleDeviceProfiles.GATE, "gate-a"), 0, 1)
        connections.getValue("gate").ready(); connections.getValue("gate").complete()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        service.onStartCommand(intent(BleDeviceProfiles.CAR, "car-a"), 0, 2)
        connections.getValue("car").ready(); connections.getValue("car").complete()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(25))
        assertTrue(connections.getValue("gate").stopped)
        assertFalse(connections.getValue("car").stopped)
        assertTrue(PressWidgetProvider.isConnected("car"))
        assertFalse(shadowOf(service).isStoppedBySelf)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(5))
        assertTrue(connections.getValue("car").stopped)
        assertTrue(shadowOf(service).isStoppedBySelf)
    }
}
