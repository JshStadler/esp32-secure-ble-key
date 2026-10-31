package dev.logiclabs.remotekey

import android.app.AlertDialog
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowAlertDialog
import java.security.MessageDigest
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class FirmwareUpdatePanelTest {
    private class InlineWorker : AbstractExecutorService() {
        override fun execute(command: Runnable) = command.run()
        override fun shutdown() {}
        override fun shutdownNow(): MutableList<Runnable> = mutableListOf()
        override fun isShutdown() = false
        override fun isTerminated() = false
        override fun awaitTermination(timeout: Long, unit: TimeUnit) = true
    }
    private val image = ByteArray(80).apply { this[0] = 0xe9.toByte(); this[12] = 5 }
    private fun feed(): ByteArray {
        val hash = MessageDigest.getInstance("SHA-256").digest(image).joinToString("") { "%02x".format(it) }
        return """[{"tag_name":"firmware-v2.8.11","draft":false,"prerelease":true,"assets":[{"name":"BLE-Car-Key-v2.8.11-signed-ota.bin","size":80,"digest":"sha256:$hash","browser_download_url":"${FirmwareUpdates.REPO}/releases/download/firmware-v2.8.11/BLE-Car-Key-v2.8.11-signed-ota.bin"}]}]""".toByteArray()
    }
    @Test fun checkingAndDownloadingNeverStartOtaWithoutTheInstallConfirmation() {
        Robolectric.buildActivity(FragmentActivity::class.java).setup().use { controller ->
            val activity = controller.get().apply { setTheme(R.style.Theme_CarKey) }
            var fetches = 0; var installs = 0
            val repository = FirmwareUpdates { url, _ -> fetches++; if (url == FirmwareUpdates.FEED) feed() else image }
            val panel = FirmwareUpdatePanel(activity, BleDeviceProfiles.CAR, { DeviceHealth.signalOnly().copy(firmware = "2.8.4") },
                { assertArrayEquals(image, it); installs++ }, repository, InlineWorker())
            panel.start(); shadowOf(Looper.getMainLooper()).idle()
            assertEquals(1, fetches); assertEquals(0, installs)
            assertTrue((panel.getChildAt(0) as TextView).text.startsWith("Update available"))
            (panel.getChildAt(1) as Button).performClick(); shadowOf(Looper.getMainLooper()).idle()
            assertEquals(2, fetches); assertEquals(0, installs)
            ShadowAlertDialog.getLatestAlertDialog().getButton(AlertDialog.BUTTON_POSITIVE).performClick()
            shadowOf(Looper.getMainLooper()).idle()
            assertEquals(1, installs)
            panel.close()
        }
    }
    @Test fun aDownloadCallbackCannotShowAnInstallDialogAfterSettingsClose() {
        Robolectric.buildActivity(FragmentActivity::class.java).setup().use { controller ->
            val activity = controller.get().apply { setTheme(R.style.Theme_CarKey) }
            val repository = FirmwareUpdates { url, _ -> if (url == FirmwareUpdates.FEED) feed() else image }
            val panel = FirmwareUpdatePanel(activity, BleDeviceProfiles.CAR, { null }, { fail("Closed settings must not install") }, repository, InlineWorker())
            panel.start(); shadowOf(Looper.getMainLooper()).idle()
            (panel.getChildAt(1) as Button).performClick()
            panel.close(); shadowOf(Looper.getMainLooper()).idle()
            assertNull(ShadowAlertDialog.getLatestAlertDialog())
        }
    }
}
