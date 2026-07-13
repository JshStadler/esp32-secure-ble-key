package dev.jshstadler.carkey

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.nio.charset.StandardCharsets
import java.util.UUID

class BleCarKeyClient(
    private val context: Context,
    private val bluetoothManager: BluetoothManager,
    private val listener: Listener,
) {
    interface Listener {
        fun onState(state: State, message: String)
        fun onReadyChanged(ready: Boolean)
        fun onDeviceAddress(address: String)
        fun onCommandResult(success: Boolean, message: String)
        fun onDiagnostic(message: String)
    }

    enum class State { DISCONNECTED, SCANNING, CONNECTING, CONNECTED }

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        private val CHALLENGE_UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567891")
        private val COMMAND_UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567892")
        private val STATUS_UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567893")
        private val PSK_UPDATE_UUID = UUID.fromString("a1b2c3d4-e5f6-7890-abcd-ef1234567894")
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    private val handler = Handler(Looper.getMainLooper())
    private var gatt: BluetoothGatt? = null
    private var challenge: BluetoothGattCharacteristic? = null
    private var command: BluetoothGattCharacteristic? = null
    private var status: BluetoothGattCharacteristic? = null
    private var pskUpdate: BluetoothGattCharacteristic? = null
    private var nonce: ByteArray? = null
    private var psk = ""
    private var ready = false
    private var manuallyStopped = false
    private var authAttempts = 0
    private var reconnectAddress: String? = null
    private var directFailures = 0
    private var preferDirect = false
    private var descriptorStage = 0
    private var authInFlight = false
    private var authGeneration = 0
    private var attemptingDirect = false
    private var awaitingScanFallback = false
    private var pressInFlight = false
    private var pressGeneration = 0

    private val scanner get() = bluetoothManager.adapter?.bluetoothLeScanner

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) = acceptScan(result)
        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            results.firstOrNull { matches(it) }?.let(::acceptScan)
        }
        override fun onScanFailed(errorCode: Int) = fail("Scan error ($errorCode)")
    }

    @SuppressLint("MissingPermission")
    fun start(key: String, cachedAddress: String?, useCachedAddress: Boolean) {
        psk = key
        reconnectAddress = cachedAddress
        preferDirect = useCachedAddress
        manuallyStopped = false
        if (!useCachedAddress) {
            awaitingScanFallback = false
            directFailures = 0
        }
        if (useCachedAddress && cachedAddress != null) {
            attemptingDirect = true
            listener.onState(State.CONNECTING, "Connecting to cached device…")
            try {
                connect(bluetoothManager.adapter.getRemoteDevice(cachedAddress))
            } catch (_: IllegalArgumentException) {
                scan()
            }
        } else {
            attemptingDirect = false
            scan()
        }
    }

    @SuppressLint("MissingPermission")
    fun stop(manual: Boolean = true) {
        manuallyStopped = manual
        handler.removeCallbacksAndMessages(null)
        scanner?.stopScan(scanCallback)
        gatt?.disconnect()
        gatt?.close()
        clearGatt()
        listener.onState(State.DISCONNECTED, "Disconnected")
    }

    fun scanFallback() {
        directFailures = 3
        awaitingScanFallback = false
        attemptingDirect = false
        stop(false)
        manuallyStopped = false
        scan()
    }

    @SuppressLint("MissingPermission")
    private fun scan() {
        attemptingDirect = false
        listener.onState(State.SCANNING, "Scanning…")
        scanner?.startScan(scanCallback) ?: return fail("Bluetooth is off")
        handler.postDelayed({
            scanner?.stopScan(scanCallback)
            if (gatt == null) fail("Device not found")
        }, 10_000)
    }

    @SuppressLint("MissingPermission")
    private fun matches(result: ScanResult): Boolean =
        result.device.address == reconnectAddress ||
            result.device.name == "BLE-Device" ||
            result.scanRecord?.serviceUuids?.any { it.uuid == SERVICE_UUID } == true

    @SuppressLint("MissingPermission")
    private fun acceptScan(result: ScanResult) {
        if (!matches(result) || gatt != null) return
        listener.onDiagnostic("Scan matched device ${result.device.address}, RSSI ${result.rssi} dBm")
        scanner?.stopScan(scanCallback)
        listener.onState(State.CONNECTING, "Connecting…")
        connect(result.device)
    }

    @SuppressLint("MissingPermission")
    private fun connect(device: BluetoothDevice) {
        gatt?.close()
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
    }

    private val callback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(g: BluetoothGatt, statusCode: Int, newState: Int) {
            listener.onDiagnostic("GATT connection callback: status=$statusCode, state=$newState, address=${g.device.address}")
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                reconnectAddress = g.device.address
                listener.onDeviceAddress(g.device.address)
                listener.onState(State.CONNECTING, "Discovering services…")
                handler.postDelayed({ if (!g.requestMtu(517)) g.discoverServices() }, 300)
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                val wasReady = ready
                g.close()
                if (gatt === g) clearGatt()
                if (!wasReady && attemptingDirect) directFailures++
                listener.onReadyChanged(false)
                if (!manuallyStopped) {
                    if (wasReady) listener.onState(State.DISCONNECTED, "Connection lost; reconnectingâ€¦")
                    scheduleReconnect()
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, statusCode: Int) {
            listener.onDiagnostic("MTU negotiation: mtu=$mtu, status=$statusCode")
            g.discoverServices()
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(g: BluetoothGatt, result: Int) {
            listener.onDiagnostic("Service discovery completed: status=$result, services=${g.services.size}")
            if (result != BluetoothGatt.GATT_SUCCESS) return fail("Service discovery failed")
            val service = g.getService(SERVICE_UUID) ?: return fail("Car Key service not found")
            challenge = service.getCharacteristic(CHALLENGE_UUID)
            command = service.getCharacteristic(COMMAND_UUID)
            status = service.getCharacteristic(STATUS_UUID)
            pskUpdate = service.getCharacteristic(PSK_UPDATE_UUID)
            if (challenge == null || command == null || status == null) return fail("Required BLE characteristics missing")
            listener.onDiagnostic("Required Car Key characteristics found; enabling notifications")
            descriptorStage = 1
            enableNotifications(g, challenge!!)
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, result: Int) {
            if (result != BluetoothGatt.GATT_SUCCESS) return fail("Could not enable notifications")
            if (descriptorStage == 1) {
                descriptorStage = 2
                enableNotifications(g, status!!)
            } else {
                descriptorStage = 3
                g.readCharacteristic(challenge)
            }
        }

        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicRead(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, result: Int) {
            if (result == BluetoothGatt.GATT_SUCCESS) handleValue(characteristic, characteristic.value ?: byteArrayOf())
        }

        override fun onCharacteristicRead(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, result: Int) {
            if (result == BluetoothGatt.GATT_SUCCESS) handleValue(characteristic, value)
        }

        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            handleValue(characteristic, characteristic.value ?: byteArrayOf())
        }

        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            handleValue(characteristic, value)
        }
    }

    private fun handleValue(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        when (characteristic.uuid) {
            CHALLENGE_UUID -> {
                nonce = value.copyOf()
                if (!ready && !authInFlight && descriptorStage == 3) authenticate()
                listener.onReadyChanged(ready && value.isNotEmpty())
            }
            STATUS_UUID -> handleStatus(String(value, StandardCharsets.UTF_8))
        }
    }

    private fun handleStatus(value: String) {
        listener.onDiagnostic("Device status: $value")
        when {
            value == "OK:AUTH" -> {
                authInFlight = false
                authGeneration++
                ready = true
                directFailures = 0
                awaitingScanFallback = false
                listener.onState(State.CONNECTED, "Authenticated")
                listener.onReadyChanged(nonce != null)
            }
            value == "OK:PRESSED" && pressInFlight -> {
                finishPress()
                listener.onCommandResult(true, "Pressed")
            }
            value == "OK:PRESSED" -> listener.onDiagnostic("Ignoring stale press confirmation")
            value == "OK:PSK_UPDATED" -> listener.onCommandResult(true, "PSK updated on device")
            value == "WARN:PSK_VOLATILE" -> listener.onCommandResult(true, "PSK updated, but not saved to flash")
            value == "ERR:AUTH" && !ready -> {
                authInFlight = false
                authGeneration++
                if (authAttempts < 2) readChallenge() else fail("BLE authentication failed; check the PSK")
            }
            value == "ERR:BUSY" && pressInFlight -> {
                finishPress()
                listener.onDiagnostic("Remote button press failed: device busy")
                listener.onCommandResult(false, "Command failed")
            }
            value.startsWith("ERR:") && pressInFlight -> {
                finishPress()
                listener.onDiagnostic("Remote button press failed: $value")
                listener.onCommandResult(false, "Command failed")
            }
            value.startsWith("ERR:") -> listener.onDiagnostic("Ignoring status with no command in flight: $value")
        }
    }

    private fun authenticate() {
        val current = nonce ?: return
        authAttempts++
        authInFlight = true
        val generation = ++authGeneration
        listener.onDiagnostic("Sending authentication challenge response, attempt $authAttempts")
        listener.onState(State.CONNECTING, "Authenticating…")
        write(command ?: return, CarKeyProtocol.command(CarKeyProtocol.AUTH_COMMAND, current, psk))
        nonce = null
        handler.postDelayed({
            if (authInFlight && !ready && generation == authGeneration) {
                authInFlight = false
                listener.onDiagnostic("Authentication response timed out on attempt $authAttempts")
                if (authAttempts < 2) readChallenge() else fail("BLE authentication timed out")
            }
        }, 2_500)
    }

    fun press() {
        val current = nonce ?: return listener.onCommandResult(false, "Command failed")
        val commandCharacteristic = command ?: return listener.onCommandResult(false, "Command failed")
        listener.onDiagnostic("Sending authenticated button-press command")
        pressInFlight = true
        val generation = ++pressGeneration
        write(commandCharacteristic, CarKeyProtocol.command(CarKeyProtocol.PRESS_COMMAND, current, psk))
        nonce = null
        listener.onReadyChanged(false)
        handler.postDelayed({
            if (pressInFlight && generation == pressGeneration) {
                finishPress()
                listener.onDiagnostic("Remote button press received no confirmation")
                listener.onCommandResult(false, "No confirmation")
            }
        }, 2_500)
    }

    private fun finishPress() {
        pressInFlight = false
        pressGeneration++
    }

    fun updatePsk(newPsk: String): Boolean {
        val current = nonce ?: return false
        val characteristic = pskUpdate ?: return false
        write(characteristic, CarKeyProtocol.pskUpdate(current, psk, newPsk))
        nonce = null
        psk = newPsk
        listener.onReadyChanged(false)
        return true
    }

    @SuppressLint("MissingPermission")
    private fun readChallenge() {
        nonce = null
        gatt?.readCharacteristic(challenge)
    }

    @SuppressLint("MissingPermission")
    private fun enableNotifications(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
        g.setCharacteristicNotification(c, true)
        val descriptor = c.getDescriptor(CCCD_UUID) ?: return fail("Notification descriptor missing")
        if (Build.VERSION.SDK_INT >= 33) g.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
        else {
            @Suppress("DEPRECATION")
            run {
                descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                g.writeDescriptor(descriptor)
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun write(c: BluetoothGattCharacteristic, value: ByteArray) {
        val g = gatt ?: return
        if (Build.VERSION.SDK_INT >= 33) g.writeCharacteristic(c, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
        else {
            @Suppress("DEPRECATION")
            run {
                c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                c.value = value
                g.writeCharacteristic(c)
            }
        }
    }

    private fun fail(message: String) {
        listener.onDiagnostic("BLE failure: $message")
        listener.onState(State.DISCONNECTED, message)
        listener.onReadyChanged(false)
        if (!manuallyStopped) scheduleReconnect()
    }

    private fun scheduleReconnect() {
        if (AppPolicies.shouldOfferScanFallback(directFailures, preferDirect)) {
            awaitingScanFallback = true
            listener.onState(State.DISCONNECTED, "Cached device unavailable — scan fallback available")
            handler.removeCallbacksAndMessages(null)
            handler.postDelayed({ if (!manuallyStopped) start(psk, reconnectAddress, true) }, 1_500)
            return
        }
        listener.onState(State.DISCONNECTED, "Reconnecting…")
        handler.removeCallbacksAndMessages(null)
        handler.postDelayed({ if (!manuallyStopped) start(psk, reconnectAddress, preferDirect) }, 1_500)
    }

    private fun clearGatt() {
        gatt = null
        challenge = null
        command = null
        status = null
        pskUpdate = null
        nonce = null
        ready = false
        authAttempts = 0
        descriptorStage = 0
        authInFlight = false
        authGeneration++
    }
}
