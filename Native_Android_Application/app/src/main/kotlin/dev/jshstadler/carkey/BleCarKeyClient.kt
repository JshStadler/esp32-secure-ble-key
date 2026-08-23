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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

class BleCarKeyClient(
    private val context: Context,
    private val bluetoothManager: BluetoothManager,
    private val profile: BleDeviceProfile,
    private val listener: Listener,
) {
    interface Listener {
        fun onState(state: State, message: String)
        fun onReadyChanged(ready: Boolean)
        fun onDeviceAddress(address: String)
        fun onDeviceState(state: String)
        fun onCommandResult(success: Boolean, message: String)
        fun onPskUpdateResult(success: Boolean, message: String)
        fun onDiagnostic(message: String)
        fun onOtaProgress(sent: Int, total: Int)
        fun onOtaResult(success: Boolean, message: String)
    }

    enum class State { DISCONNECTED, SCANNING, CONNECTING, CONNECTED }

    companion object {
        private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    private val handler = Handler(Looper.getMainLooper())
    private var gatt: BluetoothGatt? = null
    private var challenge: BluetoothGattCharacteristic? = null
    private var command: BluetoothGattCharacteristic? = null
    private var status: BluetoothGattCharacteristic? = null
    private var pskUpdate: BluetoothGattCharacteristic? = null
    private var otaControl: BluetoothGattCharacteristic? = null
    private var otaData: BluetoothGattCharacteristic? = null
    private var otaStatus: BluetoothGattCharacteristic? = null
    private var deviceState: BluetoothGattCharacteristic? = null
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
    private var pendingNewPsk: String? = null
    private var pskUpdateInFlight = false
    private var pskUpdateGeneration = 0
    private var otaImage: ByteArray? = null
    private var otaOffset = 0
    private var otaLastChunkSize = 0
    private var otaInFlight = false
    private var otaWaitingForReady = false
    private var otaStartWritePending = false
    private var otaStartWriteComplete = false
    private var otaFinishing = false
    private var negotiatedMtu = 23
    private var stateReadInFlight = false

    private val scanner get() = bluetoothManager.adapter?.bluetoothLeScanner

    private val statePoll = object : Runnable {
        @SuppressLint("MissingPermission")
        override fun run() {
            if (ready && !authInFlight && !pressInFlight && !pskUpdateInFlight && !otaInFlight) {
                deviceState?.let {
                    stateReadInFlight = true
                    if (gatt?.readCharacteristic(it) != true) stateReadInFlight = false
                    else handler.postDelayed({ stateReadInFlight = false }, 600)
                }
            }
            if (!manuallyStopped && deviceState != null) handler.postDelayed(this, 1_500)
        }
    }

    private val otaWriteTimeout = Runnable {
        if (!otaInFlight) return@Runnable
        val message = if (otaFinishing) {
            "Firmware validation response timed out"
        } else {
            "Firmware transfer stalled at byte $otaOffset"
        }
        finishOta(false, message)
    }

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
        // A user-configured profile address is always a hard target. A learned
        // address is used only while the per-device cached-address setting is on.
        reconnectAddress = if (useCachedAddress) cachedAddress else profile.defaultAddress
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
    private fun matches(result: ScanResult): Boolean {
        val targetAddress = reconnectAddress ?: profile.defaultAddress
        if (targetAddress != null) return result.device.address.equals(targetAddress, ignoreCase = true)
        return result.device.name == profile.advertisedName ||
            result.scanRecord?.serviceUuids?.any { it.uuid == profile.serviceUuid } == true
    }

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
                val wasUpdating = otaInFlight
                val wasUpdatingPsk = pskUpdateInFlight
                g.close()
                if (gatt === g) clearGatt()
                if (!wasReady && attemptingDirect) directFailures++
                listener.onReadyChanged(false)
                if (wasUpdating) {
                    manuallyStopped = true
                    listener.onOtaResult(false, "Bluetooth connection was lost during firmware update")
                }
                if (wasUpdatingPsk) {
                    manuallyStopped = true
                    listener.onPskUpdateResult(
                        false,
                        "Connection was lost during the PSK update; use app-only after confirming the car key",
                    )
                }
                if (!manuallyStopped) {
                    if (wasReady) listener.onState(State.DISCONNECTED, "Connection lost; reconnecting…")
                    scheduleReconnect()
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, statusCode: Int) {
            listener.onDiagnostic("MTU negotiation: mtu=$mtu, status=$statusCode")
            if (statusCode == BluetoothGatt.GATT_SUCCESS) negotiatedMtu = mtu
            g.discoverServices()
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(g: BluetoothGatt, result: Int) {
            listener.onDiagnostic("Service discovery completed: status=$result, services=${g.services.size}")
            if (result != BluetoothGatt.GATT_SUCCESS) return fail("Service discovery failed")
            val service = g.getService(profile.serviceUuid) ?: return fail("${profile.displayName} service not found")
            challenge = service.getCharacteristic(profile.challengeUuid)
            command = service.getCharacteristic(profile.commandUuid)
            status = service.getCharacteristic(profile.statusUuid)
            pskUpdate = service.getCharacteristic(profile.pskUpdateUuid)
            otaControl = service.getCharacteristic(profile.otaControlUuid)
            otaData = service.getCharacteristic(profile.otaDataUuid)
            otaStatus = service.getCharacteristic(profile.otaStatusUuid)
            deviceState = service.getCharacteristic(profile.deviceStateUuid)
            if (challenge == null || command == null || status == null) return fail("Required BLE characteristics missing")
            if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE) {
                listener.onDiagnostic("Required ${profile.displayName} characteristics found; using per-connection reads")
                descriptorStage = 4
                g.readCharacteristic(challenge)
            } else {
                listener.onDiagnostic("Required ${profile.displayName} characteristics found; enabling notifications")
                descriptorStage = 1
                enableNotifications(g, challenge!!)
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, result: Int) {
            if (result != BluetoothGatt.GATT_SUCCESS) return fail("Could not enable notifications")
            if (descriptorStage == 1) {
                descriptorStage = 2
                enableNotifications(g, status!!)
            } else if (descriptorStage == 2 && otaStatus != null) {
                descriptorStage = 3
                enableNotifications(g, otaStatus!!)
            } else {
                descriptorStage = 4
                g.readCharacteristic(challenge)
            }
        }

        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicRead(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, result: Int) {
            if (characteristic.uuid == profile.deviceStateUuid) stateReadInFlight = false
            if (result == BluetoothGatt.GATT_SUCCESS) handleValue(characteristic, characteristic.value ?: byteArrayOf())
        }

        override fun onCharacteristicRead(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, result: Int) {
            if (characteristic.uuid == profile.deviceStateUuid) stateReadInFlight = false
            if (result == BluetoothGatt.GATT_SUCCESS) handleValue(characteristic, value)
        }

        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            handleValue(characteristic, characteristic.value ?: byteArrayOf())
        }

        override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            handleValue(characteristic, value)
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWrite(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, result: Int) {
            if (result != BluetoothGatt.GATT_SUCCESS) {
                when (characteristic.uuid) {
                    profile.commandUuid -> fail("Command write failed ($result)")
                    profile.pskUpdateUuid -> finishPskUpdate(false, "Car PSK update write failed ($result)")
                    profile.otaControlUuid, profile.otaDataUuid -> finishOta(false, "Firmware transfer write failed ($result)")
                }
                return
            }
            if (characteristic.uuid == profile.otaControlUuid && otaInFlight && otaStartWritePending) {
                otaStartWritePending = false
                otaStartWriteComplete = true
                maybeStartOtaData()
            }
            if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE && characteristic.uuid == profile.commandUuid) {
                // ESPHome sends the ATT write response immediately before its
                // YAML on_write automation runs. A short delay avoids reading
                // the previous per-connection status value.
                handler.postDelayed({ g.readCharacteristic(status) }, 100)
            }
            if (characteristic.uuid == profile.otaDataUuid && otaInFlight) {
                handler.removeCallbacks(otaWriteTimeout)
                otaOffset += otaLastChunkSize
                otaLastChunkSize = 0
                listener.onOtaProgress(otaOffset, otaImage?.size ?: otaOffset)
                sendNextOtaChunk()
            }
        }
    }

    private fun handleValue(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        when (characteristic.uuid) {
            profile.challengeUuid -> {
                nonce = value.copyOf()
                if (!ready && !authInFlight && !otaInFlight && descriptorStage == 4) authenticate()
                listener.onReadyChanged(ready && value.isNotEmpty())
            }
            profile.statusUuid -> handleStatus(String(value, StandardCharsets.UTF_8))
            profile.otaStatusUuid -> handleOtaStatus(String(value, StandardCharsets.UTF_8))
            profile.deviceStateUuid -> {
                val state = String(value, StandardCharsets.UTF_8)
                if (!state.startsWith("ERR:")) listener.onDeviceState(state)
            }
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
                listener.onReadyChanged(profile.responseMode != BleResponseMode.READ_AFTER_WRITE && nonce != null)
                if (deviceState != null) {
                    handler.removeCallbacks(statePoll)
                    handler.post(statePoll)
                    if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE) {
                        handler.postDelayed({ readChallenge() }, 250)
                    }
                } else if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE) {
                    readChallenge()
                }
            }
            value == "OK:PRESSED" && pressInFlight -> {
                finishPress()
                listener.onCommandResult(true, "Pressed")
                if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE) readChallenge()
            }
            value == "OK:PRESSED" -> listener.onDiagnostic("Ignoring stale press confirmation")
            value == "OK:PSK_UPDATED" && pskUpdateInFlight -> {
                pendingNewPsk?.let { psk = it }
                finishPskUpdate(true, "PSK updated on phone and car")
                readChallenge()
            }
            value == "WARN:PSK_VOLATILE" && pskUpdateInFlight -> {
                pendingNewPsk?.let { psk = it }
                finishPskUpdate(false, "Car could not save the PSK; power-cycle the car ESP and try again")
            }
            value.startsWith("ERR:PSK_") && pskUpdateInFlight ->
                finishPskUpdate(false, "Car rejected the PSK update ($value)")
            value == "ERR:AUTH" && !ready -> {
                authInFlight = false
                authGeneration++
                if (authAttempts < 2) readChallenge() else fail("BLE authentication failed; check the PSK")
            }
            value == "ERR:BUSY" && pressInFlight -> {
                finishPress()
                listener.onDiagnostic("Remote button press failed: device busy")
                listener.onCommandResult(false, "Command failed")
                if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE) readChallenge()
            }
            value.startsWith("ERR:") && pressInFlight -> {
                finishPress()
                listener.onDiagnostic("Remote button press failed: $value")
                listener.onCommandResult(false, "Command failed")
                if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE) readChallenge()
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
        write(command ?: return, CarKeyProtocol.command(profile, CarKeyProtocol.AUTH_COMMAND, current, psk))
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
        handler.removeCallbacks(statePoll)
        if (stateReadInFlight) {
            handler.postDelayed({ press() }, 120)
            return
        }
        val current = nonce ?: return listener.onCommandResult(false, "Command failed")
        val commandCharacteristic = command ?: return listener.onCommandResult(false, "Command failed")
        listener.onDiagnostic("Sending authenticated button-press command")
        pressInFlight = true
        val generation = ++pressGeneration
        write(commandCharacteristic, CarKeyProtocol.command(profile, CarKeyProtocol.PRESS_COMMAND, current, psk))
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

    @SuppressLint("MissingPermission")
    fun startOta(image: ByteArray) {
        val current = nonce ?: return listener.onOtaResult(false, "No fresh challenge for firmware update")
        val control = otaControl
        if (control == null || otaData == null || otaStatus == null) {
            return listener.onOtaResult(false, "Car needs the one-time USB OTA bootstrap firmware first")
        }
        if (image.isEmpty() || image.size > 0x1e0000) {
            return listener.onOtaResult(false, "Firmware image size is invalid")
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(image)
        otaImage = image
        otaOffset = 0
        otaLastChunkSize = 0
        otaInFlight = true
        otaWaitingForReady = true
        otaStartWritePending = true
        otaStartWriteComplete = false
        otaFinishing = false
        ready = false
        listener.onReadyChanged(false)
        listener.onDiagnostic("Starting authenticated BLE OTA (${image.size} bytes)")
        val startPayload = CarKeyProtocol.otaStart(image.size, digest, current, psk)
        val highPriorityRequested = gatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH) == true
        listener.onDiagnostic("Requested high-throughput BLE connection for OTA: $highPriorityRequested")
        nonce = null
        handler.postDelayed({
            if (!otaInFlight) return@postDelayed
            if (!write(control, startPayload)) {
                finishOta(false, "Android could not queue the firmware start request")
                return@postDelayed
            }
            handler.postDelayed({
                if (otaInFlight && (otaWaitingForReady || otaStartWritePending)) {
                    finishOta(false, "ESP did not complete the firmware start request")
                }
            }, 5_000)
        }, if (highPriorityRequested) 750L else 0L)
    }

    /**
     * Re-read the per-connection challenge when the Activity and GATT ready
     * states have drifted apart. Reading while unauthenticated naturally
     * restarts authentication; reading while authenticated supplies the fresh
     * nonce required by OTA:START.
     */
    @SuppressLint("MissingPermission")
    fun requestFreshChallenge(): Boolean {
        val g = gatt ?: return false
        val c = challenge ?: return false
        listener.onDiagnostic("Requesting a fresh challenge for firmware update")
        nonce = null
        listener.onReadyChanged(false)
        return g.readCharacteristic(c)
    }

    private fun handleOtaStatus(value: String) {
        listener.onDiagnostic("OTA status: $value")
        when {
            value == "OTA:READY" && otaInFlight -> {
                otaWaitingForReady = false
                listener.onOtaProgress(0, otaImage?.size ?: 0)
                maybeStartOtaData()
            }
            value == "OTA:OK" && otaInFlight -> finishOta(true, "Firmware updated; car ESP is restarting")
            value.startsWith("ERR:OTA_") && otaInFlight -> finishOta(false, otaErrorMessage(value))
        }
    }

    private fun otaErrorMessage(status: String): String = when (status) {
        "ERR:OTA_AUTH" -> "Firmware update authentication failed"
        "ERR:OTA_BUSY" -> "Another phone is already updating the car"
        "ERR:OTA_SIZE" -> "Firmware image does not fit the OTA partition"
        "ERR:OTA_DIGEST" -> "Firmware was corrupted during transfer"
        "ERR:OTA_IMAGE" -> "Firmware signature or image validation failed"
        else -> "Car rejected firmware update ($status)"
    }

    private fun sendNextOtaChunk() {
        if (!otaInFlight || otaWaitingForReady) return
        val image = otaImage ?: return finishOta(false, "Firmware data was lost")
        if (otaOffset >= image.size) {
            listener.onDiagnostic("Firmware transfer complete; requesting signed-image validation")
            otaFinishing = true
            if (!write(otaControl ?: return finishOta(false, "OTA control characteristic disappeared"), byteArrayOf(0x02))) {
                finishOta(false, "Android could not queue firmware validation")
                return
            }
            handler.removeCallbacks(otaWriteTimeout)
            handler.postDelayed(otaWriteTimeout, 10_000)
            return
        }

        /* ATT writes carry MTU-3 bytes. Leave two bytes of headroom, then
         * reserve four bytes for the firmware offset. The current 185 MTU
         * sends 176-byte chunks; upgraded firmware can negotiate 517 and
         * accept 508-byte chunks. */
        val mtuDataCapacity = (negotiatedMtu - 9).coerceAtLeast(14)
        val count = minOf(508, mtuDataCapacity, image.size - otaOffset)
        val payload = ByteBuffer.allocate(4 + count).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(otaOffset)
            .put(image, otaOffset, count)
            .array()
        otaLastChunkSize = count
        if (!write(otaData ?: return finishOta(false, "OTA data characteristic disappeared"), payload)) {
            otaLastChunkSize = 0
            finishOta(false, "Android could not queue firmware data at byte $otaOffset")
            return
        }
        handler.removeCallbacks(otaWriteTimeout)
        handler.postDelayed(otaWriteTimeout, 5_000)
    }

    private fun maybeStartOtaData() {
        if (!otaInFlight || otaWaitingForReady || !otaStartWriteComplete) return
        if (otaOffset == 0 && otaLastChunkSize == 0 && !otaFinishing) sendNextOtaChunk()
    }

    @SuppressLint("MissingPermission")
    private fun finishOta(success: Boolean, message: String) {
        if (!otaInFlight) return
        otaInFlight = false
        gatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_BALANCED)
        otaWaitingForReady = false
        otaStartWritePending = false
        otaStartWriteComplete = false
        otaFinishing = false
        handler.removeCallbacks(otaWriteTimeout)
        otaImage = null
        otaLastChunkSize = 0
        listener.onOtaResult(success, message)
    }

    private fun finishPress() {
        pressInFlight = false
        pressGeneration++
        if (deviceState != null && !manuallyStopped) handler.postDelayed(statePoll, 500)
    }

    fun updatePsk(newPsk: String): Boolean {
        val current = nonce ?: return false
        val characteristic = pskUpdate ?: return false
        pendingNewPsk = newPsk
        pskUpdateInFlight = true
        val generation = ++pskUpdateGeneration
        listener.onDiagnostic("Sending authenticated car PSK update")
        write(characteristic, CarKeyProtocol.pskUpdate(profile, current, psk, newPsk))
        nonce = null
        listener.onReadyChanged(false)
        handler.postDelayed({
            if (pskUpdateInFlight && generation == pskUpdateGeneration) {
                finishPskUpdate(false, "Car PSK update timed out")
            }
        }, 3_500)
        return true
    }

    private fun finishPskUpdate(success: Boolean, message: String) {
        if (!pskUpdateInFlight) return
        pskUpdateInFlight = false
        pskUpdateGeneration++
        pendingNewPsk = null
        listener.onPskUpdateResult(success, message)
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
    private fun write(c: BluetoothGattCharacteristic, value: ByteArray): Boolean {
        val g = gatt ?: return false
        return if (Build.VERSION.SDK_INT >= 33) {
            g.writeCharacteristic(c, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothStatusCodes.SUCCESS
        } else {
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
        otaControl = null
        otaData = null
        otaStatus = null
        deviceState = null
        stateReadInFlight = false
        handler.removeCallbacks(statePoll)
        nonce = null
        ready = false
        authAttempts = 0
        descriptorStage = 0
        authInFlight = false
        authGeneration++
        pendingNewPsk = null
        pskUpdateInFlight = false
        pskUpdateGeneration++
        otaImage = null
        otaInFlight = false
        otaWaitingForReady = false
        otaStartWritePending = false
        otaStartWriteComplete = false
        otaFinishing = false
        handler.removeCallbacks(otaWriteTimeout)
        otaOffset = 0
        otaLastChunkSize = 0
        negotiatedMtu = 23
    }
}
