package dev.jshstadler.carkey

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/** All state and ATT requests are confined to the main dispatcher. */
@SuppressLint("MissingPermission")
class BleCarKeyClient(private val context: Context, private val bluetoothManager: BluetoothManager,
    private val profile: BleDeviceProfile, private val listener: Listener) {
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
    companion object { private val CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb") }
    private val handler = Handler(Looper.getMainLooper())
    private var epoch = 0
    private var stage = "idle"
    private var gatt: BluetoothGatt? = null
    private var scanCallback: ScanCallback? = null
    private var challenge: BluetoothGattCharacteristic? = null
    private var command: BluetoothGattCharacteristic? = null
    private var status: BluetoothGattCharacteristic? = null
    private var pskUpdate: BluetoothGattCharacteristic? = null
    private var otaControl: BluetoothGattCharacteristic? = null
    private var otaData: BluetoothGattCharacteristic? = null
    private var otaStatus: BluetoothGattCharacteristic? = null
    private var deviceState: BluetoothGattCharacteristic? = null
    private var nonce: ByteArray? = null
    private var readValue = byteArrayOf()
    private var psk = ""
    private var ready = false
    private var stopped = true
    private var reconnectAddress: String? = null
    private var preferDirect = false
    private var attemptingDirect = false
    private var directFailures = 0
    private var securePskSupported = false
    private var healthSupported = false
    private var radioSupported = false
    private var healthCallback: ((DeviceHealth?, String?) -> Unit)? = null
    private var radioCallback: ((Boolean, String) -> Unit)? = null
    private var radioResponse: String? = null
    private var radioWritePending = false
    private var radioGeneration = 0
    private var pendingCommand: Byte? = null
    private var commandWritePending = false
    private var pendingStatus: String? = null
    private var commandGeneration = 0
    private var pendingNewPsk: String? = null
    private var pskRequest: PskUpdateProtocol.Request? = null
    private var negotiatedMtu = 23
    private var otaImage: ByteArray? = null
    private var otaOffset = 0
    private var otaInFlight = false
    private var otaWaitingForReady = false
    private var otaStartWriteComplete = false
    private var otaChunkPending = false
    private var otaFinishing = false
    private var otaGeneration = 0
    private var otaResponse: String? = null
    private val queue = GattOperationQueue(
        schedule = { delay, action -> val task = Runnable(action); handler.postDelayed(task, delay); { handler.removeCallbacks(task) } },
        failed = { fail(it) }, idle = { publishReady() },
    )
    private val scanner get() = bluetoothManager.adapter?.bluetoothLeScanner
    private fun diagnostic(message: String) = listener.onDiagnostic("session=$epoch stage=$stage $message")
    private fun later(delay: Long, action: () -> Unit) {
        val generation = epoch
        handler.postDelayed({ if (!stopped && generation == epoch) action() }, delay)
    }
    private fun dispatch(g: BluetoothGatt, action: () -> Unit) {
        handler.post { if (!stopped && gatt === g) action() }
    }
    private fun publishReady() {
        listener.onReadyChanged(!stopped && ready && nonce?.size == 16 && !queue.busy &&
            pendingCommand == null && pskRequest == null && !otaInFlight && radioCallback == null)
    }
    fun start(key: String, cachedAddress: String?, useCachedAddress: Boolean) {
        teardown()
        stopped = false
        psk = key
        preferDirect = useCachedAddress
        reconnectAddress = if (useCachedAddress) cachedAddress else profile.defaultAddress
        attemptingDirect = useCachedAddress && reconnectAddress != null
        if (attemptingDirect) {
            listener.onState(State.CONNECTING, "Connecting to cached device…")
            val device = runCatching { bluetoothManager.adapter?.getRemoteDevice(reconnectAddress) }.getOrNull()
            if (device == null) scan() else connect(device)
        } else scan()
    }
    fun stop(manual: Boolean = true) {
        stopped = manual
        teardown()
        listener.onState(State.DISCONNECTED, "Disconnected")
        listener.onReadyChanged(false)
    }
    fun scanFallback() {
        preferDirect = false
        reconnectAddress = profile.defaultAddress
        directFailures = 0
        teardown()
        stopped = false
        scan()
    }
    private fun scan() {
        attemptingDirect = false
        stage = "scan"
        listener.onState(State.SCANNING, "Scanning…")
        val generation = epoch
        val callback = object : ScanCallback() {
            override fun onScanResult(type: Int, result: ScanResult) {
                handler.post { if (!stopped && generation == epoch && scanCallback === this) acceptScan(result) }
            }
            override fun onBatchScanResults(results: MutableList<ScanResult>) { results.forEach { onScanResult(0, it) } }
            override fun onScanFailed(errorCode: Int) {
                handler.post { if (!stopped && generation == epoch && scanCallback === this) fail("Scan error ($errorCode)") }
            }
        }
        scanCallback = callback
        val scan = scanner ?: return fail("Bluetooth is off")
        try { scan.startScan(callback) } catch (_: Exception) { return fail("Android could not start scanning") }
        later(10_000) { if (scanCallback === callback) fail("Device not found") }
    }
    private fun acceptScan(result: ScanResult) {
        if (gatt != null) return
        val target = reconnectAddress ?: profile.defaultAddress
        val matches = if (target != null) result.device.address.equals(target, true) else
            result.device.name == profile.advertisedName || result.scanRecord?.serviceUuids?.any { it.uuid == profile.serviceUuid } == true
        if (!matches) return
        diagnostic("Scan matched ${result.device.address}, RSSI ${result.rssi} dBm")
        stopScan()
        connect(result.device)
    }
    private fun stopScan() {
        val callback = scanCallback
        scanCallback = null
        if (callback != null) runCatching { scanner?.stopScan(callback) }
    }
    private fun connect(device: BluetoothDevice) {
        stage = "connect"
        listener.onState(State.CONNECTING, "Connecting…")
        gatt = try { device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE) } catch (_: Exception) { null }
        if (gatt == null) return fail("Android could not create a Bluetooth connection")
        later(18_000) { if (!ready) fail("Connection setup timed out at $stage") }
    }
    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, code: Int, state: Int) = dispatch(g) {
            diagnostic("GATT status=$code state=$state address=${g.device.address}")
            if (code != BluetoothGatt.GATT_SUCCESS || state == BluetoothProfile.STATE_DISCONNECTED) fail("Bluetooth disconnected (status=$code)")
            else if (state == BluetoothProfile.STATE_CONNECTED && stage == "connect") {
                reconnectAddress = g.device.address
                listener.onDeviceAddress(g.device.address)
                stage = "mtu"
                later(300) {
                    queue.enqueue("mtu", { g.requestMtu(517) }) {
                        if (negotiatedMtu < 36) fail("BLE MTU is too small for authenticated commands")
                        else {
                            stage = "services"
                            queue.enqueue("services", { g.discoverServices() }) { configureServices(g) }
                        }
                    }
                }
            }
        }
        override fun onMtuChanged(g: BluetoothGatt, mtu: Int, code: Int) = dispatch(g) {
            diagnostic("MTU=$mtu status=$code")
            if (code == BluetoothGatt.GATT_SUCCESS) negotiatedMtu = mtu
            queue.complete("mtu", code == BluetoothGatt.GATT_SUCCESS)
        }
        override fun onServicesDiscovered(g: BluetoothGatt, code: Int) = dispatch(g) {
            diagnostic("Service discovery status=$code")
            queue.complete("services", code == BluetoothGatt.GATT_SUCCESS)
        }
        override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, code: Int) = dispatch(g) {
            diagnostic("Descriptor ${d.characteristic.uuid} status=$code")
            queue.complete("notify:${d.characteristic.uuid}", code == BluetoothGatt.GATT_SUCCESS)
        }
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, code: Int) {
            @Suppress("DEPRECATION") val value = c.value?.copyOf() ?: byteArrayOf()
            receiveRead(g, c, value, code)
        }
        override fun onCharacteristicRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, code: Int) = receiveRead(g, c, value.copyOf(), code)
        @Deprecated("Deprecated in API 33")
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION") val value = c.value?.copyOf() ?: byteArrayOf()
            receiveNotification(g, c, value)
        }
        override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) = receiveNotification(g, c, value.copyOf())
        override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, code: Int) = dispatch(g) {
            if (c.uuid != profile.otaDataUuid) diagnostic("Write ${c.uuid} status=$code")
            queue.complete("write:${c.uuid}", code == BluetoothGatt.GATT_SUCCESS)
        }
    }
    private fun receiveRead(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray, code: Int) = dispatch(g) {
        readValue = value
        diagnostic("Read ${c.uuid} status=$code bytes=${value.size}")
        queue.complete("read:${c.uuid}", code == BluetoothGatt.GATT_SUCCESS)
    }
    private fun receiveNotification(g: BluetoothGatt, c: BluetoothGattCharacteristic, value: ByteArray) = dispatch(g) {
        when (c.uuid) {
            profile.challengeUuid -> { if (value.size == 16) nonce = value else fail("Invalid challenge length") }
            profile.statusUuid -> handleStatus(value.toString(Charsets.UTF_8))
            profile.otaStatusUuid -> handleOtaStatus(value.toString(Charsets.UTF_8))
        }
        publishReady()
    }
    private fun configureServices(g: BluetoothGatt) {
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
        stage = "subscribe"
        if (profile.responseMode == BleResponseMode.NOTIFICATIONS) {
            enableNotifications(g, challenge!!)
            if (gatt !== g) return
            enableNotifications(g, status!!)
            if (gatt !== g) return
            otaStatus?.let { enableNotifications(g, it) }
            if (gatt !== g) return
        }
        service.getCharacteristic(profile.identityUuid)?.let { identity ->
            // This is before authentication: firmware returns static capabilities only.
            read(identity) {
                val caps = it.toString(Charsets.UTF_8).split('|').last().split(',')
                securePskSupported = "psk2" in caps
                healthSupported = "health1" in caps
                radioSupported = "radio1" in caps
            }
        }
        readChallenge()
    }
    private fun enableNotifications(g: BluetoothGatt, c: BluetoothGattCharacteristic) {
        if (stopped || gatt !== g) return
        queue.enqueue("notify:${c.uuid}", {
            val descriptor = c.getDescriptor(CCCD_UUID)
            if (descriptor == null || !g.setCharacteristicNotification(c, true)) false
            else if (Build.VERSION.SDK_INT >= 33) g.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS
            else {
                @Suppress("DEPRECATION")
                descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                @Suppress("DEPRECATION")
                g.writeDescriptor(descriptor)
            }
        })
    }
    private fun read(c: BluetoothGattCharacteristic, done: (ByteArray) -> Unit) {
        val g = gatt ?: return
        if (!stopped) queue.enqueue("read:${c.uuid}", { g.readCharacteristic(c) }) { done(readValue) }
    }
    private fun readChallenge() {
        val c = challenge ?: return
        if (queue.contains("read:${c.uuid}")) return
        nonce = null
        listener.onReadyChanged(false)
        if (!ready) stage = "challenge"
        read(c) { value ->
            if (value.size != 16) fail("Invalid challenge length ${value.size}")
            else {
                nonce = value.copyOf()
                if (!ready && pendingCommand == null && !otaInFlight) sendCommand(CarKeyProtocol.AUTH_COMMAND)
            }
        }
    }
    fun requestFreshChallenge(): Boolean {
        if (stopped || gatt == null || challenge == null || pendingCommand != null || pskRequest != null || otaInFlight || radioCallback != null) return false
        readChallenge()
        return true
    }

    fun requestDeviceHealth(done: (DeviceHealth?, String?) -> Unit) {
        if (stopped || !ready || queue.busy || pendingCommand != null || pskRequest != null || otaInFlight || healthCallback != null || radioCallback != null) {
            done(null, "Connection is busy or recovering. Try Refresh when connected.")
            return
        }
        val identity = gatt?.getService(profile.serviceUuid)?.getCharacteristic(profile.identityUuid)
        if (!healthSupported || identity == null) {
            done(null, "Device health requires Car firmware v2.7.0 or later. Update the ESP, then reconnect.")
            return
        }
        healthCallback = done
        listener.onReadyChanged(false)
        read(identity) {
            val callback = healthCallback
            healthCallback = null
            val snapshot = DeviceHealth.parse(it.toString(Charsets.UTF_8))
            callback?.invoke(snapshot, if (snapshot == null) "Device returned incomplete health data. Try Refresh after reconnecting." else null)
        }
    }

    fun cancelDeviceHealth() { healthCallback = null }

    fun updateRadioSettings(settings: RadioSettings, done: (Boolean, String) -> Unit) {
        val control = otaControl
        val current = nonce
        if (!radioSupported || control == null) { done(false, "Update the Car firmware to v2.7.0 or later first."); return }
        if (stopped || !ready || current == null || queue.busy || pendingCommand != null || pskRequest != null ||
            otaInFlight || radioCallback != null || healthCallback != null) {
            done(false, "Connection is busy or recovering. Try again when connected."); return
        }
        if (!settings.valid() || negotiatedMtu < 46) { done(false, "Invalid settings or BLE MTU too small; reconnect and try again."); return }
        radioCallback = done
        radioResponse = null
        radioWritePending = true
        val generation = ++radioGeneration
        nonce = null
        listener.onReadyChanged(false)
        write(control, settings.packet(current, psk)) {
            radioWritePending = false
            radioResponse?.let { handleRadioStatus(it) }
        }
        later(8_000) { if (radioCallback != null && generation == radioGeneration) fail("Advertising settings response timed out") }
    }

    private fun handleRadioStatus(value: String) {
        if (radioCallback == null || !(value == "RADIO:OK" || value.startsWith("ERR:RADIO_"))) return
        if (radioWritePending) { radioResponse = value; return }
        val callback = radioCallback
        radioCallback = null
        radioResponse = null
        radioGeneration++
        readChallenge()
        val message = when (value) {
            "RADIO:OK" -> "Advertising settings saved on the ESP and applied."
            "ERR:RADIO_BUSY" -> "Wait until the firmware update and startup health check finish, then retry."
            "ERR:RADIO_SAVE" -> "ESP could not save settings; previous settings remain active."
            "ERR:RADIO_RANGE" -> "ESP rejected the interval range."
            else -> "ESP rejected settings authentication. Reconnect and retry."
        }
        callback?.invoke(value == "RADIO:OK", message)
    }
    fun press() {
        if (!ready || nonce == null || pendingCommand != null || pskRequest != null || otaInFlight || radioCallback != null) {
            listener.onCommandResult(false, "Connection is recovering; try again")
            if (ready) readChallenge()
            return
        }
        sendCommand(CarKeyProtocol.PRESS_COMMAND)
    }
    private fun sendCommand(cmd: Byte) {
        val current = nonce ?: return fail("No fresh challenge")
        val c = command ?: return fail("Command characteristic missing")
        pendingCommand = cmd
        pendingStatus = null
        commandWritePending = true
        val generation = ++commandGeneration
        if (cmd == CarKeyProtocol.AUTH_COMMAND) { stage = "authenticate"; listener.onState(State.CONNECTING, "Authenticating…") }
        nonce = null
        listener.onReadyChanged(false)
        diagnostic("Sending command=$cmd")
        write(c, CarKeyProtocol.command(profile, cmd, current, psk)) {
            commandWritePending = false
            val response = pendingStatus
            pendingStatus = null
            if (response != null) handleStatus(response)
            if (profile.responseMode == BleResponseMode.READ_AFTER_WRITE && pendingCommand != null) {
                later(100) { if (generation == commandGeneration) status?.let { read(it) { v -> handleStatus(v.toString(Charsets.UTF_8)) } } }
            }
            later(3_000) { if (generation == commandGeneration && pendingCommand != null) fail("Command response timed out; execution unknown") }
        }
    }
    private fun handleStatus(value: String) {
        diagnostic("Device status: ${if (value.startsWith("PSK2:")) value.substringBeforeLast(':') else value}")
        val request = pskRequest
        if (request != null) {
            val persisted = PskUpdateProtocol.verifyReceipt(request, value)
            if (persisted != null) {
                if (persisted) psk = pendingNewPsk!!
                finishPskUpdate(persisted, if (persisted) "PSK updated on phone and car" else "Car could not save the PSK; previous key remains active")
                readChallenge()
            } else if (value.startsWith("ERR:PSK_")) fail("Secure PSK update rejected; confirm the car key before retrying")
            return
        }
        val cmd = pendingCommand ?: return
        if (commandWritePending) { pendingStatus = value; return }
        if (!(value.startsWith("ERR:") || value == "OK:AUTH" || value == "OK:PRESSED")) return
        if (cmd == CarKeyProtocol.AUTH_COMMAND && value != "OK:AUTH") return fail("BLE authentication failed; check the PSK")
        if (cmd == CarKeyProtocol.PRESS_COMMAND && value == "OK:AUTH") return
        pendingCommand = null
        commandGeneration++
        if (cmd == CarKeyProtocol.AUTH_COMMAND) {
            ready = true
            directFailures = 0
            stage = "ready"
            listener.onState(State.CONNECTED, "Authenticated")
            scheduleStatePoll()
        } else listener.onCommandResult(value == "OK:PRESSED", if (value == "OK:PRESSED") "Pressed" else "Command failed ($value)")
        // Recovery reads a nonce; it never repeats an uncertain remote toggle.
        readChallenge()
    }
    private fun scheduleStatePoll() {
        if (deviceState == null) return
        later(1_500) {
            val c = deviceState
            if (c != null && ready && !queue.busy && pendingCommand == null && pskRequest == null && !otaInFlight) {
                read(c) { val state = it.toString(Charsets.UTF_8); if (state.startsWith("ERR:")) fail("Device session requires authentication") else listener.onDeviceState(state) }
            }
            scheduleStatePoll()
        }
    }
    private fun write(c: BluetoothGattCharacteristic, value: ByteArray, done: () -> Unit = {}) {
        val g = gatt ?: return fail("Bluetooth connection disappeared")
        queue.enqueue("write:${c.uuid}", {
            if (Build.VERSION.SDK_INT >= 33) {
                val result = g.writeCharacteristic(c, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
                if (result != BluetoothStatusCodes.SUCCESS) diagnostic("Write enqueue ${c.uuid} returned $result")
                result == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION")
                run { c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT; c.value = value; g.writeCharacteristic(c) }
            }
        }, done)
    }
    fun updatePsk(newPsk: String): Boolean {
        if (!securePskSupported) { listener.onPskUpdateResult(false, "Update the car firmware to v2.6.0 or later before changing its PSK"); return true }
        val current = nonce ?: return false
        val c = pskUpdate ?: return false
        if (!PskUpdateProtocol.validKey(newPsk)) { listener.onPskUpdateResult(false, "PSK must be 1–128 UTF-8 bytes without NUL characters"); return true }
        if (!ready || pendingCommand != null || pskRequest != null || otaInFlight || radioCallback != null) return false
        val request = PskUpdateProtocol.create(profile.securityBinding, current, psk, newPsk)
        pskRequest = request
        pendingNewPsk = newPsk
        nonce = null
        listener.onReadyChanged(false)
        write(c, request.payload) {
            if (pskRequest === request) status?.let { read(it) { v -> handleStatus(v.toString(Charsets.UTF_8)) } }
        }
        later(8_000) { if (pskRequest === request) fail("PSK receipt timed out; confirm the car key before app-only recovery") }
        return true
    }
    private fun finishPskUpdate(success: Boolean, message: String) {
        pskRequest?.receiptKey?.fill(0)
        pskRequest = null
        pendingNewPsk = null
        listener.onPskUpdateResult(success, message)
    }
    fun startOta(image: ByteArray) {
        val current = nonce ?: return listener.onOtaResult(false, "No fresh challenge for firmware update")
        val control = otaControl
        if (control == null || otaData == null || otaStatus == null) return listener.onOtaResult(false, "Car needs the one-time USB OTA bootstrap firmware first")
        if (image.isEmpty() || image.size > 0x1e0000) return listener.onOtaResult(false, "Firmware image size is invalid")
        if (pendingCommand != null || pskRequest != null || otaInFlight || radioCallback != null) return listener.onOtaResult(false, "Another BLE operation is running")
        otaImage = image; otaOffset = 0; otaInFlight = true; otaWaitingForReady = true
        otaStartWriteComplete = false; otaFinishing = false; otaChunkPending = false; otaResponse = null
        stage = "ota"
        nonce = null
        listener.onReadyChanged(false)
        val generation = ++otaGeneration
        val payload = CarKeyProtocol.otaStart(image.size, MessageDigest.getInstance("SHA-256").digest(image), current, psk)
        val highPriority = gatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH) == true
        diagnostic("OTA start bytes=${image.size} highPriority=$highPriority")
        later(if (highPriority) 750 else 0) {
            write(control, payload) { otaStartWriteComplete = true; maybeStartOtaData() }
            later(8_000) { if (otaInFlight && generation == otaGeneration && otaWaitingForReady) fail("ESP did not confirm firmware start") }
        }
    }
    private fun handleOtaStatus(value: String) {
        diagnostic("OTA status: $value")
        handleRadioStatus(value)
        if (!otaInFlight) return
        when {
            value == "OTA:READY" -> { otaWaitingForReady = false; maybeStartOtaData() }
            value == "OTA:OK" -> {
                otaResponse = value
                if (!queue.busy && otaFinishing) finishOta(true, "Firmware updated; car ESP is restarting")
            }
            value == "ERR:OTA_PROBATION" -> fail("Car is still checking its new firmware. Wait one minute and check Device health before updating again.")
            value.startsWith("ERR:OTA_") -> fail("Car rejected firmware update ($value)")
        }
    }
    private fun maybeStartOtaData() {
        if (!otaInFlight || otaWaitingForReady || !otaStartWriteComplete || otaChunkPending || otaFinishing) return
        val image = otaImage ?: return fail("Firmware image disappeared")
        if (otaOffset >= image.size) {
            otaFinishing = true
            write(otaControl ?: return fail("OTA control missing"), byteArrayOf(0x02)) {
                if (otaResponse == "OTA:OK") finishOta(true, "Firmware updated; car ESP is restarting")
                else later(10_000) { if (otaInFlight) fail("Firmware validation response timed out") }
            }
            return
        }
        val count = minOf(508, (negotiatedMtu - 9).coerceAtLeast(14), image.size - otaOffset)
        val payload = ByteBuffer.allocate(4 + count).order(ByteOrder.LITTLE_ENDIAN).putInt(otaOffset).put(image, otaOffset, count).array()
        otaChunkPending = true
        write(otaData ?: return fail("OTA data missing"), payload) {
            otaChunkPending = false; otaOffset += count
            listener.onOtaProgress(otaOffset, image.size)
            maybeStartOtaData()
        }
    }
    private fun finishOta(success: Boolean, message: String) {
        if (!otaInFlight) return
        otaInFlight = false; otaGeneration++; otaImage = null
        gatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_BALANCED)
        listener.onOtaResult(success, message)
    }
    private fun fail(message: String) {
        if (stopped) return
        diagnostic("BLE failure: $message")
        val wasPress = pendingCommand == CarKeyProtocol.PRESS_COMMAND
        val wasPsk = pskRequest != null
        val wasOta = otaInFlight
        if (!ready && attemptingDirect) directFailures++
        if (wasPsk || wasOta) stopped = true
        teardown()
        listener.onReadyChanged(false)
        listener.onState(State.DISCONNECTED, message)
        if (wasPress) listener.onCommandResult(false, "No confirmation; connection reset")
        if (wasPsk) listener.onPskUpdateResult(false, "PSK update interrupted; confirm the car key before app-only recovery")
        if (wasOta) listener.onOtaResult(false, message)
        if (!stopped) {
            if (AppPolicies.shouldOfferScanFallback(directFailures, preferDirect)) {
                preferDirect = false; reconnectAddress = profile.defaultAddress
                diagnostic("Cached attempts exhausted; switching to scan")
            }
            listener.onState(State.DISCONNECTED, "Reconnecting…")
            later(1_500) { start(psk, reconnectAddress, preferDirect) }
        }
    }
    private fun teardown() {
        val cancelledHealth = healthCallback
        healthCallback = null
        val cancelledRadio = radioCallback
        radioCallback = null; radioResponse = null; radioWritePending = false; radioGeneration++
        epoch++
        handler.removeCallbacksAndMessages(null)
        queue.clear()
        stopScan()
        val old = gatt
        gatt = null // Invalidate ownership before disconnect can deliver callbacks.
        runCatching { old?.disconnect() }; runCatching { old?.close() }
        challenge = null; command = null; status = null; pskUpdate = null
        otaControl = null; otaData = null; otaStatus = null; deviceState = null
        nonce = null; ready = false; securePskSupported = false; healthSupported = false; radioSupported = false
        pendingCommand = null; commandWritePending = false; pendingStatus = null; commandGeneration++
        pskRequest?.receiptKey?.fill(0); pskRequest = null; pendingNewPsk = null
        otaImage = null; otaInFlight = false; otaChunkPending = false; otaResponse = null; otaGeneration++
        negotiatedMtu = 23; stage = "idle"
        cancelledHealth?.invoke(null, "Connection closed before health data arrived. Tap Refresh to retry.")
        cancelledRadio?.invoke(false, "No confirmation: settings may have changed. Reopen Device health to read the ESP's current values before retrying.")
    }
}
