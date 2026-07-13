using Toybox.BluetoothLowEnergy as Ble;
using Toybox.Cryptography;
using Toybox.System;
using Toybox.Application;
using Toybox.WatchUi;
using Toybox.Lang;
using Toybox.Timer;

// UUIDs matching the ESP32 firmware
class CarKeyProfile {
    static const SERVICE_UUID         = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567890l);
    static const CHALLENGE_CHAR_UUID  = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567891l);
    static const COMMAND_CHAR_UUID    = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567892l);
    static const STATUS_CHAR_UUID     = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567893l);
    static const COMMAND_PT1_CHAR_UUID = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567895l);
    static const COMMAND_PT2_CHAR_UUID = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567896l);

    static const CCCD_UUID = Ble.cccdUuid();

    // Command types (must match ESP32 firmware)
    static const CMD_AUTH_ONLY = 0x01;
    static const CMD_PRESS     = 0x02;

    static function getProfileDef() {
        return {
            :uuid => SERVICE_UUID,
            :characteristics => [
                {
                    :uuid => CHALLENGE_CHAR_UUID,
                    :descriptors => [CCCD_UUID]
                },
                {
                    :uuid => COMMAND_CHAR_UUID
                },
                {
                    :uuid => COMMAND_PT1_CHAR_UUID
                },
                {
                    :uuid => COMMAND_PT2_CHAR_UUID
                },
                {
                    :uuid => STATUS_CHAR_UUID,
                    :descriptors => [CCCD_UUID]
                }
            ]
        };
    }
}

// State machine for the BLE connection flow
enum {
    STATE_IDLE,
    STATE_SCANNING,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_READING_CHALLENGE,
    STATE_SENDING_COMMAND,
    STATE_WAITING_STATUS,
    STATE_ERROR
}

class BleHandler extends Ble.BleDelegate {

    var _device = null;
    var _state = STATE_IDLE;
    var _statusText = "Ready";
    var _pendingCommand = CarKeyProfile.CMD_PRESS;
    var _profileRegistered = false;
    var _pendingPart2 = null;
    var _hasPendingPress = false;
    var _scanRequested = false;
    var _notificationsReady = false;
    var _notificationSetupStarted = false;
    var _timer = null;
    var _operationTimer = null;
    var _connectionTimer = null;
    var _shouldAutoReconnect = true;
    var _connectionTimeoutStage = 0;
    var _rapidRetryCount = 0;
    var _connectionFeedbackState = false;

    function initialize() {
        BleDelegate.initialize();
        Ble.setDelegate(self);
        _timer = new Timer.Timer();
        _operationTimer = new Timer.Timer();
        _connectionTimer = new Timer.Timer();

        // Register the BLE profile
        try {
            Ble.registerProfile(CarKeyProfile.getProfileDef());
        } catch (e) {
            System.println("Profile registration error: " + e.getErrorMessage());
        }
    }

    // ============================================================
    // Public API
    // ============================================================

    function startScan() {
        _scanRequested = true;
        if (!_profileRegistered) {
            _statusText = "Preparing Bluetooth...";
            WatchUi.requestUpdate();
            return;
        }
        if (_state == STATE_SCANNING || _state == STATE_CONNECTING) {
            return;
        }

        _state = STATE_SCANNING;
        _statusText = "Scanning...";
        WatchUi.requestUpdate();

        try {
            Ble.setScanState(Ble.SCAN_STATE_SCANNING);
        } catch (e) {
            _state = STATE_ERROR;
            _statusText = "Scan failed";
            System.println("Scan error: " + e.getErrorMessage());
            WatchUi.requestUpdate();
        }
    }

    function stopScan() {
        _scanRequested = false;
        try {
            Ble.setScanState(Ble.SCAN_STATE_OFF);
        } catch (e) {
            // Ignore
        }
    }

    function sendPress() {
        // Debounce: ignore if a BLE operation is already in flight
        if (_state == STATE_READING_CHALLENGE ||
            _state == STATE_SENDING_COMMAND ||
            _state == STATE_WAITING_STATUS) {
            return;
        }

        _pendingCommand = CarKeyProfile.CMD_PRESS;

        if (_device == null || !_device.isConnected()) {
            // Not connected — scan and execute after connect
            _hasPendingPress = true;
            _statusText = "Press queued";
            WatchUi.requestUpdate();
            startScan();
            return;
        }

        if (!_notificationsReady) {
            _hasPendingPress = true;
            _statusText = "Press queued";
            WatchUi.requestUpdate();
            if (!_notificationSetupStarted) {
                enableStatusNotifications();
            }
            return;
        }

        readChallenge();
    }

    function disconnect() {
        _shouldAutoReconnect = false;
        _hasPendingPress = false;
        _notificationsReady = false;
        _notificationSetupStarted = false;
        _timer.stop();
        _connectionTimer.stop();
        if (_connectionFeedbackState) {
            _connectionFeedbackState = false;
            vibrateDisconnected();
        }
        if (_device != null) {
            Ble.unpairDevice(_device);
            _device = null;
        }
        _state = STATE_IDLE;
        _statusText = "Disconnected";
        WatchUi.requestUpdate();
    }

    // Force unpair: clears the GATT cache and reconnects from scratch.
    // Use after firmware updates that change the GATT service table.
    // Triggered by MENU button (long-press UP on FR165).
    function forceUnpair() {
        _timer.stop();
        _connectionTimer.stop();
        _hasPendingPress = false;
        if (_connectionFeedbackState) {
            _connectionFeedbackState = false;
            vibrateDisconnected();
        }
        stopScan();
        if (_device != null) {
            Ble.unpairDevice(_device);
            _device = null;
        }
        _state = STATE_IDLE;
        _statusText = "Unpaired, scanning...";
        WatchUi.requestUpdate();

        // Immediately reconnect with fresh pairing
        _shouldAutoReconnect = true;
        startScan();
    }

    // Clean shutdown: stop scanning and timers but keep the device
    // paired so the OS caches the GATT service table. Next app
    // launch reconnects in ~1-2s instead of ~15s full discovery.
    function cleanup() {
        _shouldAutoReconnect = false;
        _connectionFeedbackState = false;
        _hasPendingPress = false;
        _notificationsReady = false;
        _notificationSetupStarted = false;
        _timer.stop();
        _connectionTimer.stop();
        stopScan();
    }

    function getStatusText() {
        return _statusText;
    }

    function getState() {
        return _state;
    }

    function isConnected() {
        return _device != null && _device.isConnected();
    }

    function hasPendingPress() {
        return _hasPendingPress;
    }

    // ============================================================
    // BLE flow
    // ============================================================

    private function readChallenge() {
        var service = _device.getService(CarKeyProfile.SERVICE_UUID);
        if (service == null) {
            _statusText = "Command failed";
            System.println("Remote button press failed: service not found");
            _state = STATE_ERROR;
            vibrateFailure();
            WatchUi.requestUpdate();
            return;
        }

        var challengeChar = service.getCharacteristic(CarKeyProfile.CHALLENGE_CHAR_UUID);
        if (challengeChar == null) {
            _statusText = "Command failed";
            System.println("Remote button press failed: challenge characteristic not found");
            _state = STATE_ERROR;
            vibrateFailure();
            WatchUi.requestUpdate();
            return;
        }

        _state = STATE_READING_CHALLENGE;
        _statusText = "Reading nonce...";
        WatchUi.requestUpdate();
        startOperationTimeout();

        try {
            challengeChar.requestRead();
        } catch (e) {
            _statusText = "Command failed";
            _state = STATE_CONNECTED;
            cancelOperationTimeout();
            System.println("Remote button press failed: " + e.getErrorMessage());
            vibrateFailure();
            WatchUi.requestUpdate();
        }
    }

    private function sendCommand(nonce) {
        var psk = Application.Properties.getValue("psk");

        // Convert PSK string to ByteArray if needed
        var keyBytes;
        if (psk instanceof Lang.String) {
            var chars = (psk as Lang.String).toCharArray();
            keyBytes = new [chars.size()]b;
            for (var i = 0; i < chars.size(); i++) {
                keyBytes[i] = (chars[i] as Lang.Char).toNumber();
            }
        } else {
            keyBytes = psk as Lang.ByteArray;
        }

        // Use native Garmin HMAC-SHA256
        var hmacEngine = new Cryptography.HashBasedMessageAuthenticationCode({
            :algorithm => Cryptography.HASH_SHA256,
            :key => keyBytes
        });
        hmacEngine.update(nonce as Lang.ByteArray);
        var hmac = hmacEngine.digest() as Lang.ByteArray;

        var service = _device.getService(CarKeyProfile.SERVICE_UUID);
        if (service == null) {
            _statusText = "Command failed";
            System.println("Remote button press failed: service lost");
            _state = STATE_ERROR;
            vibrateFailure();
            WatchUi.requestUpdate();
            return;
        }

        var pt1Char = service.getCharacteristic(CarKeyProfile.COMMAND_PT1_CHAR_UUID);
        if (pt1Char == null) {
            _statusText = "Command failed";
            System.println("Remote button press failed: split command characteristic not found");
            _state = STATE_ERROR;
            vibrateFailure();
            WatchUi.requestUpdate();
            return;
        }

        // Store part 2 for sending after pt1 callback
        var part2 = new [16]b;
        for (var i = 0; i < 16; i++) {
            part2[i] = hmac[i + 16];
        }
        _pendingPart2 = part2;

        // Part 1: command byte + first 16 bytes of HMAC = 17 bytes
        var part1 = new [17]b;
        part1[0] = _pendingCommand;
        for (var i = 0; i < 16; i++) {
            part1[i + 1] = hmac[i];
        }

        _state = STATE_SENDING_COMMAND;
        _statusText = "Sending...";
        WatchUi.requestUpdate();

        try {
            pt1Char.requestWrite(part1, {:writeType => Ble.WRITE_TYPE_WITH_RESPONSE});
            startOperationTimeout();
        } catch (e) {
            _statusText = "Command failed";
            _state = STATE_CONNECTED;
            _pendingPart2 = null;
            System.println("Remote button press failed: " + e.getErrorMessage());
            vibrateFailure();
            WatchUi.requestUpdate();
        }
    }
    
    private function enableStatusNotifications() {
        _notificationSetupStarted = true;
        var service = _device.getService(CarKeyProfile.SERVICE_UUID);
        if (service == null) {
            finishNotificationSetup(false);
            return;
        }

        var statusChar = service.getCharacteristic(CarKeyProfile.STATUS_CHAR_UUID);
        if (statusChar == null) {
            finishNotificationSetup(false);
            return;
        }

        var cccd = statusChar.getDescriptor(CarKeyProfile.CCCD_UUID);
        if (cccd != null) {
            try {
                cccd.requestWrite([0x01, 0x00]b);
            } catch (e) {
                System.println("CCCD write error: " + e.getErrorMessage());
                finishNotificationSetup(false);
            }
        } else {
            finishNotificationSetup(false);
        }
    }

    private function finishNotificationSetup(success) {
        _notificationsReady = success;
        _notificationSetupStarted = false;
        if (_hasPendingPress && _device != null && _device.isConnected()) {
            _hasPendingPress = false;
            if (!success) {
                _statusText = "Sending without feedback";
            }
            readChallenge();
        } else if (!success) {
            _statusText = "Connected (no feedback)";
            WatchUi.requestUpdate();
        }
    }

    // Auto-reconnect after unexpected disconnect or scan timeout
    function onReconnectTimer() as Void {
        if (_shouldAutoReconnect && _state == STATE_IDLE) {
            startScan();
        }
    }

    // Status response timeout — release debounce so user can retry
    function onStatusTimeout() as Void {
        if (_state == STATE_WAITING_STATUS) {
            _state = STATE_CONNECTED;
            _statusText = "No confirmation";
            System.println("Remote button press received no confirmation");
            vibrateFailure();
            WatchUi.requestUpdate();
        }
    }

    function startOperationTimeout() as Void {
        _operationTimer.stop();
        _operationTimer.start(method(:onOperationTimeout), 5000, false);
    }

    function cancelOperationTimeout() as Void {
        _operationTimer.stop();
    }

    private function startConnectionTimeout() as Void {
        _connectionTimeoutStage = 0;
        _connectionTimer.stop();
        _connectionTimer.start(method(:onConnectionTimeout), 8000, false);
    }

    function onConnectionTimeout() as Void {
        if (_state != STATE_CONNECTING) {
            return;
        }

        if (_connectionTimeoutStage == 0) {
            // Give Garmin's BLE subsystem one extra window before discarding
            // the useful paired/GATT cache.
            _connectionTimeoutStage = 1;
            _statusText = "Connection slow...";
            WatchUi.requestUpdate();
            _connectionTimer.start(method(:onConnectionTimeout), 8000, false);
            return;
        }

        System.println("Connection timed out; clearing stale pairing");
        if (_device != null) {
            try {
                Ble.unpairDevice(_device);
            } catch (e) {
                System.println("Timeout unpair error: " + e.getErrorMessage());
            }
        }
        _device = null;
        _state = STATE_IDLE;
        _statusText = "Retrying connection...";
        WatchUi.requestUpdate();
        scheduleReconnect(250);
    }

    private function scheduleReconnect(baseDelay) as Void {
        var delay = baseDelay;
        if (_rapidRetryCount == 1 && delay < 1000) {
            delay = 1000;
        } else if (_rapidRetryCount >= 2 && delay < 3000) {
            delay = 3000;
        }
        _rapidRetryCount++;
        _timer.stop();
        _timer.start(method(:onReconnectTimer), delay, false);
    }

    private function useConnectedPairedDevice() {
        try {
            var devices = Ble.getPairedDevices();
            var device = devices.next();
            while (device != null) {
                if (device instanceof Ble.Device) {
                    var pairedDevice = device as Ble.Device;
                    if (pairedDevice.isConnected() &&
                        pairedDevice.getService(CarKeyProfile.SERVICE_UUID) != null) {
                        System.println("Reusing connected paired device");
                        onConnectedStateChanged(pairedDevice, Ble.CONNECTION_STATE_CONNECTED);
                        return true;
                    }
                }
                device = devices.next();
            }
        } catch (e) {
            System.println("Paired device lookup error: " + e.getErrorMessage());
        }
        return false;
    }

    function onOperationTimeout() as Void {
        if (_state == STATE_READING_CHALLENGE || _state == STATE_SENDING_COMMAND) {
            _pendingPart2 = null;
            if (_device != null && _device.isConnected()) {
                _state = STATE_CONNECTED;
            } else {
                _state = STATE_IDLE;
            }
            _statusText = "No confirmation";
            System.println("Remote button press timed out");
            vibrateFailure();
            WatchUi.requestUpdate();
        }
    }

    // ============================================================
    // BleDelegate callbacks
    // ============================================================

    function onProfileRegister(uuid, status) {
        if (status == Ble.STATUS_SUCCESS) {
            _profileRegistered = true;
            System.println("Profile registered");
            if (_scanRequested && !useConnectedPairedDevice()) {
                startScan();
            }
        } else {
            _state = STATE_ERROR;
            _statusText = "BLE profile failed";
            System.println("Profile registration failed: " + status);
            WatchUi.requestUpdate();
        }
    }

    function onScanStateChanged(scanState, status) {
        if (scanState == Ble.SCAN_STATE_OFF && _state == STATE_SCANNING) {
            // Scan was stopped externally or timed out
            if (_device == null) {
                _state = STATE_IDLE;
                _statusText = "Scanning...";
                WatchUi.requestUpdate();
                // Retry scan immediately
                if (_shouldAutoReconnect) {
                    scheduleReconnect(100);
                }
            }
        }
    }

    function onScanResults(scanResults as Ble.Iterator) as Void {
        var scanResult = scanResults.next();
        while (scanResult != null) {
            if (scanResult instanceof Ble.ScanResult) {
                var sr = scanResult as Ble.ScanResult;
                var uuidsIterator = sr.getServiceUuids(); // This is an Iterator, not an Array
                
                if (uuidsIterator != null) {
                    // Fix: Iterate using .next() instead of .size() and []
                    for (var currentUuid = uuidsIterator.next(); currentUuid != null; currentUuid = uuidsIterator.next()) {
                        if (currentUuid.equals(CarKeyProfile.SERVICE_UUID)) {
                            // Found our device
                            stopScan();
                            _state = STATE_CONNECTING;
                            _statusText = "Connecting...";
                            WatchUi.requestUpdate();

                            try {
                                _device = Ble.pairDevice(sr);
                                if (_device == null) {
                                    _state = STATE_IDLE;
                                    _statusText = "Pairing did not start";
                                    WatchUi.requestUpdate();
                                    scheduleReconnect(250);
                                    return;
                                }
                                startConnectionTimeout();
                            } catch (e) {
                                _statusText = "Pair failed";
                                _state = STATE_IDLE;
                                System.println("Pair error: " + e.getErrorMessage());
                                WatchUi.requestUpdate();
                                scheduleReconnect(1000);
                            }
                            return;
                        }
                    }
                }
            }
            scanResult = scanResults.next();
        }
    }

    function onConnectedStateChanged(device, state) {
        if (state == Ble.CONNECTION_STATE_CONNECTED) {
            _timer.stop();
            _connectionTimer.stop();
            _rapidRetryCount = 0;
            _device = device;
            _notificationsReady = false;
            _notificationSetupStarted = false;
            _state = STATE_CONNECTED;
            _statusText = _hasPendingPress ? "Press queued" : "Connected";
            if (!_connectionFeedbackState) {
                _connectionFeedbackState = true;
                vibrateConnected();
            }
            WatchUi.requestUpdate();

            // Enable notifications on status characteristic.
            // If there's a pending unlock, it will execute from
            // onDescriptorWrite once the CCCD write completes.
            enableStatusNotifications();

        } else {
            var wasConnected = _connectionFeedbackState;
            _connectionFeedbackState = false;
            _device = null;
            _pendingPart2 = null;
            _connectionTimer.stop();
            _notificationsReady = false;
            _notificationSetupStarted = false;
            cancelOperationTimeout();
            _state = STATE_IDLE;
            _statusText = "Disconnected";
            if (wasConnected) {
                vibrateDisconnected();
            }
            WatchUi.requestUpdate();

            // Auto-reconnect after 2 seconds
            if (_shouldAutoReconnect) {
                scheduleReconnect(2000);
            }
        }
    }

    function onCharacteristicRead(char, status, value) {
        if (status != Ble.STATUS_SUCCESS) {
            cancelOperationTimeout();
            _statusText = "Command failed";
            System.println("Remote button press failed: challenge read status " + status);
            _state = STATE_CONNECTED;
            vibrateFailure();
            WatchUi.requestUpdate();
            return;
        }

        if (char.getUuid().equals(CarKeyProfile.CHALLENGE_CHAR_UUID)) {
            // Got the nonce, now compute HMAC and send command
            cancelOperationTimeout();
            sendCommand(value);
        }
    }

    function onCharacteristicWrite(char, status) {
        var uuid = char.getUuid();

        if (uuid.equals(CarKeyProfile.COMMAND_PT1_CHAR_UUID)) {
            if (status == Ble.STATUS_SUCCESS && _pendingPart2 != null) {
                // Part 1 succeeded, now send part 2
                var service = _device.getService(CarKeyProfile.SERVICE_UUID);
                if (service != null) {
                    var pt2Char = service.getCharacteristic(CarKeyProfile.COMMAND_PT2_CHAR_UUID);
                    if (pt2Char != null) {
                        try {
                            pt2Char.requestWrite(_pendingPart2, {:writeType => Ble.WRITE_TYPE_WITH_RESPONSE});
                            return;
                        } catch (e) {
                            _statusText = "Command failed";
                            System.println("Remote button press failed: " + e.getErrorMessage());
                            _state = STATE_CONNECTED;
                            vibrateFailure();
                        }
                    }
                }
                _pendingPart2 = null;
                cancelOperationTimeout();
                WatchUi.requestUpdate();
            } else if (status != Ble.STATUS_SUCCESS) {
                _statusText = "Command failed";
                System.println("Remote button press failed: part 1 write status " + status);
                _state = STATE_CONNECTED;
                _pendingPart2 = null;
                cancelOperationTimeout();
                vibrateFailure();
                WatchUi.requestUpdate();
            }
        } else if (uuid.equals(CarKeyProfile.COMMAND_PT2_CHAR_UUID)) {
            _pendingPart2 = null;
            cancelOperationTimeout();
            if (status == Ble.STATUS_SUCCESS) {
                _state = STATE_WAITING_STATUS;
                _statusText = "Sent, waiting...";
                _timer.stop();
                _timer.start(method(:onStatusTimeout), 2000, false);
            } else {
                _statusText = "Command failed";
                System.println("Remote button press failed: part 2 write status " + status);
                _state = STATE_CONNECTED;
                vibrateFailure();
            }
            WatchUi.requestUpdate();
        } else if (uuid.equals(CarKeyProfile.COMMAND_CHAR_UUID)) {
            cancelOperationTimeout();
            if (status == Ble.STATUS_SUCCESS) {
                _state = STATE_WAITING_STATUS;
                _statusText = "Sent, waiting...";
                _timer.stop();
                _timer.start(method(:onStatusTimeout), 2000, false);
            } else {
                _statusText = "Command failed";
                System.println("Remote button press failed: command write status " + status);
                _state = STATE_CONNECTED;
                vibrateFailure();
            }
            WatchUi.requestUpdate();
        }
    }

    function onCharacteristicChanged(char, value) {
        if (char.getUuid().equals(CarKeyProfile.STATUS_CHAR_UUID)) {
            _timer.stop(); // cancel status timeout
            // Parse status from ESP32
            var statusStr = byteArrayToString(value as Lang.ByteArray);
            if (statusStr.find("OK:PRESSED") != null) {
                _statusText = "Pressed";
                _state = STATE_CONNECTED;
                System.println("Remote button pressed");
                vibrateSuccess();
            } else if (statusStr.find("OK:AUTH") != null) {
                _statusText = "Authenticated";
                _state = STATE_CONNECTED;
            } else if (statusStr.find("ERR:BUSY") != null) {
                _statusText = "Command failed";
                System.println("Remote button press failed: busy");
                vibrateFailure();
                _state = STATE_CONNECTED; // recoverable, not an error state
            } else if (statusStr.find("ERR:AUTH") != null) {
                _statusText = "Command failed";
                System.println("Remote button press failed: authentication");
                vibrateFailure();
                _state = STATE_CONNECTED; // recoverable — user can retry
            } else if (statusStr.find("ERR") != null) {
                _statusText = "Command failed";
                System.println("Remote button press failed: " + statusStr);
                _state = STATE_ERROR;
                vibrateFailure();
            } else if (statusStr.find("WARN") != null) {
                _statusText = statusStr;
                _state = STATE_CONNECTED;
            } else {
                _statusText = statusStr;
            }
            WatchUi.requestUpdate();
        }
    }

    function onDescriptorWrite(desc, status) {
        // CCCD write complete — notifications are now active
        if (status == Ble.STATUS_SUCCESS) {
            System.println("Notifications enabled");
            finishNotificationSetup(true);
        } else {
            System.println("Notifications failed: " + status);
            finishNotificationSetup(false);
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    private function vibrateConnected() {
        vibrate([new Toybox.Attention.VibeProfile(100, 80)]);
    }

    private function vibrateDisconnected() {
        vibrate([
            new Toybox.Attention.VibeProfile(100, 80),
            new Toybox.Attention.VibeProfile(0, 60),
            new Toybox.Attention.VibeProfile(100, 80)
        ]);
    }

    private function vibrateSuccess() {
        vibrate([new Toybox.Attention.VibeProfile(100, 200)]);
    }

    private function vibrateFailure() {
        vibrate([
            new Toybox.Attention.VibeProfile(100, 220),
            new Toybox.Attention.VibeProfile(0, 140),
            new Toybox.Attention.VibeProfile(100, 220)
        ]);
    }

    private function vibrate(pattern) {
        if (Toybox.Attention has :vibrate) {
            Toybox.Attention.vibrate(pattern);
        }
    }

    // Fix: Explicitly type 'bytes' so the compiler knows it can be indexed
    private function byteArrayToString(bytes as Lang.ByteArray) {
        var chars = new [bytes.size()];
        for (var i = 0; i < bytes.size(); i++) {
            chars[i] = (bytes[i] & 0xFF).toChar();
        }
        return StringUtil.charArrayToString(chars);
    }
}
