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
    var _hasPendingUnlock = false;
    var _timer = null;
    var _shouldAutoReconnect = true;

    function initialize() {
        BleDelegate.initialize();
        Ble.setDelegate(self);
        _timer = new Timer.Timer();

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
        if (_state == STATE_SCANNING) {
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
        try {
            Ble.setScanState(Ble.SCAN_STATE_OFF);
        } catch (e) {
            // Ignore
        }
    }

    function sendUnlock() {
        // Debounce: ignore if a BLE operation is already in flight
        if (_state == STATE_READING_CHALLENGE ||
            _state == STATE_SENDING_COMMAND ||
            _state == STATE_WAITING_STATUS) {
            return;
        }

        _pendingCommand = CarKeyProfile.CMD_PRESS;

        if (_device == null || !_device.isConnected()) {
            // Not connected — scan and execute after connect
            _hasPendingUnlock = true;
            startScan();
            return;
        }

        readChallenge();
    }

    function disconnect() {
        _shouldAutoReconnect = false;
        _hasPendingUnlock = false;
        _timer.stop();
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
        _hasPendingUnlock = false;
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
        _hasPendingUnlock = false;
        _timer.stop();
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

    // ============================================================
    // BLE flow
    // ============================================================

    private function readChallenge() {
        var service = _device.getService(CarKeyProfile.SERVICE_UUID);
        if (service == null) {
            _statusText = "Service not found";
            _state = STATE_ERROR;
            WatchUi.requestUpdate();
            return;
        }

        var challengeChar = service.getCharacteristic(CarKeyProfile.CHALLENGE_CHAR_UUID);
        if (challengeChar == null) {
            _statusText = "Challenge char not found";
            _state = STATE_ERROR;
            WatchUi.requestUpdate();
            return;
        }

        _state = STATE_READING_CHALLENGE;
        _statusText = "Reading nonce...";
        WatchUi.requestUpdate();

        try {
            challengeChar.requestRead();
        } catch (e) {
            _statusText = "Read failed";
            _state = STATE_ERROR;
            System.println("Read error: " + e.getErrorMessage());
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
            _statusText = "Service lost";
            _state = STATE_ERROR;
            WatchUi.requestUpdate();
            return;
        }

        var pt1Char = service.getCharacteristic(CarKeyProfile.COMMAND_PT1_CHAR_UUID);
        if (pt1Char == null) {
            _statusText = "Split char not found";
            _state = STATE_ERROR;
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
        } catch (e) {
            _statusText = "Write pt1: " + e.getErrorMessage();
            _state = STATE_ERROR;
            _pendingPart2 = null;
            WatchUi.requestUpdate();
        }
    }
    
    private function enableStatusNotifications() {
        var service = _device.getService(CarKeyProfile.SERVICE_UUID);
        if (service == null) { return; }

        var statusChar = service.getCharacteristic(CarKeyProfile.STATUS_CHAR_UUID);
        if (statusChar == null) { return; }

        var cccd = statusChar.getDescriptor(CarKeyProfile.CCCD_UUID);
        if (cccd != null) {
            try {
                cccd.requestWrite([0x01, 0x00]b);
            } catch (e) {
                System.println("CCCD write error: " + e.getErrorMessage());
            }
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
            _statusText = "No response";
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
        } else {
            System.println("Profile registration failed: " + status);
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
                    _timer.start(method(:onReconnectTimer), 100, false);
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
                            } catch (e) {
                                _statusText = "Pair failed";
                                _state = STATE_ERROR;
                                System.println("Pair error: " + e.getErrorMessage());
                                WatchUi.requestUpdate();
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
            _device = device;
            _state = STATE_CONNECTED;
            _statusText = "Connected";
            WatchUi.requestUpdate();

            // Enable notifications on status characteristic.
            // If there's a pending unlock, it will execute from
            // onDescriptorWrite once the CCCD write completes.
            enableStatusNotifications();

        } else {
            _device = null;
            _pendingPart2 = null;
            _state = STATE_IDLE;
            _statusText = "Disconnected";
            WatchUi.requestUpdate();

            // Auto-reconnect after 2 seconds
            if (_shouldAutoReconnect) {
                _timer.start(method(:onReconnectTimer), 2000, false);
            }
        }
    }

    function onCharacteristicRead(char, status, value) {
        if (status != Ble.STATUS_SUCCESS) {
            _statusText = "Read error";
            _state = STATE_ERROR;
            WatchUi.requestUpdate();
            return;
        }

        if (char.getUuid().equals(CarKeyProfile.CHALLENGE_CHAR_UUID)) {
            // Got the nonce, now compute HMAC and send command
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
                            _pendingPart2 = null;
                            return;
                        } catch (e) {
                            _statusText = "Write pt2: " + e.getErrorMessage();
                            _state = STATE_ERROR;
                        }
                    }
                }
                _pendingPart2 = null;
                WatchUi.requestUpdate();
            } else if (status != Ble.STATUS_SUCCESS) {
                _statusText = "Write pt1 err: " + status;
                _state = STATE_ERROR;
                _pendingPart2 = null;
                WatchUi.requestUpdate();
            }
        } else if (uuid.equals(CarKeyProfile.COMMAND_PT2_CHAR_UUID)) {
            if (status == Ble.STATUS_SUCCESS) {
                _state = STATE_WAITING_STATUS;
                _statusText = "Sent, waiting...";
                _timer.start(method(:onStatusTimeout), 2000, false);
            } else {
                _statusText = "Write pt2 err: " + status;
                _state = STATE_ERROR;
            }
            WatchUi.requestUpdate();
        } else if (uuid.equals(CarKeyProfile.COMMAND_CHAR_UUID)) {
            if (status == Ble.STATUS_SUCCESS) {
                _state = STATE_WAITING_STATUS;
                _statusText = "Sent, waiting...";
                _timer.start(method(:onStatusTimeout), 2000, false);
            } else {
                _statusText = "Write error: " + status;
                _state = STATE_ERROR;
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
                _statusText = "Button pressed";
                _state = STATE_CONNECTED;
                // Vibrate for feedback
                if (Toybox.Attention has :vibrate) {
                    Toybox.Attention.vibrate([
                        new Toybox.Attention.VibeProfile(100, 200)
                    ]);
                }
            } else if (statusStr.find("OK:AUTH") != null) {
                _statusText = "Authenticated";
                _state = STATE_CONNECTED;
            } else if (statusStr.find("ERR:BUSY") != null) {
                _statusText = "Busy, try again";
                _state = STATE_CONNECTED; // recoverable, not an error state
            } else if (statusStr.find("ERR:AUTH") != null) {
                _statusText = "Auth failed";
                _state = STATE_CONNECTED; // recoverable — user can retry
            } else if (statusStr.find("ERR") != null) {
                _statusText = "Error: " + statusStr;
                _state = STATE_ERROR;
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
            // If user pressed SELECT while disconnected, execute now
            if (_hasPendingUnlock && _device != null && _device.isConnected()) {
                _hasPendingUnlock = false;
                readChallenge();
            }
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    // Fix: Explicitly type 'bytes' so the compiler knows it can be indexed
    private function byteArrayToString(bytes as Lang.ByteArray) {
        var chars = new [bytes.size()];
        for (var i = 0; i < bytes.size(); i++) {
            chars[i] = (bytes[i] & 0xFF).toChar();
        }
        return StringUtil.charArrayToString(chars);
    }
}