using Toybox.BluetoothLowEnergy as Ble;
using Toybox.Cryptography;
using Toybox.System;
using Toybox.Application;
using Toybox.WatchUi;
using Toybox.Lang;

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

    function initialize() {
        BleDelegate.initialize();
        Ble.setDelegate(self);

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
        if (_device == null || !_device.isConnected()) {
            // Not connected, try scanning first
            _pendingCommand = CarKeyProfile.CMD_PRESS;
            startScan();
            return;
        }
        _pendingCommand = CarKeyProfile.CMD_PRESS;
        readChallenge();
    }

    function disconnect() {
        if (_device != null) {
            Ble.unpairDevice(_device);
            _device = null;
        }
        _state = STATE_IDLE;
        _statusText = "Disconnected";
        WatchUi.requestUpdate();
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
            // Scan was stopped externally
            if (_device == null) {
                _state = STATE_IDLE;
                _statusText = "Not found";
                WatchUi.requestUpdate();
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

            // Enable notifications on status characteristic
            enableStatusNotifications();

        } else {
            _device = null;
            _state = STATE_IDLE;
            _statusText = "Disconnected";
            WatchUi.requestUpdate();
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
            } else {
                _statusText = "Write pt2 err: " + status;
                _state = STATE_ERROR;
            }
            WatchUi.requestUpdate();
        } else if (uuid.equals(CarKeyProfile.COMMAND_CHAR_UUID)) {
            if (status == Ble.STATUS_SUCCESS) {
                _state = STATE_WAITING_STATUS;
                _statusText = "Sent, waiting...";
            } else {
                _statusText = "Write error: " + status;
                _state = STATE_ERROR;
            }
            WatchUi.requestUpdate();
        }
    }

    function onCharacteristicChanged(char, value) {
        if (char.getUuid().equals(CarKeyProfile.STATUS_CHAR_UUID)) {
            // Parse status from ESP32
            var statusStr = byteArrayToString(value as Lang.ByteArray); // Added cast for safety
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
            } else if (statusStr.find("ERR") != null) {
                _statusText = "Error: " + statusStr;
                _state = STATE_ERROR;
            } else {
                _statusText = statusStr;
            }
            WatchUi.requestUpdate();
        }
    }

    function onDescriptorWrite(desc, status) {
        // CCCD write complete
        if (status == Ble.STATUS_SUCCESS) {
            System.println("Notifications enabled");
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