using Toybox.BluetoothLowEnergy as Ble;
using Toybox.Cryptography;
using Toybox.System;
using Toybox.Application;
using Toybox.WatchUi;
using Toybox.Lang;
using Toybox.Timer;
using Toybox.StringUtil;

enum { STATE_IDLE, STATE_SCANNING, STATE_CONNECTING, STATE_CONNECTED,
       STATE_READING_CHALLENGE, STATE_SENDING_COMMAND, STATE_WAITING_STATUS, STATE_ERROR }

// Shared recovery state machine for Car notifications and Gate read responses.
class BleHandler extends Ble.BleDelegate {
    var _device = null;
    var _state = STATE_IDLE;
    var _statusText = "Ready";
    var _registered = false;
    var _stopped = true;
    var _authenticated = false;
    var _subscribing = false;
    var _hasPendingPress = false;
    var _pendingCommand = null;
    var _part2 = null;
    var _writeStage = 0;
    var _earlyStatus = null;
    var _retries = 0;
    var _timer;
    var _operationTimer;
    var _connectionTimer;
    var _windowTimer;

    function initialize() {
        BleDelegate.initialize();
        _timer = new Timer.Timer();
        _operationTimer = new Timer.Timer();
        _connectionTimer = new Timer.Timer();
        _windowTimer = new Timer.Timer();
        Ble.setDelegate(self);
        try { Ble.registerProfile(CarKeyProfile.getProfileDef()); }
        catch (e) { System.println("Profile registration: " + e.getErrorMessage()); }
    }
    function getStatusText() { return _statusText; }
    function getState() { return _state; }
    function hasPendingPress() { return _hasPendingPress; }
    function isConnected() { return !_stopped && _authenticated && _device != null && _device.isConnected(); }
    private function configured() {
        var key = Application.Properties.getValue("psk");
        return key instanceof Lang.String && key.length() > 0 && !key.equals("SET_IN_CONNECT_IQ");
    }
    private function show(text) { _statusText = text; WatchUi.requestUpdate(); }
    function startConnectionWindow() {
        recordInteraction();
        if (!configured()) { _stopped = true; _state = STATE_ERROR; show("Set PSK in Connect IQ"); return; }
        _stopped = false;
        if (_registered) { startScan(); } else { show("Preparing Bluetooth..."); }
    }
    function applySettings() { disconnect(); startConnectionWindow(); }
    function cleanup() {
        _stopped = true;
        _timer.stop(); _operationTimer.stop(); _connectionTimer.stop(); _windowTimer.stop();
        stopScan();
        _pendingCommand = null; _part2 = null; _earlyStatus = null; _hasPendingPress = false;
        // Retain a healthy cached pairing, but discard one with unfinished ATT work.
        if (_subscribing || _state == STATE_READING_CHALLENGE || _state == STATE_SENDING_COMMAND || _state == STATE_WAITING_STATUS) { releaseDevice(); }
        _subscribing = false; _authenticated = false;
    }
    function disconnect() { cleanup(); releaseDevice(); _state = STATE_IDLE; show("Disconnected"); }
    function forceUnpair() {
        disconnect();
        try {
            var devices = [];
            var iterator = Ble.getPairedDevices();
            for (var d = iterator.next(); d != null; d = iterator.next()) {
                if (!(d instanceof Ble.Device)) { continue; }
                if (d.getService(CarKeyProfile.SERVICE_UUID) != null) { devices.add(d); }
            }
            for (var i = 0; i < devices.size(); i++) { Ble.unpairDevice(devices[i]); }
        } catch (e) { System.println("Pairing cleanup: " + e.getErrorMessage()); }
        startConnectionWindow();
    }
    private function releaseDevice() {
        var old = _device;
        _device = null; // Invalidate before unpair emits a disconnect callback.
        if (old != null) { try { Ble.unpairDevice(old); } catch (e) { System.println("Unpair: " + e.getErrorMessage()); } }
    }
    private function owns(device) { return !_stopped && _device != null && _device.equals(device); }
    private function ownsCharacteristic(c) { return owns(c.getService().getDevice()); }
    private function stopScan() { try { Ble.setScanState(Ble.SCAN_STATE_OFF); } catch (e) {} }
    private function startScan() {
        if (_stopped || !_registered || _state == STATE_SCANNING || _state == STATE_CONNECTING) { return; }
        // Reuse a live pairing on a clean app launch, then authenticate it again.
        if (_retries == 0 && _device == null) {
            try {
                var paired = Ble.getPairedDevices();
                for (var d = paired.next(); d != null; d = paired.next()) {
                    if (!(d instanceof Ble.Device)) { continue; }
                    if (d.isConnected() && d.getService(CarKeyProfile.SERVICE_UUID) != null) {
                        _device = d;
                        onConnectedStateChanged(d, Ble.CONNECTION_STATE_CONNECTED);
                        return;
                    }
                }
            } catch (e) { System.println("Cached pairing: " + e.getErrorMessage()); }
        }
        _state = STATE_SCANNING;
        show("Scanning");
        try {
            Ble.setScanState(Ble.SCAN_STATE_SCANNING);
            _connectionTimer.start(method(:onConnectionTimeout), 10000, false);
        } catch (e) { recover("Scan failed", true); }
    }
    function onProfileRegister(uuid, status) {
        if (!uuid.equals(CarKeyProfile.SERVICE_UUID)) { return; }
        _registered = status == Ble.STATUS_SUCCESS;
        if (_registered && !_stopped) { startScan(); }
        else if (!_registered) { _state = STATE_ERROR; show("Bluetooth unavailable"); }
    }
    function onScanStateChanged(scanState, status) {
        if (!_stopped && _state == STATE_SCANNING && (status != Ble.STATUS_SUCCESS || scanState == Ble.SCAN_STATE_OFF)) { recover("Scan interrupted", true); }
    }
    function onScanResults(results as Ble.Iterator) as Void {
        if (_stopped || _state != STATE_SCANNING) { return; }
        for (var result = results.next(); result != null; result = results.next()) {
            if (!(result instanceof Ble.ScanResult)) { continue; }
            var match = false;
            var uuids = result.getServiceUuids();
            if (uuids != null) {
                for (var uuid = uuids.next(); uuid != null; uuid = uuids.next()) {
                    if (uuid.equals(CarKeyProfile.SERVICE_UUID)) { match = true; break; }
                }
            }
            var name = result.getDeviceName();
            if (!match && !(name != null && name.equals(CarKeyProfile.DEVICE_NAME))) { continue; }
            _state = STATE_CONNECTING; // Before stopping scan: ignore its OFF callback.
            stopScan();
            _connectionTimer.stop();
            show("Connecting");
            try {
                _device = Ble.pairDevice(result);
                if (_device == null) { recover("Pairing unavailable", true); return; }
                _connectionTimer.start(method(:onConnectionTimeout), 12000, false);
            } catch (e) { recover("Pairing failed", true); }
            return;
        }
    }
    function onConnectedStateChanged(device, state) {
        if (!owns(device)) { return; }
        if (state != Ble.CONNECTION_STATE_CONNECTED) { recover("Disconnected", _pendingCommand == null || _pendingCommand == CarKeyProfile.CMD_AUTH_ONLY); return; }
        if (_state != STATE_CONNECTING && _state != STATE_IDLE) { return; }
        _timer.stop(); _connectionTimer.stop();
        _state = STATE_CONNECTED; _authenticated = false;
        show("Authenticating");
        if (CarKeyProfile.READ_STATUS) { beginAuthentication(); }
        else {
            _subscribing = true;
            armOperation();
            try {
                var c = characteristic(CarKeyProfile.STATUS_CHAR_UUID);
                var d = c == null ? null : c.getDescriptor(CarKeyProfile.CCCD_UUID);
                if (d == null) { recover("Service cache reset", true); return; }
                d.requestWrite([1, 0]b);
            } catch (e) { recover("Subscription failed", true); }
        }
    }
    private function characteristic(uuid) {
        if (_device == null) { return null; }
        var service = _device.getService(CarKeyProfile.SERVICE_UUID);
        return service == null ? null : service.getCharacteristic(uuid);
    }
    function onDescriptorWrite(desc, status) {
        if (!_subscribing || !ownsCharacteristic(desc.getCharacteristic())) { return; }
        _operationTimer.stop(); _subscribing = false;
        if (status != Ble.STATUS_SUCCESS) { recover("Subscription failed", true); return; }
        beginAuthentication();
    }
    private function beginAuthentication() { _pendingCommand = CarKeyProfile.CMD_AUTH_ONLY; readChallenge(); }
    function sendPress() {
        recordInteraction();
        dispatchPress();
    }
    private function dispatchPress() {
        if (!configured()) { show("Set PSK in Connect IQ"); return; }
        if (_pendingCommand == CarKeyProfile.CMD_PRESS) { return; }
        if (_pendingCommand != null || _subscribing) { _hasPendingPress = true; show("Press queued"); return; }
        if (!isConnected()) {
            _hasPendingPress = true;
            if (_stopped || _state == STATE_IDLE || _state == STATE_ERROR) { _state = STATE_IDLE; startConnectionWindow(); }
            show("Press queued");
            return;
        }
        _hasPendingPress = false;
        _pendingCommand = CarKeyProfile.CMD_PRESS;
        readChallenge();
    }
    private function readChallenge() {
        _state = STATE_READING_CHALLENGE;
        _writeStage = 0; _earlyStatus = null;
        armOperation();
        try {
            var c = characteristic(CarKeyProfile.CHALLENGE_CHAR_UUID);
            if (c == null) { recover("Service cache reset", false); return; }
            c.requestRead();
        } catch (e) { recover("Challenge read failed", false); }
    }
    function onCharacteristicRead(c, status, value) {
        if (!ownsCharacteristic(c)) { return; }
        var uuid = c.getUuid();
        if (uuid.equals(CarKeyProfile.CHALLENGE_CHAR_UUID) && _state == STATE_READING_CHALLENGE) {
            if (status != Ble.STATUS_SUCCESS || !(value instanceof Lang.ByteArray) || value.size() != 16) { recover("Invalid challenge", false); return; }
            _operationTimer.stop();
            sendCommand(value);
        } else if (CarKeyProfile.READ_STATUS && uuid.equals(CarKeyProfile.STATUS_CHAR_UUID) && _state == STATE_WAITING_STATUS) {
            if (status != Ble.STATUS_SUCCESS) { recover("Status read failed", false); return; }
            finishStatus(value);
        }
    }
    private function utf8(text) {
        return StringUtil.convertEncodedString(text, {:fromRepresentation => StringUtil.REPRESENTATION_STRING_PLAIN_TEXT,
            :toRepresentation => StringUtil.REPRESENTATION_BYTE_ARRAY, :encoding => StringUtil.CHAR_ENCODING_UTF8});
    }
    private function sendCommand(nonce) {
        try {
            var hmac = new Cryptography.HashBasedMessageAuthenticationCode({:algorithm => Cryptography.HASH_SHA256,
                :key => utf8(Application.Properties.getValue("psk"))});
            hmac.update(utf8("BLEKEY-V2")); hmac.update([0]b);
            hmac.update(utf8(CarKeyProfile.BINDING)); hmac.update([0, _pendingCommand]b); hmac.update(nonce);
            var digest = hmac.digest();
            var first = new [17]b; _part2 = new [16]b;
            first[0] = _pendingCommand;
            for (var i = 0; i < 16; i++) { first[i + 1] = digest[i]; _part2[i] = digest[i + 16]; }
            var c = characteristic(CarKeyProfile.COMMAND_PT1_CHAR_UUID);
            if (c == null) { recover("Service cache reset", false); return; }
            _state = STATE_SENDING_COMMAND; _writeStage = 1;
            armOperation();
            c.requestWrite(first, {:writeType => Ble.WRITE_TYPE_WITH_RESPONSE});
        } catch (e) { System.println("Command: " + e.getErrorMessage()); recover("Command failed", false); }
    }
    function onCharacteristicWrite(c, status) {
        if (!ownsCharacteristic(c) || _state != STATE_SENDING_COMMAND) { return; }
        var uuid = c.getUuid();
        if (_writeStage == 1 && uuid.equals(CarKeyProfile.COMMAND_PT1_CHAR_UUID)) {
            if (status != Ble.STATUS_SUCCESS || _part2 == null) { recover("Write failed", false); return; }
            var second = characteristic(CarKeyProfile.COMMAND_PT2_CHAR_UUID);
            if (second == null) { recover("Service cache reset", false); return; }
            _writeStage = 2;
            armOperation();
            try { second.requestWrite(_part2, {:writeType => Ble.WRITE_TYPE_WITH_RESPONSE}); }
            catch (e) { recover("Write failed", false); }
        } else if (_writeStage == 2 && uuid.equals(CarKeyProfile.COMMAND_PT2_CHAR_UUID)) {
            if (status != Ble.STATUS_SUCCESS) { recover("Write failed", false); return; }
            _part2 = null; _writeStage = 0; _state = STATE_WAITING_STATUS;
            armOperation();
            if (_earlyStatus != null) { var early = _earlyStatus; _earlyStatus = null; finishStatus(early); }
            else if (CarKeyProfile.READ_STATUS) { _timer.stop(); _timer.start(method(:readStatus), 100, false); }
        }
    }
    function readStatus() as Void {
        if (_stopped || _state != STATE_WAITING_STATUS) { return; }
        var c = characteristic(CarKeyProfile.STATUS_CHAR_UUID);
        if (c == null) { recover("Status unavailable", false); return; }
        try { c.requestRead(); } catch (e) { recover("Status read failed", false); }
    }
    function onCharacteristicChanged(c, value) {
        if (CarKeyProfile.READ_STATUS || !ownsCharacteristic(c) || !c.getUuid().equals(CarKeyProfile.STATUS_CHAR_UUID)) { return; }
        if (_state == STATE_SENDING_COMMAND && _writeStage == 2) { _earlyStatus = value; }
        else if (_state == STATE_WAITING_STATUS) { finishStatus(value); }
    }
    private function finishStatus(value) {
        if (_pendingCommand == null) { return; }
        var text = byteArrayToString(value);
        System.println("BLE status: " + text);
        var auth = _pendingCommand == CarKeyProfile.CMD_AUTH_ONLY;
        if (auth && !text.equals("OK:AUTH")) { _hasPendingPress = false; recover("Auth failed", false); return; }
        if (!auth && !text.equals("OK:PRESSED") && text.find("ERR:") != 0) { return; }
        _timer.stop(); _operationTimer.stop();
        _pendingCommand = null; _part2 = null; _earlyStatus = null; _writeStage = 0;
        _state = STATE_CONNECTED;
        if (auth) {
            _authenticated = true; _retries = 0;
            show("Authenticated");
            vibrateConnected();
            if (_hasPendingPress) { dispatchPress(); }
        } else {
            show(text.equals("OK:PRESSED") ? "Pressed" : "Command failed");
            if (text.equals("OK:PRESSED")) { vibrateSuccess(); } else { vibrateFailure(); }
        }
    }
    private function armOperation() { _operationTimer.stop(); _operationTimer.start(method(:onOperationTimeout), 5000, false); }
    function onOperationTimeout() as Void {
        if (!_stopped && (_subscribing || _pendingCommand != null)) { recover("No confirmation", false); }
    }
    function onConnectionTimeout() as Void {
        if (!_stopped && (_state == STATE_SCANNING || _state == STATE_CONNECTING)) { recover("Connection timed out", true); }
    }
    function onReconnectTimer() as Void { if (!_stopped && _state == STATE_IDLE) { startScan(); } }
    function recordInteraction() {
        _windowTimer.stop();
        _windowTimer.start(method(:onWindowTimeout), 120000, false);
    }
    function onWindowTimeout() as Void {
        // Only user interaction resets this deadline, never BLE callbacks.
        disconnect();
        System.exit();
    }
    private function recover(message, preserveQueued) {
        if (_stopped) { return; }
        var wasReady = _authenticated;
        var uncertainPress = _pendingCommand == CarKeyProfile.CMD_PRESS;
        System.println("BLE recovery: state=" + _state + " write=" + _writeStage + " " + message);
        _state = STATE_IDLE; // Invalidate state before stop/unpair callbacks.
        _timer.stop(); _operationTimer.stop(); _connectionTimer.stop();
        stopScan(); releaseDevice();
        _authenticated = false; _subscribing = false;
        _pendingCommand = null; _part2 = null; _earlyStatus = null; _writeStage = 0;
        if (!preserveQueued || uncertainPress) { _hasPendingPress = false; }
        if (uncertainPress) { vibrateFailure(); }
        if (wasReady) { vibrateDisconnected(); }
        show(message);
        _retries++;
        _timer.start(method(:onReconnectTimer), _retries < 3 ? 1500 : 3000, false);
    }
    private function byteArrayToString(bytes as Lang.ByteArray) {
        var chars = new [bytes.size()];
        for (var i = 0; i < bytes.size(); i++) { chars[i] = (bytes[i] & 0xff).toChar(); }
        return StringUtil.charArrayToString(chars);
    }
    private function vibrateConnected() { vibratePattern([new Toybox.Attention.VibeProfile(100, 80)]); }
    private function vibrateDisconnected() { vibratePattern([new Toybox.Attention.VibeProfile(100, 80), new Toybox.Attention.VibeProfile(0, 60), new Toybox.Attention.VibeProfile(100, 80)]); }
    private function vibrateSuccess() { vibratePattern([new Toybox.Attention.VibeProfile(100, 200)]); }
    private function vibrateFailure() { vibratePattern([new Toybox.Attention.VibeProfile(100, 220), new Toybox.Attention.VibeProfile(0, 140), new Toybox.Attention.VibeProfile(100, 220)]); }
    private function vibratePattern(pattern) { if (Toybox.Attention has :vibrate) { Toybox.Attention.vibrate(pattern); } }
}
