import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';
import 'package:crypto/crypto.dart';
import 'package:local_auth/local_auth.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:permission_handler/permission_handler.dart';

// ============================================================
// Configuration - must match firmware UUIDs
// ============================================================

const serviceUuidStr = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const challengeCharUuidStr = 'a1b2c3d4-e5f6-7890-abcd-ef1234567891';
const commandCharUuidStr = 'a1b2c3d4-e5f6-7890-abcd-ef1234567892';
const statusCharUuidStr = 'a1b2c3d4-e5f6-7890-abcd-ef1234567893';
const pskUpdateCharUuidStr = 'a1b2c3d4-e5f6-7890-abcd-ef1234567894';

final serviceUuid = Guid(serviceUuidStr);
final challengeCharUuid = Guid(challengeCharUuidStr);
final commandCharUuid = Guid(commandCharUuidStr);
final statusCharUuid = Guid(statusCharUuidStr);
final pskUpdateCharUuid = Guid(pskUpdateCharUuidStr);

const bleDeviceName = 'BLE-Device';

// Command type prefixes - must match firmware
const cmdAuthOnly = 0x01;
const cmdPress = 0x02;

// Secure storage keys
const _pskStorageKey = 'car_unlock_psk';
const _cachedMacStorageKey = 'car_unlock_cached_mac';

void main() {
  runApp(const CarKeyApp());
}

class CarKeyApp extends StatelessWidget {
  const CarKeyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Car Key',
      theme: ThemeData(
        brightness: Brightness.dark,
        colorSchemeSeed: Colors.blue,
        useMaterial3: true,
      ),
      home: const AuthGate(),
    );
  }
}

// ============================================================
// Biometric auth gate
// ============================================================

class AuthGate extends StatefulWidget {
  const AuthGate({super.key});

  @override
  State<AuthGate> createState() => _AuthGateState();
}

class _AuthGateState extends State<AuthGate> {
  final LocalAuthentication _localAuth = LocalAuthentication();
  bool _authenticated = false;
  bool _checking = true;

  @override
  void initState() {
    super.initState();
    _authenticate();
  }

  Future<void> _authenticate() async {
    try {
      final bool canAuth = await _localAuth.canCheckBiometrics ||
          await _localAuth.isDeviceSupported();

      if (!canAuth) {
        setState(() {
          _authenticated = true;
          _checking = false;
        });
        return;
      }

      final bool result = await _localAuth.authenticate(
        localizedReason: 'Authenticate to access Car Key',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: false,
        ),
      );

      setState(() {
        _authenticated = result;
        _checking = false;
      });
    } catch (e) {
      setState(() {
        _authenticated = false;
        _checking = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        // UnlockScreen is always mounted so BLE connects immediately
        const UnlockScreen(),

        // Auth overlay - blocks interaction until authenticated
        if (!_authenticated)
          Scaffold(
            body: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.lock_outline, size: 64),
                  const SizedBox(height: 24),
                  Text(
                    _checking ? 'Authenticating...' : 'Authentication required',
                  ),
                  const SizedBox(height: 16),
                  if (_checking)
                    const CircularProgressIndicator()
                  else
                    FilledButton.icon(
                      onPressed: _authenticate,
                      icon: const Icon(Icons.fingerprint),
                      label: const Text('Authenticate'),
                    ),
                ],
              ),
            ),
          ),
      ],
    );
  }
}

// ============================================================
// Main unlock screen
// ============================================================

class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();
  final LocalAuthentication _localAuth = LocalAuthentication();

  // State
  BleConnectionState _connectionState = BleConnectionState.disconnected;
  String _statusMessage = 'Not connected';
  BluetoothDevice? _device;
  StreamSubscription? _scanSub;
  StreamSubscription? _connectionSub;
  StreamSubscription? _statusSub;
  StreamSubscription? _challengeSub;
  Uint8List? _currentNonce;
  bool _isProcessing = false;

  // Discovered characteristics
  BluetoothCharacteristic? _challengeChar;
  BluetoothCharacteristic? _commandChar;
  BluetoothCharacteristic? _statusChar;
  BluetoothCharacteristic? _pskUpdateChar;

  // Command result feedback
  CommandResult? _lastResult;
  Timer? _resultClearTimer;

  // PSK
  String _psk = '';
  bool _pskConfigured = false;

  // Cached device MAC
  String? _cachedMac;

  // Auto-reconnect
  bool _shouldAutoConnect = true;

  @override
  void initState() {
    super.initState();
    _loadConfig().then((_) {
      _requestPermissions().then((_) {
        if (_pskConfigured) {
          _startConnection();
        } else {
          Future.delayed(const Duration(milliseconds: 300), _showInitialPSKDialog);
        }
      });
    });
  }

  @override
  void dispose() {
    _scanSub?.cancel();
    _connectionSub?.cancel();
    _statusSub?.cancel();
    _challengeSub?.cancel();
    _resultClearTimer?.cancel();
    super.dispose();
  }

  Future<void> _requestPermissions() async {
    await [
      Permission.bluetoothScan,
      Permission.bluetoothConnect,
      Permission.locationWhenInUse,
    ].request();
  }

  Future<void> _loadConfig() async {
    final storedPsk = await _secureStorage.read(key: _pskStorageKey);
    final storedMac = await _secureStorage.read(key: _cachedMacStorageKey);
    setState(() {
      if (storedPsk != null && storedPsk.isNotEmpty) {
        _psk = storedPsk;
        _pskConfigured = true;
      }
      _cachedMac = storedMac;
    });
  }

  Future<void> _savePSKLocally(String psk) async {
    await _secureStorage.write(key: _pskStorageKey, value: psk);
    setState(() {
      _psk = psk;
      _pskConfigured = true;
    });
  }

  Future<void> _cacheDeviceMac(String mac) async {
    _cachedMac = mac;
    await _secureStorage.write(key: _cachedMacStorageKey, value: mac);
  }

  // --------------------------------------------------------
  // BLE Connection Strategy
  // --------------------------------------------------------

  bool _deviceReady = false;

  /// Start connection in parallel:
  /// - Always start scanning
  /// - If cached MAC exists, also try direct connect simultaneously
  /// - Whichever succeeds first calls _setupDevice, the other is ignored
  void _startConnection() {
    if (_connectionState != BleConnectionState.disconnected) return;

    _deviceReady = false;

    setState(() {
      _connectionState = BleConnectionState.scanning;
      _statusMessage = _cachedMac != null ? 'Connecting...' : 'Scanning...';
    });

    // Always start scanning
    _startScan();

    // If cached MAC exists, try direct connect in parallel
    if (_cachedMac != null) {
      _tryDirectConnect(_cachedMac!);
    }
  }

  void _startScan() {
    _scanSub?.cancel();
    _scanSub = FlutterBluePlus.scanResults.listen(
      (results) {
        if (_deviceReady) return;
        for (final r in results) {
          if (r.device.platformName == bleDeviceName ||
              r.advertisementData.serviceUuids.contains(serviceUuid)) {
            FlutterBluePlus.stopScan();
            _scanSub?.cancel();
            _connectFromScan(r.device);
            return;
          }
        }
      },
      onError: (error) {
        if (!_deviceReady) {
          setState(() {
            _connectionState = BleConnectionState.disconnected;
            _statusMessage = 'Scan error';
          });
        }
      },
    );

    FlutterBluePlus.startScan(
      withServices: [serviceUuid],
      timeout: const Duration(seconds: 10),
    ).then((_) {
      if (!_deviceReady && _connectionState == BleConnectionState.scanning) {
        _scanSub?.cancel();
        setState(() {
          _connectionState = BleConnectionState.disconnected;
          _statusMessage = 'Device not found';
        });
        if (_shouldAutoConnect && _pskConfigured) {
          Future.delayed(const Duration(seconds: 3), _startConnection);
        }
      }
    });
  }

  void _tryDirectConnect(String mac) {
    final device = BluetoothDevice.fromId(mac);
    device.connect(
      timeout: const Duration(seconds: 3),
      autoConnect: false,
    ).then((_) {
      if (!_deviceReady) {
        _deviceReady = true;
        FlutterBluePlus.stopScan();
        _scanSub?.cancel();
        _setupDevice(device);
      } else {
        // Scan already won, disconnect this one
        device.disconnect();
      }
    }).catchError((e) {
      debugPrint('Direct connect failed, scan continues');
    });
  }

  void _connectFromScan(BluetoothDevice device) {
    if (_deviceReady) return;

    setState(() {
      _connectionState = BleConnectionState.connecting;
      _statusMessage = 'Connecting...';
    });

    device.connect(timeout: const Duration(seconds: 10)).then((_) {
      if (!_deviceReady) {
        _deviceReady = true;
        _setupDevice(device);
      } else {
        device.disconnect();
      }
    }).catchError((e) {
      debugPrint('Scan connect failed: $e');
      if (!_deviceReady) {
        _resetConnectionState();
        if (_shouldAutoConnect && _pskConfigured) {
          Future.delayed(const Duration(seconds: 2), _startConnection);
        }
      }
    });
  }

  /// Set up a connected device: listen for disconnects, cache MAC, discover services
  void _setupDevice(BluetoothDevice device) {
    _device = device;
    setState(() {
      _connectionState = BleConnectionState.connected;
      _statusMessage = 'Discovering services...';
    });

    _cacheDeviceMac(device.remoteId.str);

    // Listen for future disconnects
    _connectionSub?.cancel();
    _connectionSub = device.connectionState.listen(
      (state) {
        if (state == BluetoothConnectionState.disconnected) {
          _resetConnectionState();
          if (_shouldAutoConnect && _pskConfigured) {
            Future.delayed(const Duration(seconds: 2), _startConnection);
          }
        }
      },
    );

    _discoverAndSubscribe();
  }

  void _resetConnectionState() {
    setState(() {
      _connectionState = BleConnectionState.disconnected;
      _statusMessage = 'Disconnected';
      _currentNonce = null;
      _lastResult = null;
      _challengeChar = null;
      _commandChar = null;
      _statusChar = null;
      _pskUpdateChar = null;
    });
  }

  Future<void> _discoverAndSubscribe() async {
    if (_device == null) return;

    try {
      final services = await _device!.discoverServices();

      for (final svc in services) {
        if (svc.uuid == serviceUuid) {
          for (final c in svc.characteristics) {
            if (c.uuid == challengeCharUuid) _challengeChar = c;
            if (c.uuid == commandCharUuid) _commandChar = c;
            if (c.uuid == statusCharUuid) _statusChar = c;
            if (c.uuid == pskUpdateCharUuid) _pskUpdateChar = c;
          }
        }
      }

      if (_challengeChar == null || _commandChar == null || _statusChar == null) {
        debugPrint('Missing required characteristics');
        setState(() {
          _statusMessage = 'Service mismatch';
        });
        return;
      }

      setState(() {
        _statusMessage = 'Connected';
      });

      _subscribeToChallengeAndStatus();
      Future.delayed(const Duration(milliseconds: 200), _sendAuthPing);
    } catch (e) {
      debugPrint('Service discovery failed: $e');
      setState(() {
        _statusMessage = 'Discovery failed';
      });
    }
  }

  void _disconnect() {
    _shouldAutoConnect = false;
    _connectionSub?.cancel();
    _statusSub?.cancel();
    _challengeSub?.cancel();
    _device?.disconnect();
    setState(() {
      _connectionState = BleConnectionState.disconnected;
      _statusMessage = 'Disconnected';
      _device = null;
      _currentNonce = null;
      _lastResult = null;
      _challengeChar = null;
      _commandChar = null;
      _statusChar = null;
      _pskUpdateChar = null;
    });
  }

  void _reconnect() {
    _shouldAutoConnect = true;
    _startConnection();
  }

  // --------------------------------------------------------
  // GATT Operations
  // --------------------------------------------------------

  Future<void> _readChallenge() async {
    if (_challengeChar == null) return;
    try {
      final data = await _challengeChar!.read();
      _currentNonce = Uint8List.fromList(data);
    } catch (e) {
      debugPrint('Failed to read challenge: $e');
    }
  }

  void _subscribeToChallengeAndStatus() {
    _challengeSub?.cancel();
    _challengeChar?.setNotifyValue(true);
    _challengeSub = _challengeChar?.onValueReceived.listen(
      (data) {
        _currentNonce = Uint8List.fromList(data);
      },
      onError: (error) {
        debugPrint('Challenge subscription error: $error');
      },
    );

    _statusSub?.cancel();
    _statusChar?.setNotifyValue(true);
    _statusSub = _statusChar?.onValueReceived.listen(
      (data) {
        try {
          final status = utf8.decode(data);
          if (status.startsWith('OK:') ||
              status.startsWith('ERR:') ||
              status == 'READY') {
            setState(() {
              if (status == 'OK:PRESSED') {
                _statusMessage = 'Command sent';
                _lastResult = CommandResult.success;
              } else if (status == 'OK:AUTH') {
                _statusMessage = 'Authenticated';
              } else if (status == 'OK:PSK_UPDATED') {
                _statusMessage = 'PSK updated on device';
                _lastResult = CommandResult.success;
              } else if (status == 'ERR:AUTH') {
                _statusMessage = 'Authentication failed';
                _lastResult = CommandResult.error;
              } else if (status.startsWith('ERR:')) {
                _statusMessage = 'Error: ${status.substring(4)}';
                _lastResult = CommandResult.error;
              } else if (status == 'READY') {
                _statusMessage = 'Connected';
              }
            });
            _resultClearTimer?.cancel();
            _resultClearTimer = Timer(const Duration(seconds: 2), () {
              if (mounted) {
                setState(() {
                  _lastResult = null;
                });
              }
            });
          }
        } catch (_) {}
      },
      onError: (error) {},
    );

    _readChallenge();
  }

  Uint8List _computeHMAC(Uint8List nonce, String key) {
    final keyBytes = utf8.encode(key);
    final hmacSha256 = Hmac(sha256, keyBytes);
    final digest = hmacSha256.convert(nonce);
    return Uint8List.fromList(digest.bytes);
  }

  Uint8List _buildCommandPayload(int cmdType, Uint8List nonce, String key) {
    final hmac = _computeHMAC(nonce, key);
    return Uint8List.fromList([cmdType, ...hmac]);
  }

  Future<void> _sendAuthPing() async {
    if (_device == null || _commandChar == null || _currentNonce == null) return;
    try {
      final payload = _buildCommandPayload(cmdAuthOnly, _currentNonce!, _psk);
      await _commandChar!.write(payload, withoutResponse: false);
    } catch (e) {
      debugPrint('Auth ping failed: $e');
    }
  }

  Future<void> _sendCommand() async {
    if (_device == null || _commandChar == null || _isProcessing) return;

    setState(() {
      _isProcessing = true;
      _lastResult = null;
      _statusMessage = 'Sending...';
    });

    try {
      if (_currentNonce == null || _currentNonce!.isEmpty) {
        await _readChallenge();
        if (_currentNonce == null || _currentNonce!.isEmpty) {
          setState(() {
            _statusMessage = 'No challenge nonce';
            _lastResult = CommandResult.error;
            _isProcessing = false;
          });
          return;
        }
      }
      final payload = _buildCommandPayload(cmdPress, _currentNonce!, _psk);
      await _commandChar!.write(payload, withoutResponse: false);
    } catch (e) {
      setState(() {
        _statusMessage = 'Send error';
        _lastResult = CommandResult.error;
      });
    } finally {
      setState(() {
        _isProcessing = false;
      });
    }
  }

  // --------------------------------------------------------
  // PSK Management (requires biometric re-auth)
  // --------------------------------------------------------

  Future<bool> _reauthenticate() async {
    try {
      return await _localAuth.authenticate(
        localizedReason: 'Authenticate to access PSK settings',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: false,
        ),
      );
    } catch (_) {
      return false;
    }
  }

  Future<void> _showInitialPSKDialog() async {
    final controller = TextEditingController();
    await showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => AlertDialog(
        title: const Text('Welcome'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Enter the pre-shared key that matches your device firmware:',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              obscureText: true,
              autofocus: true,
              decoration: const InputDecoration(
                labelText: 'PSK',
                border: OutlineInputBorder(),
              ),
            ),
          ],
        ),
        actions: [
          FilledButton(
            onPressed: () {
              if (controller.text.trim().isNotEmpty) {
                _savePSKLocally(controller.text.trim());
                Navigator.pop(context);
                _startConnection();
              }
            },
            child: const Text('Save & Connect'),
          ),
        ],
      ),
    );
  }

  Future<void> _showPSKDialog() async {
    final authed = await _reauthenticate();
    if (!authed || !mounted) return;

    final newPskController = TextEditingController();
    final confirmPskController = TextEditingController();
    bool localOnly = _connectionState != BleConnectionState.connected;

    await showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('PSK Settings'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (!_pskConfigured) ...[
                  const Text(
                    'Set your initial PSK (must match the firmware default):',
                    style: TextStyle(fontSize: 13),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: newPskController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'PSK',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ] else ...[
                  const Text(
                    'Change PSK:',
                    style: TextStyle(fontSize: 13),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: newPskController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'New PSK',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: confirmPskController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'Confirm new PSK',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  if (_connectionState == BleConnectionState.connected) ...[
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Checkbox(
                          value: !localOnly,
                          onChanged: (v) {
                            setDialogState(() {
                              localOnly = !(v ?? false);
                            });
                          },
                        ),
                        const Expanded(
                          child: Text(
                            'Also update on device',
                            style: TextStyle(fontSize: 13),
                          ),
                        ),
                      ],
                    ),
                  ],
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () async {
                final newPsk = newPskController.text.trim();
                if (newPsk.isEmpty) return;

                if (_pskConfigured) {
                  if (newPsk != confirmPskController.text.trim()) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('PSK values do not match')),
                    );
                    return;
                  }

                  if (!localOnly &&
                      _connectionState == BleConnectionState.connected &&
                      _pskUpdateChar != null) {
                    try {
                      await _readChallenge();
                      if (_currentNonce == null) {
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Failed to read challenge')),
                          );
                        }
                        return;
                      }
                      final hmac = _computeHMAC(_currentNonce!, _psk);
                      final separator = Uint8List.fromList([0x00]);
                      final newPskBytes = Uint8List.fromList(utf8.encode(newPsk));
                      final payload = Uint8List.fromList([
                        ...hmac,
                        ...separator,
                        ...newPskBytes,
                      ]);

                      await _pskUpdateChar!.write(payload, withoutResponse: false);
                    } catch (e) {
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Failed to update PSK on device')),
                        );
                      }
                      return;
                    }
                  }
                }

                await _savePSKLocally(newPsk);
                if (context.mounted) {
                  Navigator.pop(context);
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text(localOnly
                          ? 'PSK saved locally'
                          : 'PSK updated locally and on device'),
                    ),
                  );
                }
              },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
  }

  // --------------------------------------------------------
  // UI
  // --------------------------------------------------------

  Color get _statusColor {
    switch (_connectionState) {
      case BleConnectionState.connected:
        return Colors.green;
      case BleConnectionState.scanning:
      case BleConnectionState.connecting:
        return Colors.orange;
      case BleConnectionState.disconnected:
        return Colors.red;
    }
  }

  IconData get _connectionIcon {
    switch (_connectionState) {
      case BleConnectionState.connected:
        return Icons.bluetooth_connected;
      case BleConnectionState.scanning:
        return Icons.bluetooth_searching;
      case BleConnectionState.connecting:
        return Icons.bluetooth;
      case BleConnectionState.disconnected:
        return Icons.bluetooth_disabled;
    }
  }

  Color? get _buttonColor {
    if (_lastResult == CommandResult.success) return Colors.green;
    if (_lastResult == CommandResult.error) return Colors.red;
    return null;
  }

  IconData get _buttonIcon {
    if (_isProcessing) return Icons.hourglass_top;
    if (_lastResult == CommandResult.success) return Icons.check_circle;
    if (_lastResult == CommandResult.error) return Icons.error;
    return Icons.touch_app;
  }

  String get _buttonText {
    if (_isProcessing) return 'Sending...';
    if (_lastResult == CommandResult.success) return 'Sent';
    if (_lastResult == CommandResult.error) return 'Failed';
    return 'Press';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Car Key'),
        actions: [
          IconButton(
            icon: const Icon(Icons.key),
            tooltip: 'PSK Settings',
            onPressed: _showPSKDialog,
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              // Connection status card
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Icon(_connectionIcon, color: _statusColor, size: 32),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              _connectionState.label,
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                            Text(
                              _statusMessage,
                              style: Theme.of(context).textTheme.bodySmall,
                            ),
                          ],
                        ),
                      ),
                      if (_connectionState == BleConnectionState.disconnected &&
                          !_shouldAutoConnect)
                        FilledButton(
                          onPressed: _pskConfigured ? _reconnect : null,
                          child: const Text('Connect'),
                        )
                      else if (_connectionState == BleConnectionState.connected)
                        OutlinedButton(
                          onPressed: _disconnect,
                          child: const Text('Disconnect'),
                        )
                      else
                        const SizedBox(
                          width: 24,
                          height: 24,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                    ],
                  ),
                ),
              ),

              if (!_pskConfigured) ...[
                const SizedBox(height: 32),
                const Icon(Icons.warning_amber, size: 48, color: Colors.orange),
                const SizedBox(height: 16),
                const Text(
                  'PSK not configured. Tap the key icon to set your pre-shared key.',
                  textAlign: TextAlign.center,
                ),
              ],

              const Spacer(),

              // Main button
              SizedBox(
                width: 200,
                height: 200,
                child: ElevatedButton(
                  onPressed:
                      (_connectionState == BleConnectionState.connected && !_isProcessing)
                          ? _sendCommand
                          : null,
                  style: ElevatedButton.styleFrom(
                    shape: const CircleBorder(),
                    padding: const EdgeInsets.all(32),
                    backgroundColor:
                        _buttonColor ?? Theme.of(context).colorScheme.primaryContainer,
                    foregroundColor: _buttonColor != null
                        ? Colors.white
                        : Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(_buttonIcon, size: 48),
                      const SizedBox(height: 8),
                      Text(
                        _buttonText,
                        style: Theme.of(context).textTheme.titleLarge?.copyWith(
                              color: _buttonColor != null ? Colors.white : null,
                            ),
                      ),
                    ],
                  ),
                ),
              ),

              const Spacer(),
            ],
          ),
        ),
      ),
    );
  }
}

// ============================================================
// Enums
// ============================================================

enum BleConnectionState {
  disconnected('Disconnected'),
  scanning('Scanning...'),
  connecting('Connecting...'),
  connected('Connected');

  final String label;
  const BleConnectionState(this.label);
}

enum CommandResult {
  success,
  error,
}
