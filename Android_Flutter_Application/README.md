# BLE Car Key — Flutter App

The companion mobile app for the BLE Car Key system. Connects to the ESP32 over Bluetooth Low Energy, authenticates with HMAC-SHA256, and sends unlock/lock commands.

## Features

- BLE scanning and connection with device caching for fast reconnect
- HMAC-SHA256 challenge-response authentication
- Optional device-authentication gate (fingerprint, face, or device PIN)
- Authentication can be disabled for the main button during frequent use
- PSK changes always require device authentication
- PSK management with platform-native secure storage
- Auto-reconnect and connection state feedback
- Optional cached-address fast connection with persistent scan fallback

## Requirements

- Flutter SDK 3.44+
- JDK 17
- Android device with BLE support (Android 6.0+) or iOS 12+

## Setup

```bash
flutter pub get
flutter run
```

On first launch, enter the same PSK that was flashed onto the ESP32 firmware.

Device authentication is enabled by default. Open **App Settings** from the gear
icon and turn off **Require device authentication** to open and use the main
car-key button without a prompt. This preference persists across app restarts.
Changing the PSK remains protected by device authentication.

For faster connections, enable **Use cached device address** after the app has
connected once. Cached attempts continue while the app is in the foreground.
After three failures, **Scan for device** appears; tapping it keeps scanning and
retrying until a connection succeeds, then future connections return to the
cached fast path.

## Dependencies

| Package | Purpose |
|---|---|
| `flutter_blue_plus` | BLE connectivity |
| `crypto` | HMAC-SHA256 computation |
| `local_auth` | Biometric authentication |
| `flutter_secure_storage` | Encrypted PSK storage |
| `permission_handler` | Bluetooth and location permissions |
