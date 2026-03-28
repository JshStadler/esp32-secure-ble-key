# BLE Car Key — Flutter App

The companion mobile app for the BLE Car Key system. Connects to the ESP32 over Bluetooth Low Energy, authenticates with HMAC-SHA256, and sends unlock/lock commands.

## Features

- BLE scanning and connection with device caching for fast reconnect
- HMAC-SHA256 challenge-response authentication
- Biometric gating (fingerprint / face) before any action
- PSK management with platform-native secure storage
- Auto-reconnect and connection state feedback

## Requirements

- Flutter SDK 3.0+
- Android device with BLE support (Android 6.0+) or iOS 12+

## Setup

```bash
flutter pub get
flutter run
```

On first launch, enter the same PSK that was flashed onto the ESP32 firmware.

## Dependencies

| Package | Purpose |
|---|---|
| `flutter_blue_plus` | BLE connectivity |
| `crypto` | HMAC-SHA256 computation |
| `local_auth` | Biometric authentication |
| `flutter_secure_storage` | Encrypted PSK storage |
| `permission_handler` | Bluetooth and location permissions |
