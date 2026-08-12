# BLE Key — native Android app

This is the supported native Kotlin/Android BLE Key application. It controls
the separately identified Car and Gate devices without a Flutter runtime.

## Features

- Stable two-device dashboard with fixed Car and Gate actions
- Foreground-persistent BLE connections with per-device cached-address retries and scan fallback
- Independent encrypted PSK and address settings for each device
- API-v2 HMAC-SHA256 authentication for both Car and Gate
- Authenticated, progress-reporting BLE OTA for signed car firmware
- AES-256 Android Keystore-backed secure storage
- Optional biometric or device-credential app gate
- Shareable 24-hour diagnostic logs with BLE/GATT details
- Seven-day operation history and per-device optional latest-30 location pins
- AMOLED-black UI and Android adaptive launcher/splash assets

The car uses the `a1b2c3d4-...` API-v2 UUID family and `car-main` security
binding. The gate uses the distinct `b1b2c3d4-...` API-v2 family and
`gate-main`, preventing discovery from selecting the wrong ESP while all
devices are in range.
Nearby configured devices connect and authenticate when the app is open, making
card-button presses immediate. Ordinary connections close when the app leaves
the foreground. The Gate settings screen only changes the app's saved copy of
the PSK; the ESPHome PSK itself is changed by rebuilding the gate firmware.
Car settings can either update only the app's saved key, or securely update the
car ESP over BLE and save the phone copy only after the ESP confirms persistence.
Location recording is also configured independently in each device's settings,
so the car can record operation locations while the fixed gate does not.

Each device settings screen can generate a cryptographically random 32-character
PSK. A newly generated PSK is revealed with a Copy action only in the generation
dialog; after it is saved, the app masks it and does not provide a later reveal
or copy action. Store the copied value in a password manager before closing the
dialog, then configure the matching ESP with that same value.

After the one-time USB OTA bootstrap is installed on the car, open Car
Settings and choose **Update car firmware (.bin)**. Select PlatformIO's signed
`firmware.bin`; the app keeps the transfer serialized and reports progress.

## Build

Use JDK 17 and the included wrapper:

```powershell
$env:JAVA_HOME = 'C:\dev\jdk-17'
.\gradlew.bat assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

Release builds require the permanent signing key through environment variables:

```powershell
$env:CAR_KEY_KEYSTORE_PATH = 'C:\secure\car-key-release.jks'
$env:CAR_KEY_STORE_PASSWORD = '<store password>'
$env:CAR_KEY_KEY_ALIAS = 'car-key'
$env:CAR_KEY_KEY_PASSWORD = '<key password>'
.\gradlew.bat assembleRelease
```

Never commit the keystore or its passwords. Android updates must be signed with
the same permanent key.
