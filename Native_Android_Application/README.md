# BLE Key — native Android app

This is the supported native Kotlin/Android BLE Key application. It controls
the separately identified Car and Gate devices without a Flutter runtime.

## Features

- Configurable device-card dashboard, initially populated with Car and Gate
- Add, rename, or remove Standalone and ESPHome device cards from app settings
- Foreground-persistent BLE connections with per-device cached-address retries and scan fallback
- Independent encrypted PSK and address settings for each device
- Authenticated live Open/Closed/Opening/Closing gate state while connected
- API-v2 HMAC-SHA256 authentication for both Car and Gate
- Authenticated, progress-reporting BLE OTA for signed standalone ESP firmware
- AES-256 Android Keystore-backed secure storage
- Optional biometric or device-credential app gate
- Shareable 24-hour diagnostic logs with BLE/GATT details
- All-device or per-device filtering for diagnostics, operations, locations, export, and clearing
- Seven-day operation history and per-device optional latest-30 location pins
- AMOLED-black UI and Android adaptive launcher/splash assets

The car uses the `a1b2c3d4-...` API-v2 UUID family and `car-main` security
binding. The gate uses the distinct `b1b2c3d4-...` API-v2 family and
`gate-main`, preventing discovery from selecting the wrong ESP while all
devices are in range.
Nearby configured devices connect and authenticate when the app is open, making
card-button presses immediate. Ordinary connections close when the app leaves
the foreground. Normal PSK changes require the existing PSK. Car changes
securely update the car ESP over BLE and save the phone copy only after the ESP
confirms persistence; ESPHome access-device changes update the app copy after
the YAML secret has been changed. A separately labelled, device-authenticated
recovery action can replace only the phone copy when the ESP was changed
elsewhere or the old value is lost.
Location recording is also configured independently in each device's settings,
so the car can record operation locations while the fixed gate does not.

Each device settings screen can generate a cryptographically random 32-character
PSK. A newly generated PSK is revealed with a Copy action only in the generation
dialog; after it is saved, the app masks it and does not provide a later reveal
or copy action. Store the copied value in a password manager before closing the
dialog, then configure the matching ESP with that same value.

When two cards use the same firmware type and service UUID, configure a fixed
BLE address for each. The app requires an address for the additional card and
pins the existing learned device as well, preventing nearby devices from being
mixed up during scanning.

The card name is only the label displayed in BLE Key and may be anything useful
to the user; it does not need to match the ESP's advertised Bluetooth name. A
BLE address such as `AA:BB:CC:DD:EE:FF` identifies one physical ESP and is used
to target it when multiple devices of the same firmware type are nearby.

After the one-time USB OTA bootstrap is installed on the standalone ESP, open
its settings and choose **Update ESP firmware (.bin)**. Select PlatformIO's signed
`firmware.bin`; the app keeps the transfer serialized and reports progress. It
requests Android's high-throughput BLE connection mode for the transfer, sizes
chunks to the negotiated MTU, and restores balanced connection priority when
the operation ends. Per-chunk and final-validation watchdogs report a genuinely
stalled transfer without imposing a short whole-image timeout. The BLE
connection is retained while Android's firmware document picker is open, and
an already-authenticated connection starts the selected update immediately.
Starting firmware selection closes Device Settings first, preventing its Save
action from rebuilding the BLE connection during OTA.

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
