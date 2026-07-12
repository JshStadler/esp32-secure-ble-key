# Car Key — native Android rewrite

This is the supported native Kotlin/Android BLE Car Key application. It replaces
the legacy `Android_Flutter_Application` and has no Flutter runtime.

## Features

- Native Android BLE connection with cached-address retries and scan fallback
- HMAC-SHA256 challenge-response authentication and PSK updates
- AES-256 Android Keystore-backed secure storage
- Optional biometric or device-credential app gate
- Shareable 24-hour diagnostic logs with BLE/GATT details
- Seven-day operation history and optional latest-30 location pins
- AMOLED-black UI and Android adaptive launcher/splash assets

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

The release APK is written to `app/build/outputs/apk/release/app-release.apk`.
Never commit the keystore or its passwords. Back up both securely; Android app
updates must be signed by the same key. Tagged builds use the equivalent
encrypted GitHub Actions secrets.

The app stores the PSK with an AES-256 key held in Android Keystore. It performs the same HMAC-SHA256 challenge-response protocol as the Flutter app and requests device credential/biometric authentication for the app gate and PSK settings.
