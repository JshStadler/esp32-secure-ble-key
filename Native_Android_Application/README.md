# Remote Key — native Android app

This is the supported native Kotlin/Android Remote Key application. It controls
the separately identified Car and Gate devices without a Flutter runtime.

The release application ID and Kotlin namespace are `dev.logiclabs.remotekey`.
Debug builds use `dev.logiclabs.remotekey.test` so they can be installed alongside
the release app. Both display **Remote Key**.

This identity is a new installation relative to `dev.jshstadler.carkey` (and its
`.test` variant). Android does not migrate the old app's encrypted preferences,
Keystore entries, device configuration, or history. Keep the existing app until
you have reconfigured Remote Key with the device PSKs from your password manager
and verified access. Saved PSKs cannot be revealed in the old app.

Privacy and support: `info@6675162.xyz`. The app contains no ads. Read the bundled
privacy policy from App Settings or the authentication screen. App Settings also
provides a support email action and optional connection-notification permission
on Android 13 and later. BLE operation does not depend on notification permission.
The About section shows the installed app version and build number; its text can
be selected/copied for support, and test builds retain their `-test` suffix.

Read the [privacy policy](app/src/main/res/raw/privacy_policy.html) for details
about local storage, optional locations, exports, and deletion.

## Features

- First-launch device-type chooser with Standalone, ESPHome, or setup-later options; no pre-created Car/Gate cards
- Bluetooth availability banner with a system turn-on action, paused connection retries while off, and automatic reconnection when enabled
- Add, rename, or remove Standalone and ESPHome device cards from app settings
- Foreground-persistent BLE connections with per-device cached-address retries and scan fallback
- Continuous Connecting/Reconnecting card status across retry stages, with detailed stages retained in Diagnostics
- Cards and settings buttons that grow with Android font/display scaling, with stacked actions when space is limited
- Per-device home-screen press widgets on Android 12+, colour/status feedback and a reusable connection window that follows the app's background duration setting
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
Fresh installations start with no device cards. After app authentication, select
one or both firmware types, or choose **Set up later**. Selected cards use neutral
type labels; open their settings to set a name and the installed device's PSK.
An empty dashboard provides an **Add device** action. Existing saved device lists
and legacy credentials are retained on upgrade, and removing all cards does not
restart onboarding.

The dashboard distinguishes Bluetooth off, switching on/off, missing permission,
and unsupported BLE hardware. Press actions are disabled while Bluetooth is
unavailable. **Turn on Bluetooth** opens Android's enable prompt; denying it leaves
the off state visible. Turning Bluetooth back on reconnects configured devices
while the app is open without replaying interrupted commands. A key change that
was interrupted keeps its recovery journal; a dispatched press without a receipt
remains marked as unconfirmed.

Nearby configured devices connect and authenticate when the app is open, making
card-button presses immediate. Each device's **Connect automatically when the
app opens** switch defaults to on. Turning it off still permits an explicit
Press, Device health, Reconnect or Rescan to establish a connection.
**Reconnect** and **Rescan for this device** use saved settings; Rescan bypasses
the direct-address shortcut while preserving any explicitly configured target
address. Neither action is allowed during a pending press, key change, radio
write, firmware selection or firmware transfer, and neither sends a press.

App Settings provides **Background connections: Off / 30 seconds / 2 minutes**.
Existing installations default to two minutes. The deadline uses elapsed time,
including screen-off sleep. An already-started operation or open firmware picker
is allowed to finish; the original deadline is not extended after it finishes.
Off disconnects on leaving the app unless such an operation is active. Returning
to the app cancels the old lease. These are phone connection preferences, not
changes to the ESP advertising or sleep configuration.

Widgets use the same saved duration after each confirmed press. Another confirmed
widget press restarts that widget connection's deadline; Off disconnects immediately
after its result. Connecting is amber, sending is blue, confirmation is green and
failure/uncertainty is red. Confirmation lasts three seconds before the widget
returns to its device name and ready status (or idle when Off).

A button tapped while connecting stays pending after **Home** or **Recent apps**
is pressed. The background service retains the connection attempt and sends the
press once ready, within the original ten-second connection deadline. This also
works with background connections set to Off: the active operation, including its
receipt, may finish before disconnecting. Returning to the app does not resend it.
Cancel, Bluetooth off, closing/removing the app task, or activity/process teardown
revokes an unsent press; commands are never restored or replayed after restart.

**Copy support summary** includes app/build version, Android API, Bluetooth
state, connection preferences, and last collected health firmware/signal data
labelled with snapshot age. It does not connect or refresh health on its own.
Missing readings are labelled, and PSKs, names, BLE addresses, locations and logs
are excluded. Device health Refresh collects a new snapshot for the summary.

Normal PSK changes require the existing PSK. Car changes
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

New Car key replacements require 32–128 UTF-8 bytes, at least eight distinct
byte values, and no repeating pattern of 1–16 bytes. Use the generator rather
than a memorable password: validation cannot establish randomness. Firmware
enforces the same rule on BLE updates and fresh customized bootstrap keys.
Existing keys still work; setup, ESPHome key import, and app-only recovery
accept the installed device's original key without forcing a remote change.

When two cards use the same firmware type and service UUID, configure a fixed
BLE address for each. The app requires an address for the additional card and
pins the existing learned device as well, preventing nearby devices from being
mixed up during scanning.

The card name is only the label displayed in Remote Key and may be anything useful
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
$env:JAVA_HOME = 'C:\path\to\jdk-17'
.\gradlew.bat assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

Release builds require a signing keystore through environment variables. Use
your own key for a fork; the project's private release key is not distributed.

```powershell
$env:CAR_KEY_KEYSTORE_PATH = 'C:\secure\car-key-release.jks'
$env:CAR_KEY_STORE_PASSWORD = '<store password>'
$env:CAR_KEY_KEY_ALIAS = 'car-key'
$env:CAR_KEY_KEY_PASSWORD = '<key password>'
.\gradlew.bat assembleRelease
```

Never commit the keystore or its passwords. Android updates require compatible
signing certificates. See [signing and credentials](../SIGNING_KEYS.md).

To build an Android App Bundle using the configured signing key:

```powershell
.\gradlew.bat bundleRelease
```

The bundle is written to `app/build/outputs/bundle/release/app-release.aab`.
Release builds enable R8 code optimization and resource shrinking. The release
workflow produces APK, AAB, and `app/build/outputs/mapping/release/mapping.txt`
artifacts. Keep the mapping file for each released build to decode obfuscated
crash reports; the AAB also includes it for Google Play. Debug builds remain
unobfuscated.

### Standalone ESP radio settings (2.8.8)

Open **Device health → Radio settings**. With standalone firmware 2.8.8, select
transmit power from -12 to +9 dBm in 3 dB steps (default +3), alongside advertising
intervals. Save authenticates and persists the complete configuration, applies
power to advertising and active links, then explicitly reads health back.
Device health distinguishes the saved target from the controller's actual
advertising/connection settings. Earlier firmware retains interval controls.
Gate ESPHome transmit power continues to be set in its YAML configuration.

Phone RSSI requests are on demand. A timed-out or canceled controller request
is quarantined until its callback arrives or the GATT connection is discarded;
late callbacks cannot fulfill a newer measurement. Optional RSSI failure does
not prevent key commands or the ESP health snapshot.

### Connected links stay high (2.8.10)

Firmware 2.8.10 uses the high power target for default/non-advertising traffic and
every connected link at all times. The inactive target affects advertising only;
its timer is shared with the fast/slow advertising intervals. Choose equal targets
for fixed power. Existing settings are preserved on upgrade.

Boot, connection results, disconnects and authenticated activity restart the
recent advertising window. Passive scanning cannot trigger it, so inactive
advertising power determines initial discovery range. Health reads do not extend
the timer. OTA keeps advertising high until its transfer ends. Health distinguishes
the two saved targets from actual advertising and current-link power.

The `linkpower1` capability identifies this policy. The earlier 2.8.9 dual-power
firmware also lowered connected power; the app displays that older behavior and
requests a firmware update rather than claiming connected links remain high.
