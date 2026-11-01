# Remote Key Android 2.8.17 (build 43)

Widget results now clear after three seconds for success, failure and cancellation.
Normal widgets are gray while disconnected and blue while the app or widget still
holds a BLE connection. The connection duration and tap-again cancellation rules
are unchanged. Transient results cannot overwrite a newer pending action.

Opening Device Settings checks public GitHub firmware releases in the background.
The check uses a five-minute in-memory cache; Check again forces a fresh request.
There is no scheduled update polling. New INTERNET access is used only for the
public release metadata and explicitly selected firmware downloads; no device
names, keys, Bluetooth addresses, logs or locations are sent to GitHub.

Standalone ESP32-C3 updates use Download and update, followed by Install. Images
are bounded by the OTA partition size and checked against the GitHub SHA-256
digest and ESP32-C3 header. The existing BLE updater and ESP signature validation
remain in charge of transfer/installation. Known same/newer versions and pending
startup validation do not offer an upgrade. The local .bin picker remains available.

ESPHome updates link to the published config source and are installed through
ESPHome. Gate config 2.8.12 adds version/build reporting over the existing BLE
identity; that config must be installed before Android can identify the running
gate revision. No standalone ESP or Garmin update is needed for the app changes.

Manual checks: confirm both success and out-of-range failure clear after three
seconds; gray/blue must follow the actual connection and background timeout.
Open settings online/offline, inspect version comparison, cancel a download or
Install confirmation, and confirm nothing is sent to the ESP before Install.
Then test a real signed BLE OTA and confirm the version after reconnecting.
Gate revision comparison requires the 2.8.12 ESPHome config to be installed.
