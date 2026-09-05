# v2.6.0 — BLE recovery and secure key updates

Phone and watch connections now recover from missing Bluetooth callbacks,
stalled setup, failed writes, and stale connection state without restarting
the app. An unconfirmed press is never automatically repeated. Both Garmin
apps share the same recovery logic and authenticate before showing ready.

The phone serializes GATT operations, discards callbacks from old sessions,
and falls back to scanning after repeated cached-address failures. Diagnostic
exports include connection stage, session number, callback errors and timeouts.
Phone unlock now fails closed when device authentication is unavailable.

Car firmware adds encrypted, authenticated PSK updates with authenticated
storage receipts, fixes loading 127/128-byte saved keys, and disables the public
placeholder key. Storage errors preserve credentials and disable access rather
than erasing NVS or falling back to a known key. Per-client status and BLE
maintenance on the NimBLE host task prevent cross-session interference.
Car and ESPHome Gate now evict stalled unauthenticated clients and repeated
authentication failures so they cannot occupy all connection slots indefinitely.

## Install

1. Install the signed Android APK over the existing app.
2. Use its firmware update screen to install the signed Car OTA binary. Keep
   the current PSK; OTA preserves NVS. Do not erase flash. The supplied image
   requires an already provisioned key. Fresh devices need private provisioning
   as described in the firmware build instructions.
3. Install the matching Car/Gate PRG for your watch, or use the IQ package for
   Connect IQ distribution. Keep the existing app PSK settings.
4. Apply the updated Gate YAML in ESPHome and compile/upload using your existing
   secrets and hardware settings. The release includes source, because Wi-Fi,
   API, OTA and BLE credentials are specific to your installation.

Ordinary API-v2 press/authentication remains compatible across versions. Secure
PSK changes require both the new phone app and Car firmware. After a PSK change,
update watch settings to match. Keep the new key until the update is confirmed;
if the acknowledgement is lost, the car may already be using it.

Builds and automated tests cannot reproduce the intermittent radio issue on
your hardware. If it recurs, export the phone log before restarting the app.
