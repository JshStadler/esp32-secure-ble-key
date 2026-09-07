# v2.8.0 — recoverable Car press acknowledgments

- Remove the Car's three-hour scheduled reboot. Keep the daily fallback,
  watchdog, BLE host heartbeat, advertising recovery and stale-session cleanup.
- Add authenticated Car press results retained in RAM for at most **30 seconds**.
  Android and Garmin Car reconnect and query the original request after a lost
  response, without sending another press. Results confirm a completed GPIO pulse.
- Acknowledgment clears the result, leaving only a duplicate-request ID until
  the original expiry. Reboot/expiry reports “Unable to confirm”; it never
  automatically repeats a remote toggle. Recovery ends after 25 seconds.
- Limit unsent queued presses to 10 seconds. Android offers Cancel and cancels
  unsent presses on backgrounding; press SELECT again to cancel a queued watch
  action. Already sent Car commands can continue confirmation recovery.
- Persist customized first-boot keys before OTA, and refuse OTA probation
  validation without a usable key. Retain encrypted old/candidate phone keys
  after an interrupted PSK change; Device Settings provides authenticated
  recovery without pressing the remote. PSK changes require Car firmware 2.8.0.
- Android uses filtered scanning with retry backoff and supports basic legacy
  commands at the default BLE MTU through the existing split-write path.

## Updating

1. Install the new Android APK. Existing API-v2 Car/Gate firmware remains usable.
2. Update the Car with the signed OTA application image in Device Settings.
   Existing OTA partitions and hardware wiring do not change. Preserve NVS.
3. Install the updated Garmin Car app for watch acknowledgment recovery.
   If an existing watch pairing does not expose the new characteristic,
   long-press MENU to unpair/reconnect once. A stale phone service cache may
   require disconnecting/reconnecting or cycling Bluetooth.
4. After about a minute, check Device health for firmware 2.8.0 and Validated.

The Garmin Gate package includes the queued-press deadline/cancel improvement.
Gate firmware and its existing press/status protocol are unchanged; the new
receipt cache and reconnect recovery are Car features. Device encryption and
per-client revocation remain outside this personal-project release.

If the current Car uses only a compiled bootstrap key and has never saved it
in NVS, persist a backed-up key with the existing app/firmware before installing
a generic release image. This fixes new provisioning going forward; an OTA
image cannot recover a key that existed only in the replaced application.

## Verification

Android unit tests and lint; ESP-IDF signed build; Garmin Car/Gate builds for
the supported watches; sanitizer-enabled host tests for cache lifetime,
duplicate/ACK handling, the actual GATT handler, interrupted responses, and
fresh provisioning. Physical phone/watch/ESP radio tests remain to be performed
on the installation. Keep a physical access method available for the first test.
