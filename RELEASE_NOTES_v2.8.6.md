# Remote Key Android v2.8.6

Android version code: **32**. Minimum Android: **7.0 / API 24**.

- App Settings now offers background connection durations: Off, 30 seconds and
  2 minutes. Existing installations retain the two-minute default. A dispatched
  operation or open firmware picker is allowed to finish even with Off selected.
- Device Settings adds an automatic foreground connection switch (on by
  default), Reconnect and Rescan actions. Explicit Press and Device health
  requests still connect when automatic connection is disabled. Manual recovery
  never replays an operation and cannot interrupt a mutating operation.
- Copy support summary includes app/build, Android API, Bluetooth status,
  connection settings and last firmware/RSSI snapshots with age labels. No PSKs,
  user device names, BLE addresses, locations or logs are included. Copying does
  not start connections or background polling.

Android-only update. Car firmware and Garmin apps remain at 2.8.4. No ESP
firmware update is required for these settings.

## Physical tests remaining

- Upgrade from 2.8.5: settings/keys preserved; automatic connections still on
  and background duration still 2 minutes unless explicitly changed.
- Select Off, 30 seconds and 2 minutes; leave the app, including screen-off, and
  check disconnect timing, notification wording and reconnect on return.
- Background during a press, PSK change, firmware picker and OTA; confirm no
  interruption by the preference deadline and no automatic replay of a press.
- Disable automatic connection for one device, reopen/toggle Bluetooth, then
  explicitly connect using Press, Device health, Reconnect and Rescan.
- Rescan with two devices of the same firmware type: retain explicit addresses.
- Copy support summary before/after health Refresh, while disconnected and with
  Bluetooth off; verify unavailable/stale readings and absence of private fields.

## Closed testing transition

Reuse the existing **Internal Testers** email list for the closed Alpha track.
Testers keep the installed Play app and its settings. To receive the closed
track, they must opt out of internal testing and opt into closed testing using
the same eligible Google account. Do not uninstall or clear app storage.
The closed release may require Google review before its opt-in link is active.

## Google Play notes

Choose how long Bluetooth connections stay ready after leaving the app. Add
per-device automatic connections, Reconnect and Rescan controls, and a copyable
support summary with versions and recent signal readings, excluding credentials.
