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

### Publication status and foreground-service demo

Version 2.8.6 (32) was published to internal testing on 22 October 2026. The
closed Alpha release is prepared with the same 11-entry Internal Testers list,
but remains a draft: Play requires a demo video for the connected-device
foreground-service declaration before the release can be saved and submitted.
The appropriate declaration is continuous data transfer to an external device;
Google's automotive-key use case is specific to automotive manufacturers.

Prepare a short recording using a real configured test ESP:

1. Open Remote Key, show About / version 2.8.6, and select a 30-second background
   connection duration in App Settings. Configure the device and key off-camera.
2. Show the in-app connection reaching Ready (Reconnect can demonstrate the
   connection flow), then use the key button and show the successful result.
   Include the external device's response if possible, using another camera.
3. Go Home, open the notification shade and show the Remote Key connected
   notification and its 30-second background window.
4. Stay outside the app until the notification disappears after the window,
   then return and show reconnection. Do not swipe the app away during the demo.

Keep keys, credential QR codes, private notifications and identifying location
details out of the video. Supply an accessible link, such as an unlisted YouTube
video, for the Play form. No fixed duration is prescribed here; around one to
two minutes should cover these steps. The release still needs Google review
after the declaration is completed. Leave testers on internal until closed is
available. Production access additionally requires at least 12 closed testers
opted in continuously for 14 days; the current list has 11 entries.

References:
- https://support.google.com/googleplay/android-developer/answer/13392821
- https://support.google.com/googleplay/android-developer/answer/9845334
- https://support.google.com/googleplay/android-developer/answer/14151465

## Google Play notes

Choose how long Bluetooth connections stay ready after leaving the app. Add
per-device automatic connections, Reconnect and Rescan controls, and a copyable
support summary with versions and recent signal readings, excluding credentials.
