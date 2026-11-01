# Remote Key v2.8.4 testing release

Android version code: **30**. Minimum Android: **7.0 / API 24**.
Car firmware app version: **2.8.4**. Existing partitions and signing identity
are retained for BLE OTA. Existing installed keys continue to authenticate.

- Car firmware now rejects weak new PSK2 replacements and weak fresh bootstrap
  keys: 32–128 non-NUL bytes, at least eight distinct byte values, no repeating
  pattern of 1–16 bytes. This rejects obvious weaknesses, not every guessable
  passphrase. Use generated random keys. Existing keys are not invalidated.
- Car and Android negotiate compact `auth2` authentication. At a sufficient
  MTU, Android sends one request write and receives a 19-byte verified proof on
  the existing status notification. Full request HMAC, independent random client
  ID, device proof, nonce consumption and failure limits remain in force.
  Older apps/firmware keep their original authentication path. No press is
  automatically repeated when an outcome is uncertain.
- Device health shows BLE RSSI measured at the phone and, with this Car
  firmware, at the ESP for the current connection. Refresh requests one new
  snapshot; it does not continuously poll. ESPHome cards can show phone-side
  RSSI; their existing firmware does not report the ESP-side reading.
- Both Garmin apps fix reuse of an existing live connection and log scan,
  connect and authentication durations. Car supports the compact result at
  default MTU using fragmented requests; Gate retains its established protocol.

## Installation and compatibility

1. Update Android first. It works with the previous Car firmware.
2. In the Car device settings, choose **Update ESP firmware (.bin)** and select
   `BLE-Car-Key-v2.8.4-signed-ota.bin`. This is the application-only signed OTA
   image; bootloader, partitions and NVS are not flashed.
3. Reconnect after the ESP restarts. Wait at least one minute, then refresh
   device health and confirm firmware **2.8.4**, OTA **Validated**, and RSSI.
4. Install the matching Garmin PRG for the watch model through Garmin USB
   sideloading, or use the IQ package for a separate Connect IQ Store submission.

This does not update the ESPHome gate controller. No firmware has been flashed
automatically. Radio intervals, TX power and BLE sleep defaults are unchanged.

## Hardware checks remaining

- Old/new Android and watch clients against old/new Car firmware; verify the
  configured PSK survives OTA, reboot and normal disconnect/reconnect.
- Cold connect, retained connection, out-of-range return, Bluetooth off/on,
  foreground/background transitions, and simultaneous phone/watch connections.
- Verify authentication and health never pulse the output. Test an ordinary
  press once and confirm an interrupted/uncertain press is not replayed.
- Compare both RSSI readings at several distances/antenna positions, refresh,
  close/reopen health, and confirm unavailable readings are labelled honestly.
- On a spare board, weak-key rejection, a strong key change, interrupted update
  recovery and power-loss persistence. Do not experiment with unknown keys on
  the only installed controller.
- Measure idle/connected/active current and watch connection timings before
  further advertising/connection-interval, TX-power or sleep changes.

## Google Play notes

Device health now shows Bluetooth signal strength at the phone and, with the
new Car firmware, at the ESP. Compatible Car firmware uses a shorter verified
authentication exchange. Existing devices remain compatible.
