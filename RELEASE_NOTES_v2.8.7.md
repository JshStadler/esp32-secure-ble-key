# Remote Key Android v2.8.7 / ESPHome gate signal diagnostic

Android version code: **33**. Minimum Android: **7.0 / API 24**.

- Gate Device health can show both directions: received at the phone
  (gate ESP → phone) and received at the gate ESP (phone → gate ESP).
- The reverse reading requires the updated ESPHome gate YAML and its local
  `components/gate_ble_signal/` folder. Build with the installed node's existing
  secrets and use ESPHome OTA. Never install a validation binary built with
  dummy credentials.
- Reading is on demand, scoped to the authenticated connection, bounded, and
  correlated to a new random request ID. No continuous polling or extra scans.
- Older gate firmware still shows phone-side RSSI. A failed optional reverse
  diagnostic shows unavailable rather than an old reading. The support summary
  includes the newly collected gate RSSI in its existing age-labelled snapshot.
- Car firmware stays **2.8.4**; Garmin stays **2.8.4**. Transmit power is unchanged:
  car firmware requests +3 dBm; gate firmware requests +9 dBm. These are code
  settings, not verified RF measurements on installed hardware.

## Physical tests remaining

- Upgrade Android without losing settings/keys; old gate firmware must continue
  to connect, press, show live state, and display phone-side RSSI.
- Install the new gate build with existing credentials. Confirm build
  `gate-ble-v2.8.7-on-demand-signal-production` in ESPHome and refresh both RSSI
  readings near and far. Opening health must not pulse the relay.
- Keep the phone and watch connected together; verify each diagnostic belongs
  to the requesting phone and ordinary presses/live state remain responsive.
- Disconnect during a diagnostic and reconnect; reject old results and show
  unavailable if the new request cannot complete.
- Check that canceling health/backgrounding does not restart diagnostic reads.
- Compare the car at the same measured positions/orientation with several
  samples before deciding whether to test +6 or +9 dBm. A higher ESP transmit
  setting improves only ESP → phone/watch; installation/antenna changes can
  improve both directions. RF output power ratios are not whole-board current
  ratios, and actual battery impact requires measurement.
