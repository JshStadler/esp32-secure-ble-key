# BLE Gate Key

This is a standalone Garmin app with its own application ID, so it can be
installed alongside BLE Car Key.

The app accepts the previously logged test address `A0:B7:65:4A:15:EE`, the
advertised name `centurion-d5-evo`, or the gate-specific `b1b2c3d4-...` service
UUID family. It cannot select the car ESP.

## Watch status

- The screen shows concise states such as `Scanning`, `Connecting`,
  `Connected`, `Pressed`, and `Auth failed`.
- Detailed address, name, RSSI, and GATT diagnostics remain in the debug log
  and are not drawn on the round watch screen.

Configure the app PSK to the assigned ESPHome key slot before authenticated
button presses. In Garmin Connect or the Connect IQ Store app, open the watch,
select the BLE Gate Key app, open Settings, and enter the PSK in the masked,
required field. The app displays `Set PSK in Connect IQ` until configured.
Save/sync the setting; a running app applies the change immediately, and a
newly opened app reads the saved value at startup.
