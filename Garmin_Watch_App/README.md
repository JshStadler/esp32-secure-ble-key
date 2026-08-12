# BLE Car Key

The Car watch app uses Secure BLE Key API v2 with the `car-main` security
binding and can be installed alongside the separate Gate app.

Discovery primarily matches the Car-specific `a1b2c3d4-...` API-v2 service
UUID. The advertised name `BLE-Device` remains a fallback because Garmin may
not expose a device name in every scan result. The screen shows concise states
such as `Scanning`, `Connecting`, `Connected`, `Pressed`, and `Auth failed`;
detailed BLE diagnostics remain in the debug log.

Configure its PSK through Garmin Connect or the Connect IQ Store app: open the
watch, select BLE Car Key, open Settings, and enter the same PSK installed on
the Car ESP. The setting uses Garmin's masked `password` control and is required.
The watch app displays `Set PSK in Connect IQ` instead of scanning until a key
has been configured. Save/sync the setting; a running app applies the change
immediately, and a newly opened app reads the saved value at startup.
