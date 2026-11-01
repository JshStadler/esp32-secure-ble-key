# Car and gate firmware 2.8.11

- Car: keep button busy and receipt completion bookkeeping on the BLE host task. The timer releases the GPIO, then queues completion before another pulse can begin. Also turn the debug LED off if the release timer cannot be armed.
- Gate: reject both Garmin split-command fragments once a session is closing, matching the full-command handler.

The BLE protocol, GATT handles, saved keys, standalone radio settings and OTA partition layout are unchanged. Existing Android 2.8.10 and Garmin 2.8.4 clients remain compatible. Connected standalone ESP links keep their configured high power; only advertising follows the recent/inactive power timer.

For an already provisioned car ESP, install only `BLE-Car-Key-v2.8.11-signed-ota.bin` through the existing Android app's firmware update action. No USB bootstrap or erase is needed. Device health should show firmware 2.8.11 after reconnecting and a validated OTA state after the startup health check.

The gate uses its ESPHome YAML and encrypted Wi-Fi OTA workflow. Its build identifier is `gate-ble-v2.8.11-session-close-guards`.

This is a firmware-only release. Android publication is held until the existing closed-testing review is approved. No watch app update is required.
