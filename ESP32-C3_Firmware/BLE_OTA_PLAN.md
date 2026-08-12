# Car BLE OTA migration plan

BLE OTA is compatible with the car's BLE-only, low-power design. ESP-IDF's OTA
write API is transport-independent: authenticated firmware chunks received over
NimBLE can be written to the inactive application slot with `esp_ota_begin()`,
`esp_ota_write()`, `esp_ota_end()`, and `esp_ota_set_boot_partition()`.

The currently installed car build cannot OTA yet because it uses a single-app
partition table. The first migration therefore requires one final USB flash
that installs an OTA data partition and two app slots. All later releases can
then be transferred by the Android app over BLE.

Implemented safeguards:

- Enter update mode only after normal car API-v2 authentication plus a separate
  domain-separated `BLEKEY-OTA1` HMAC over size, digest, and the current nonce.
- Accept only an RSA-signed firmware image; the BLE link and PSK do not establish
  firmware authorship by themselves.
- Bind the image size and SHA-256 digest to authentication, require sequential
  chunk offsets, and support finalise/abort operations.
- Keep the current app running while the inactive slot is written, then use
  bootloader rollback and a quick boot self-test before marking the new app valid.
- Report update state/errors to the initiating phone, and expose the `car-main`
  API-v2 identity used by the current phone and Garmin apps.
- Do not add Wi-Fi or ESPHome to the car image; the phone is the BLE transport.

Official references:

- https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/system/ota.html
- https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/kconfig-reference.html
