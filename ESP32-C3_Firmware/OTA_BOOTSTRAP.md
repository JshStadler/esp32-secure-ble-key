# Car BLE OTA bootstrap

## API-v2 migration order

The API-v2-only phone and watch releases cannot authenticate an older API-v1
Car firmware. Upgrade the Car before replacing the client apps:

- If its current identity advertises `ota1` and it already has the dual-OTA
  partition layout, use BLE Key 2.3.6 (or another v1-capable build) to install
  the signed API-v2 `firmware.bin` over BLE.
- If it still has the original single-app partition layout, perform the
  one-time USB migration below. That layout cannot update itself over BLE.

Confirm the Car reconnects after the firmware upgrade, then install BLE Key
2.4.0 and the API-v2 Car watch app. All later signed `firmware.bin` files can
be sent from the Android app over BLE.

## Before the USB flash

1. Do not erase flash when migrating an installed Car ESP. The four-file flash
   below does not write the NVS partition at `0x9000`, so the existing PSK is
   retained. The supplied firmware deliberately contains the non-working
   `CHANGE_ME_before_flashing_32chars!` fallback instead of embedding a real
   credential.
2. For a factory-fresh or previously erased ESP, set `DEFAULT_PSK` in
   `main/main.c` before compiling, or add a separate secure provisioning flow.
   Otherwise no client will know the placeholder key.
3. Keep `secure_boot_signing_key.pem` private. The same key is required for
   every future BLE-OTA image. Its Base64 representation is stored as the
   encrypted GitHub Actions secret `ESP_FIRMWARE_SIGNING_KEY_BASE64`; the
   decoded local key remains ignored by Git. Keep an additional encrypted
   offline backup.
4. Keep hardware Secure Boot disabled for this prototype. Signed updates are
   verified, but a USB recovery flash remains possible.

## One-time USB migration

From this directory run:

```powershell
platformio run --target upload
```

The full upload writes these required pieces together:

| Flash offset | Release file | Purpose |
|---:|---|---|
| `0x00000` | `car-api-v2-bootloader-0x0000.bin` | OTA-aware ESP-IDF bootloader containing the update verification configuration |
| `0x08000` | `car-api-v2-partitions-0x8000.bin` | Dual-slot partition table |
| `0x0f000` | `car-api-v2-otadata-0xf000.bin` | Initial OTA selection metadata |
| `0x20000` | `car-api-v2-firmware-0x20000.bin` | Signed API-v2 application in `ota_0` |

Do not flash only the application during this first migration. The new
bootloader, partition table, and OTA metadata are all required. Do not select
an erase-all option: the existing PSK is stored in the untouched NVS partition.

With `esptool` and the ESP in download mode, replace `COMx` and run:

```powershell
esptool --chip esp32c3 --port COMx --baud 460800 write_flash `
  --flash_mode dio --flash_freq 80m --flash_size keep `
  0x00000 car-api-v2-bootloader-0x0000.bin `
  0x08000 car-api-v2-partitions-0x8000.bin `
  0x0f000 car-api-v2-otadata-0xf000.bin `
  0x20000 car-api-v2-firmware-0x20000.bin
```

The release deliberately does not include a merged full-flash image. A merged
image fills the gaps between segments and can overwrite NVS, losing the PSK.

## Partition layout

The device requires at least 4 MiB of flash. Offsets and sizes come from
`partitions_ota.csv`:

| Partition | Type/subtype | Start | Size | End | Notes |
|---|---|---:|---:|---:|---|
| `nvs` | data/nvs | `0x09000` | `0x06000` (24 KiB) | `0x0efff` | PSK and BLE/NVS state; preserve during migration |
| `otadata` | data/ota | `0x0f000` | `0x02000` (8 KiB) | `0x10fff` | Active OTA slot metadata |
| `phy_init` | data/phy | `0x11000` | `0x01000` (4 KiB) | `0x11fff` | PHY calibration data |
| `ota_0` | app/ota_0 | `0x20000` | `0x1e0000` (1,920 KiB) | `0x1fffff` | Initial and alternating application slot |
| `ota_1` | app/ota_1 | `0x200000` | `0x1e0000` (1,920 KiB) | `0x3dffff` | Alternating BLE-OTA application slot |

## Later BLE updates

Build normally, then select `.pio/build/esp32c3/firmware.bin` from the device's
**Settings > Update ESP firmware (.bin)** action in BLE Key. The app authenticates the
manifest, transfers sequential chunks, and the ESP verifies SHA-256 plus the
embedded RSA signature before changing boot slots. A failed or interrupted
transfer leaves the currently running slot intact.

The release copy intended for subsequent BLE OTA is
`release-builds/BLE-Car-Key-APIv2-signed-ota.bin`. Do not use the bootloader,
partition-table, or OTA-metadata binaries in the mobile OTA picker.

Reinstalling the same signed application image is supported and is a useful
end-to-end OTA test. It is written to the inactive OTA slot, verified, selected
for boot, and marked valid by the application after restart. Keep stable power
and the phone close for the entire transfer.

Recent builds negotiate up to a 517-byte ATT MTU and request a 7.5-15 ms,
zero-latency connection while an OTA session is active. The Android client also
requests its high-throughput connection priority before sending `OTA:START` and
sizes chunks to the negotiated MTU. The first update from older firmware still
uses that firmware's 185-byte MTU, but benefits from the phone-side priority
request; later updates use both optimizations. Acknowledged writes remain in use
so a dropped or rejected chunk is detected rather than silently skipped.

If the signing key is lost, future BLE updates will be rejected. Because
hardware Secure Boot is not enabled, installing a new full USB bootstrap with
a new key remains the recovery path.
