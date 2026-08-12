# ESPHome Gate BLE API v2

This package adds a gate-specific Secure BLE Key API-v2 service to the
Centurion gate ESPHome node. The gate uses the `b1b2c3d4-...` UUID family while
the car retains `a1b2c3d4-...`, so clients cannot select the wrong ESP. Command
`0x02` maps to the existing ESPHome button with ID `button_1`.

API v2 keeps the same BLE packet sizes as v1, but authenticates this complete
transcript instead of authenticating only the nonce:

```text
BLEKEY-V2 || 0x00 || gate-main || 0x00 || command || nonce
```

The command and stable `gate-main` identity are therefore covered by the HMAC.
The Android BLE Key app is hybrid: Gate uses v2 while Car remains on v1 until
its ESP32-C3 firmware is upgraded. Garmin uses separate Car-v1 and Gate-v2 apps.

## Current limitations

- The BLE server permits five simultaneous clients, with independent challenge,
  status, and Garmin split-write state for each connection.
- PSK updates over BLE are not exposed. Change the key slots in the YAML and
  their secrets in `secrets.yaml`, then reflash when needed.
- BLE transmit power is set to the classic ESP32 maximum of +9 dBm for both
  advertising and connections. Enclosure and antenna placement still affect range.

## Easiest install: one YAML file

Use `centurion-d5-evo-ble-v2.yaml` as the complete ESPHome device
configuration. It contains the existing gate configuration and all BLE/HMAC
logic, so no companion header or package file is needed.

The first slot remains the generic `BLE Remote` and uses the existing secret:

```yaml
ble_psk: "replace-with-the-current-app-psk"
```

Up to five keys can be enabled in the `substitutions` block. An empty PSK
disables that slot. For example, to identify Joshua's phone and watch
separately, add secrets such as `ble_psk_joshua_phone` and
`ble_psk_joshua_watch`, then configure the slots like this:

```yaml
gate_ble_key_2_name: "Joshua Phone"
gate_ble_key_2_event: "joshua_phone"
gate_ble_key_2_psk: !secret ble_psk_joshua_phone
gate_ble_key_3_name: "Joshua Watch"
gate_ble_key_3_event: "joshua_watch"
gate_ble_key_3_psk: !secret ble_psk_joshua_watch
```

Enter the corresponding PSK in that phone app or Garmin build. Names are shown
in logs and the `Last BLE Remote` Home Assistant text sensor. Event IDs must
contain only lowercase letters, numbers, and underscores.

The production configuration preserves the installed controller identity
`centurion-d5-evo` and its original manual address `10.0.0.32`. The temporary
spare-board BLE indicator on GPIO2 has been removed, so the YAML is a drop-in
replacement for the existing gate controller wiring.

After boot, logs must show `gate-ble-v2.6.0-5key-pulse-decoder-production` and
`max BLE clients = 5`. The same build string is exposed as the diagnostic
`BLE Firmware Build` text sensor. If either still says one client, clean the
ESPHome build files before installing again.

Successful BLE operations trigger the Home Assistant event entity
`Gate BLE Remote`. Its event type identifies the configured key and client,
for example `joshua_phone_android_press` or `joshua_watch_garmin_press`.
This distinguishes BLE operations from presses initiated through Home Assistant.

Gate state is decoded from the controller LED with ESPHome's interrupt-backed
`pulse_meter`, while a polling view of the same GPIO resolves the final steady
Open/Closed state. Opening and Closing require consecutive samples, and the
more specific No Mains and Low Battery sequences are evaluated before the
broader motion/pillar ranges. Decoder thresholds are substitutions at the top
of the YAML so they can be tuned from real diagnostic pulse-rate logs.

## Legacy v1 rollback files

`secure_ble_key_v1.yaml` and `secure_ble_key_v1.h` remain only as a rollback
reference for the earlier compatibility prototype. Do not include them in the
API-v2 configuration.

Do not change the existing Wi-Fi or API `reboot_timeout` settings for this use
case. BLE and Wi-Fi can operate concurrently; if Wi-Fi is lost, ESPHome may
continue its normal recovery/reboot behaviour and BLE will be available between
reboots.

## Test sequence

1. Disconnect the gate motor from the relay output if possible, or otherwise
   put the gate in a state where an unexpected pulse is safe.
2. Compile and upload the combined configuration through normal ESPHome OTA.
   Use USB only if the current node is not OTA-capable or recovery is needed.
3. Confirm the ESP advertises gate service
   `b1b2c3d4-e5f6-7890-abcd-ef1234567890`.
4. Connect with BLE Key 2.3.6 or newer and verify it reaches `Authenticated`.
5. Press the app action once and confirm `relay_1` pulses for 300 ms.
6. Install the API-v2 Garmin Gate app and repeat the test using the watch.
7. Disconnect the Wi-Fi access point and confirm Android/watch BLE operation
   still works while the ESP attempts its normal Wi-Fi recovery.

The package does not alter the existing Home Assistant API, OTA, web server,
cover, status detection, or fallback access-point configuration.
