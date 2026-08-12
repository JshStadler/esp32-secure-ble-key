# Production signing keys

Production private keys are deliberately excluded from Git. GitHub Actions
stores Base64 copies as encrypted repository secrets so release builds do not
depend on a particular development computer.

## GitHub Actions secrets

- `CAR_KEY_KEYSTORE_BASE64`
- `CAR_KEY_STORE_PASSWORD`
- `CAR_KEY_KEY_ALIAS`
- `CAR_KEY_KEY_PASSWORD`
- `GARMIN_DEVELOPER_KEY_BASE64`
- `ESP_FIRMWARE_SIGNING_KEY_BASE64`

These six entries are configured as encrypted repository secrets in
`JshStadler/esp32-secure-ble-key`. Secret values are never committed and GitHub
does not allow them to be read back after creation.

The Android workflow restores its keystore only on the ephemeral runner. The
Car firmware workflow does the same for the ESP signing key. Both workflows can
be started manually; version tags also create signed builds.

The Garmin key is stored for continuity. Local Garmin releases currently use
`garmin_developer_key.der`; every Connect IQ update must continue using that
same key. A future Garmin CI workflow should restore
`GARMIN_DEVELOPER_KEY_BASE64` immediately before invoking `monkeyc -y`.

GitHub secrets cannot be read back after creation. Keep an additional encrypted
offline backup of every private key and its passwords. Never add decoded keys,
keystores, or passwords to the repository or workflow artifacts.

## Device PSKs

Device authentication PSKs are runtime credentials, not build-signing keys.
They are not required by CI and must not be committed or stored as GitHub
Actions secrets. Generate a unique PSK for every device/user slot with
the mobile app's one-time PSK generator or `./generate-device-psk.ps1`, save
its master copy in a password manager, and provision it only to the
corresponding ESP and clients. The mobile app displays and offers to copy a
generated PSK only at creation time; saved PSKs remain masked and cannot be
revealed later. ESPHome values belong in the ignored `secrets.yaml` file.
