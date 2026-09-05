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

The Garmin workflow restores `GARMIN_DEVELOPER_KEY_BASE64` immediately before
building both watch apps and removes it in a `finally` block. It uses an
ephemeral Windows runner labeled `blekey-garmin-release` with the licensed
Connect IQ SDK and the five supported device definitions installed. Register
that trusted runner for each release; never run pull requests on it. The SDK
path comes from the user's Garmin `current-sdk.cfg`; Java 17 is installed at
`C:/dev/jdk-17`. Artifacts contain only signed PRG and IQ packages.

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
