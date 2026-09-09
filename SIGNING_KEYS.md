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

The Garmin workflow runs on GitHub-hosted Ubuntu. Compile both IQ packages
locally with Connect IQ SDK 9.1.0 and the installed device definitions, using
the existing developer key. Archive them as `garmin-build-inputs.zip`, upload
to a draft release, and dispatch the workflow with its release name and the
reviewed archive SHA256. Garmin requires account access to download device
definitions, so compilation is local; final signing happens in GitHub.

The workflow verifies the input package signatures against the GitHub secret,
removes and regenerates every PRG signature with Garmin's SDK, and regenerates
both manifest signatures. It requires identical program bytes after signing
to preserve the compiler's manifest hashes and checks the final IQ packages.
The decoded key is removed on exit. Artifacts contain only signed PRG and IQ
packages. Remove the compiler-input asset before publishing the release.

## Android and Google Play

The Android workflow builds both a signed APK and an Android App Bundle (AAB)
using the existing `CAR_KEY_*` keystore secrets. For compatible updates between
GitHub APKs and Play installations, provide this existing app signing key through
Play Console's encrypted enrollment procedure. A Google-generated app signing
private key cannot be downloaded into GitHub.

Play can initially accept uploads signed with this same key. If you register a
separate upload key later, configure AAB signing separately from the key used for
GitHub APKs; replacing the APK signing key would break their update continuity.
See [the signing and Console preparation guide](Native_Android_Application/PLAY_CONSOLE_SUBMISSION.md).

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
