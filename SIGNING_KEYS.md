# Signing and credentials

Release signing keys identify trusted application and firmware builds. Device
pre-shared keys (PSKs) authenticate access to individual hardware. They serve
different purposes and must not be committed to the repository.

## Building signed releases

Forks need their own signing identities. The upstream project's private keys
are not distributed. Keep encrypted offline backups of any keys you generate.

The release workflows accept these encrypted repository secrets:

| Secret | Purpose |
| --- | --- |
| `CAR_KEY_KEYSTORE_BASE64` | Base64-encoded Android release keystore |
| `CAR_KEY_STORE_PASSWORD` | Android keystore password |
| `CAR_KEY_KEY_ALIAS` | Android signing-key alias |
| `CAR_KEY_KEY_PASSWORD` | Android signing-key password |
| `GARMIN_DEVELOPER_KEY_BASE64` | Base64-encoded Garmin developer key |
| `ESP_FIRMWARE_SIGNING_KEY_BASE64` | Base64-encoded ESP firmware signing key |

The Android workflow produces APK and AAB artifacts. Local Android builds use
the environment variables documented in the
[Android README](Native_Android_Application/README.md).

Release workflows restore private keys only for signing and remove restored key
files afterward. Artifacts must contain signed binaries, never private keys or
passwords. GitHub secrets cannot be read back; keep a separate secure backup.

## Update compatibility

Android updates require the same application ID and compatible signing
certificates. Upload certificates and certificates used to sign installed APKs
can differ; plan signing compatibility across distribution channels.

ESP OTA images must be signed with a key trusted by the installed firmware.
Changing that identity can require reprovisioning the hardware; see
[OTA bootstrap and recovery](ESP32-C3_Firmware/OTA_BOOTSTRAP.md).

## Device PSKs

Generate a unique PSK for each device or client slot using the app's generator
or [generate-device-psk.ps1](generate-device-psk.ps1). Save its master copy in a
password manager and provision it only to the corresponding device and clients.
Generated keys are displayed only at creation; saved app keys remain masked.

Device PSKs are runtime credentials, not CI build inputs. ESPHome values belong
in an ignored `secrets.yaml`. Never include actual device keys in source code,
issues, logs, screenshots, or published build artifacts.
