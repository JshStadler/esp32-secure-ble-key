# Remote Key Android 2.8.11 (build 37)

Firmware file selection now stops reading once a file exceeds the supported OTA image size. Oversized or endless input is rejected without loading the whole file into memory, preventing a possible app crash when the wrong file is selected.

This update is compatible with the current car and gate firmware and Garmin apps. It does not require another ESP firmware update. Car and gate firmware 2.8.11 were released separately.

Validation covers 95 Android unit tests, including maximum-size, oversized, short, empty and zero-length reads, plus lint and optimized signed APK/AAB builds.
