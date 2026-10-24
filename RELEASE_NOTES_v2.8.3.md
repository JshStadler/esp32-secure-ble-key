# Remote Key Android v2.8.3

Android version code: **29**. This is an Android-only update compatible with the
currently supported Car and ESPHome firmware and Garmin apps.

Minimum Android version: **Android 7.0 (API 24)**, required by the app's enabled
Google Play automatic protection. Android 6 devices cannot install this update.

- Show when Bluetooth is off, changing state, unavailable, or missing permission.
  Offer Android's Bluetooth enable prompt and pause connection retries while off.
- Reconnect configured devices when Bluetooth returns, without replaying an
  interrupted press. Preserve uncertain outcomes and interrupted key-change
  recovery information.
- Ask new users which device types to configure, with no preselected Car/Gate
  cards. Offer setup later and a direct Add device action on an empty dashboard.
  Existing device lists, names, addresses, and keys are retained on upgrade.
- Reject weak new replacement keys and keep generated keys within the policy.
  Existing installed keys can still be imported and used.

The established BLE connection, short press exchange, cached-address fallback,
and advertising controls remain available. This release does not change ESP
advertising defaults, connection intervals, BLE sleep, or the authentication
result wire format. Those changes require separate firmware and hardware tests.

Validation: Android unit tests, lint, and signed release APK/AAB build. Physical
phone/watch/ESP testing is still required; no ESP firmware is flashed by this
release.

## Google Play release notes

Bluetooth-off status and a turn-on shortcut are now shown clearly. New users can
choose their device types or set up later, while existing device settings are
preserved. Connection interruptions are handled more clearly, and new replacement
keys receive stronger validation.
