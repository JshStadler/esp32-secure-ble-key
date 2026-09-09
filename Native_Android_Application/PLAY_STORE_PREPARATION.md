# Remote Key: Google Play preparation

Checked against the project and Google's documentation on 9 September 2026.
These are preparation tasks, not confirmation that Play Console setup is complete.

## Build and signing

- Release identity: `dev.logiclabs.remotekey`; launcher name: **Remote Key**.
  Debug builds use `dev.logiclabs.remotekey.test` and must not be uploaded as the
  production app. Existing installations under the old ID do not migrate;
  see the [native app README](README.md).
- The project already targets API 36, meeting the new-app requirement effective
  31 August 2026. Recheck the
  [target API policy](https://support.google.com/googleplay/android-developer/answer/11926878?hl=en)
  at submission time.
- Configure Play App Signing and confirm the upload certificate registered for
  the Console app. Use the matching upload keystore with the existing
  `CAR_KEY_*` signing environment variables. Keep encrypted offline backups.
  If GitHub-distributed APKs and Play installs should update one another, plan
  for the same application ID and compatible app signing certificates; the
  upload certificate alone does not provide this. See
  [Android app signing](https://developer.android.com/studio/publish/app-signing).
- Build a signed release bundle with `./gradlew bundleRelease` (Windows:
  `.\gradlew.bat bundleRelease`). Upload
  `app/build/outputs/bundle/release/app-release.aab`. Google Play requires an
  [Android App Bundle for new apps](https://developer.android.com/studio/publish/).
  The current GitHub release workflow produces only an APK; add `bundleRelease`
  and the AAB artifact path there if you want automated Play upload artifacts.
- The current version is `2.8.1` / version code `25`. Check previously uploaded
  bundles in this Console app and increase `versionCode` when required; each
  subsequent release needs a new, increasing code. Verify the final bundle's
  package, version, signing, and supported devices before rollout.

## Privacy, permissions, and review access

- Publish a public privacy policy and add a link or policy text within the app
  as well as its Play listing. No in-app privacy policy entry currently exists.
  Describe device names/addresses, PSKs, local diagnostic and operation logs,
  optional location pins, retention/deletion, user-initiated exports and map
  intents, and a privacy contact. All apps need a policy, including apps that
  do not collect data. See Google's
  [User Data policy](https://support.google.com/googleplay/android-developer/answer/10144311).
- Complete Data safety using the actual release behavior and its dependencies.
  The current manifest has no Internet permission, and the app uses local
  storage, BLE, optional location recording, and explicit share/map intents.
  Do not infer the form answers solely from Android permissions: Google's
  collection definition concerns off-device transmission. Review BLE transfers,
  exports, and user-initiated sharing exceptions before submitting. See
  [Data safety guidance](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en-GB).
- Review Bluetooth and location explanations and denied-permission behavior.
  Location recording is optional per device; the app does not request background
  location. Explain location handling before requesting permission where a
  prominent disclosure is required. The privacy policy must match the UI.
- Complete the `connectedDevice` foreground-service declaration. The app retains
  BLE connections for a short background grace period and during firmware OTA.
  Describe those uses, the impact of interruption, and provide a video showing
  how the user starts each feature and its notification. See
  [foreground-service requirements](https://support.google.com/googleplay/android-developer/answer/13392821?hl=en).
- Complete App access with precise ESP hardware, firmware, PSK setup, and
  device-authentication instructions. Reviewers need access to the functionality.
  Recommended preparation: record an accessible walkthrough with a test device
  and consider a clearly labelled demo mode if review without hardware is needed.
  A video alone does not guarantee review access or approval. Never provide
  personal production device PSKs. See
  [review preparation](https://support.google.com/googleplay/android-developer/answer/9859455?hl=en).

## Console and listing

- Finish outstanding identity/contact and Android developer verification tasks
  shown in Console. New personal accounts also need real-device verification
  through the Play Console mobile app; see
  [device verification](https://support.google.com/googleplay/android-developer/answer/14316361?hl=en).
- Complete the main store listing: descriptions, category, support email,
  privacy policy URL, a 512 x 512 store icon, 1024 x 500 feature graphic, and at
  least two app screenshots. Make the compatible ESP hardware requirement clear;
  the app is not a universal car-key replacement. See
  [preview asset requirements](https://support.google.com/googleplay/android-developer/answer/9866151?hl=en).
- Complete all applicable App content tasks: ads declaration, target audience,
  content rating, Data safety, App access, and any additional declarations shown
  by Console. Choose distribution countries and free/paid availability.

## Testing and production access

- Start with an internal test using the signed release AAB. Test actual Car and
  Gate hardware, initial PSK configuration, authentication, BLE reconnects,
  denied Bluetooth/location permissions, background timeout/notification, log
  export, optional location recording, and signed firmware OTA. Review Play's
  pre-launch report; automated devices cannot validate the physical ESP actions.
- If the personal developer account was created after 13 November 2023, run a
  closed test with at least 12 testers opted in continuously for at least 14 days,
  then apply for production access. Internal testing does not replace this.
  Keep feedback and evidence of meaningful testing; reaching the time/count
  threshold does not itself grant production access. See
  [personal-account testing requirements](https://support.google.com/googleplay/android-developer/answer/14151465).
- Resolve release issues, complete the Console dashboard, and submit the tested
  release for review after production access is approved where required.
