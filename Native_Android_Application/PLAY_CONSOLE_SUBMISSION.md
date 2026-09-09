# Remote Key submission pack

Prepared 9 September 2026. Copy the relevant text into Play Console after testing
the release. This file does not submit declarations, publish the policy, or
change distribution settings.

## Signing: choose the identity before the first Play release

Google's app signing key signs the APKs installed from Play. Your upload key
signs the AAB you send to Play. A Google-generated private signing key cannot be
downloaded into GitHub; the downloadable certificate is public and cannot sign
builds. See [Android signing](https://developer.android.com/studio/publish/app-signing).

The repository already has `CAR_KEY_KEYSTORE_BASE64`, `CAR_KEY_STORE_PASSWORD`,
`CAR_KEY_KEY_ALIAS`, and `CAR_KEY_KEY_PASSWORD` secrets. The workflow uses that
keystore for both the APK and the AAB. Do not replace those secrets just because
you are enrolling in Play.

Recommended for continued GitHub APK distribution with compatible updates:

1. In the new app's Play App Signing setup, choose to supply an existing app
   signing key instead of asking Google to generate one.
2. Follow Console's current encrypted key-export procedure (PEPK) using the
   existing release keystore and the tool/encryption material supplied by Google.
   This is a private transfer to Google; never commit the exported private key.
3. Verify that Play's app signing certificate SHA-256 matches the existing
   release signing certificate. The package ID must also match for updates.
4. The existing key can initially sign the uploaded AAB too. A separate upload
   key is recommended for isolation; when you register one, split APK signing
   from AAB signing in CI instead of replacing the key used for GitHub APKs.
5. Keep an encrypted offline backup of your existing keystore and passwords.

Alternative: let Google generate the app signing key and register the existing
CI key as the upload key. This is simpler for Play-only distribution, but locally
signed GitHub APKs then have a different signing certificate and cannot normally
update a Play installation (or vice versa). Use Play-generated signed APKs for
compatible downloads in that arrangement.

If signing is already enrolled, inspect both certificates in App signing before
changing anything. Do not assume an upload-certificate download is a private key.

After merging, run the **Android** workflow on `main` with **Run workflow**.
Download its `Remote-Key-*` artifact and upload `app-release.aab` to Internal
testing. The workflow also retains `app-release.apk`. These files contain no
private signing key. The current code is version code 25: increase it before an
upload if that code was already used in this Play app.

## Public privacy policy on GitHub Pages

The source is `app/src/main/res/raw/privacy_policy.html`. It is bundled for
offline reading from Settings and the authentication screen. The Pages builder
wraps that exact text in a responsive page; edit this one source for future
policy changes.

After this PR and the rename PR have reached `main`:

1. Open repository **Settings > Pages** and choose **GitHub Actions** as the
   build/deployment source. No Pages site was returned by the API during preparation.
2. Run **Publish Remote Key privacy policy** on `main` from Actions. It is a
   manual workflow and is restricted to `main` to avoid publishing draft branches.
3. Open the deployed URL reported by the workflow, check it without signing in,
   and paste that URL into Play Console's privacy-policy field.
4. With the default project-site address, the expected URL is
   `https://jshstadler.github.io/esp32-secure-ble-key/`. This is an expected address,
   not a claim that the page is already live; use the actual deployment URL if a
   custom domain or account configuration changes it.
5. Run the publishing workflow again whenever a revised policy is merged.

Local preview: `python tools/prepare-play-pages.py --output <preview-directory>`
from the repository root. See [GitHub Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).

## Store listing text

**App name:** Remote Key

**Developer display name:** Logic-Labs

**Support and privacy email:** info@6675162.xyz

**Suggested category:** Tools

**Contains ads:** No

**Short description:**

Control compatible ESP car and gate devices over Bluetooth, without ads.

**Full description:**

Remote Key controls compatible ESP-based car remotes, gates, garage doors, and
other access devices over Bluetooth Low Energy. Compatible hardware running the
supported firmware is required. Remote Key does not replace arbitrary vehicle
keys or work with every car or gate.

Create device cards, give them useful names, and configure each device with its
own security key. Authenticated commands help ensure that your configured
hardware responds to the correct controller.

Features include:

- Customizable device cards for supported standalone and ESPHome devices.
- Per-device security keys stored with Android Keystore-backed encryption.
- Optional biometric or device-credential access to the app.
- Quick reconnection and a short background connection period.
- Live gate state when supported by the connected firmware.
- Local operation history and diagnostic logs you can save or share.
- Optional location pins for device operations, enabled separately per device.
- Signed firmware updates over BLE for supported standalone ESP devices.

Remote Key has no ads or in-app account registration. Your configuration,
operation history, and optional locations are stored on your phone. You control
when logs are exported or a saved location is opened in another app.

Only operate hardware you are authorized to control. Set up the supported
firmware and matching device keys before use. Bluetooth and location permission
requirements depend on your Android version and the features you enable.

Support: info@6675162.xyz

## App content and distribution

- Ads: **No**. No ad SDK or Advertising ID permission is present.
- Account creation: **None**. The Android biometric/screen-lock gate is not an
  online user account. In-app account-deletion requirements tied to account
  creation do not apply to this design; local data deletion is in the policy.
- Target audience: select the age groups you actually intend to serve. An adult
  audience is a reasonable starting point for this access-control utility; this
  is a recommendation, not a completed declaration. It is not designed for kids.
- Content rating: complete the IARC questionnaire based on actual content; do
  not invent a rating or answer every question "No" without reading it.
- Pricing: choose free or paid before publication. **No ads** does not determine
  the purchase price; no price decision has been applied by this PR.
- Global availability: in **Production > Countries/regions**, select every
  available supported country/region you intend to distribute to. Review any
  country-specific requirements Console presents. Confirm closed/open-test
  country targeting too; internal testing is not country-targeted. Availability
  remains subject to Play support, local requirements, and compatible devices.
  See [country targeting](https://support.google.com/googleplay/android-developer/answer/7550024?hl=en).
- Assets still to supply: 512 x 512 store icon, 1024 x 500 feature graphic, at
  least two real screenshots, and any additional assets Console requires.
  Suggested screenshots: device dashboard, device settings with keys masked,
  operation history, optional location feature, and firmware progress.

## Data safety worksheet

This is a review worksheet, not a submitted or blanket "no data" declaration.
Use the final release and Google's definitions when completing the form.

| Feature | Actual behavior | Declaration consideration |
| --- | --- | --- |
| PSKs and device settings | Keystore-encrypted app-private storage; no developer cloud | Local-only processing is outside collection scope. Evaluate key-update BLE transfers separately. |
| Diagnostics and operation history | App-private local records | Local processing alone is not collection. |
| Optional precise/approximate location | Per-device opt-in; local pins | Location permission alone does not establish off-device collection. |
| Save/share logs and open maps | Explicit user action sends selected data to chosen destination | Review the user-initiated sharing exception; disclose actual behavior in the policy. |
| BLE communication | Direct authentication, commands/status, PSK updates and firmware transfer | Assess transferred data against listed data types. HMAC authentication must not be described as encrypting every BLE payload. |
| Support email | User sends an email, optionally attaching logs | Contact details/content reach support and the email provider. Check the form's scope for external email flows. |
| Ads, analytics, accounts | No app-integrated ads/analytics/account service | Do not declare features or certifications that are absent. Reassess if SDKs change. |

Google excludes local-only processing from collection and has specific exceptions
for user-initiated sharing. Those are separate rules: do not treat a sharing
exception as an automatic collection exception. Source:
[Data safety definitions](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en-GB).

## Foreground-service declaration: text to paste

Open **App content > Foreground service permissions** (the exact navigation may
vary). Declare **Connected device / FOREGROUND_SERVICE_CONNECTED_DEVICE**.
If offered, select **Continuous data transfer to an external device**.

The Android manifest already declares both `FOREGROUND_SERVICE` and
`FOREGROUND_SERVICE_CONNECTED_DEVICE`, and the service type is `connectedDevice`.
There is no additional Play form declaration that a code PR can submit.

**Functionality:**

Remote Key communicates with user-configured ESP access-control hardware over
Bluetooth Low Energy. When the user leaves an authenticated app session with
active device clients, a foreground service preserves the existing connections
for up to two minutes so the user can return without reconnecting. It also keeps
a user-started signed firmware transfer running while the app is backgrounded.
The service displays a connection or firmware-update notification and stops
when the background connection window expires and no firmware transfer is
active, when the app returns to the foreground, or when the app task is removed.

**User impact if deferred or interrupted:**

Deferral loses the existing BLE connection and makes the user reconnect before
the next hardware command. Interruption of a firmware transfer stops that update
and requires retrying it. The service supports a connected-device interaction
the user started in the app. It does not perform advertising, analytics, or
continuous background location tracking.

**Video URL:** supply the accessible link to your actual recording below. Do not
submit a placeholder or claim that a video was recorded by this PR.

## Recording script: show the behavior, not background code

Google asks for a video demonstrating every declared foreground-service feature,
including the actions that trigger it. This lets reviewers see why the ongoing
work is necessary and visible. See
[foreground-service declarations](https://support.google.com/googleplay/android-developer/answer/13392821?hl=en).

Use the phone's built-in screen recorder, or film the phone and test ESP with a
second phone. Use a non-critical bench device and keep keys, personal addresses,
and unrelated notifications out of view. Record a real test; do not simulate a
successful hardware operation.

1. **Preparation:** install the release under review, configure a test ESP and
   PSK, and enable **App Settings > Connection notifications > Enable / manage**.
   On Android 13+, allow notifications and make sure the background-connection
   channel is enabled in Android settings. Begin recording after credential entry.
2. **Connection feature:** show Remote Key connected to the test device and a
   successful command/status. Press Home, pull down the notification shade, and
   show **Remote Key connected / Keeping connections ready for 2 minutes**.
3. Return to the app within that period and demonstrate another command. Then
   leave it again with no OTA running; record just over two minutes to show the
   notification disappearing. Return and optionally show the diagnostic entry
   **Background connection window ended**. Keep the expiry sequence continuous
   or clearly label any editing/time compression.
4. **Firmware feature:** on supported standalone hardware, choose a valid signed
   firmware file, confirm Update, show real progress, then briefly press Home
   and show **Firmware update in progress** in the notification. Return and
   capture completion and reconnection. A short transfer may need a second
   person filming to catch the notification. Never pause or alter firmware to
   fabricate this demonstration.
5. Upload as an accessible unlisted video (for example on YouTube), verify the
   link in a signed-out browser, and paste it into the declaration. No private
   login, access request, expiring link, or production PSK should be required.

You do not need to record radio packets or invisible background execution. The
user action, notification, continued behavior, and stopping behavior are the
evidence. A video does not replace testing or guarantee Play approval.

## App access: reviewer instructions draft

Remote Key does not use an online username/password account. The app may request
Android device authentication; use the review phone's configured screen lock or
biometric method. The privacy policy is readable without unlocking the app.

Full control features require a nearby compatible ESP device running this
project's firmware. Set the app's per-device PSK to match a dedicated test device.
Use Device Settings to select the device type, configure its key and optional
BLE address, then connect and use the dashboard control. Standalone firmware
supports signed BLE OTA; compatible ESPHome gate firmware provides live state.

Provide the review team with a practical way to test these hardware-dependent
features and an accessible demonstration. Supply any test-hardware instructions
and dedicated credentials privately in App access, never in this repository or
the public listing. This PR does not implement a hardware-free demo mode.

## Final sequence

Merge the rename PR, then this follow-up; enable/publish the policy page; enroll
the intended signing identity; generate and upload the AAB to Internal testing;
test real BLE hardware and permission-denial cases; record the videos; complete
the listing and App content forms; finish account/device verification; run the
required closed test if applicable; then apply for production access and review.
