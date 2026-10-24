# Remote Key Android 2.8.12 (build 38)

A button tapped while the device is connecting can now finish after pressing
Home or Recent apps. The existing short background service keeps the connection
attempt alive, including when Background connections is Off. The original
ten-second connection deadline, cancellation and single-send safeguards still
apply. Already-sent commands wait for their result before the connection closes.

The background notification now says Remote Key Bluetooth, so connecting is not
incorrectly reported as already connected. No ESP or Garmin update is required.

Manual checks: tap Press while connecting, immediately press Home or Recent apps,
and confirm one device action and one successful history entry. Repeat with
Background connections Off. Cancel before connection or stay out of range for
more than ten seconds, then reconnect: neither case should send a stale press.
Switch back to the app during connection and verify the press still sends once.
