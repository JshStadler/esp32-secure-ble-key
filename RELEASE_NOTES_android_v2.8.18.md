# Remote Key Android 2.8.18 (build 44)

The dashboard and widgets can connect and press different devices at the same
time. Each device owns its pending authorization, connection and result deadlines,
cancellation token, feedback reset, operation log session and widget connection
window. One pending press per device is allowed; unsent taps are never queued or
replayed. Canceling, failing or timing out one device leaves the others running.

Widget notifications summarize the active devices and offer device-specific
Cancel or Disconnect actions. Existing background duration, authentication,
configuration/key rechecks and the three-second result display are preserved.
Dashboard key changes and firmware transfers remain exclusive maintenance actions.
An uncertain sent dashboard command discards its connection callbacks before a
new action can start; delayed firmware cleanup cannot close a newer press.

Validation covers simultaneous dashboard taps, Home/Recents, separate deadlines,
Bluetooth being disabled, independent widget dispatch/results and warm connection
expiry, Off duration, unsent cancellation, sent-command cancellation rejection,
duplicate intents and stale callbacks. The Android unit suite, lint, debug build
and release R8 build pass. No ESP or Garmin firmware update is required.

Manual check: with the car out of range, request a car press and immediately press
the nearby gate, first in the dashboard and then with widgets. The gate should
complete while the car waits; canceling the car should leave the gate connection
open for its configured duration. Only perform this when safe to operate the gate.
