# Remote Key Android 2.8.16 (build 42)

Tap a widget again while it shows Wait… / Connecting… to cancel the pending press
before it is sent. Cancellation goes directly to the running operation, without
opening the app or asking for authentication, and shows Canceled / Cancel.

Once Sending… starts, the command cannot be recalled; further taps are ignored
while its result is pending. A delayed tap on an old Wait… display is always a
cancellation for that original request, never a new press. Notification Cancel
actions have the same request binding. After process death, an old cancellation
cannot start a connection or send a command.

The background connection duration, device/icon configuration and normal press
authentication stay unchanged. No ESP or Garmin update is required.

Manual check: while out of range tap the widget, wait for Wait…, then tap again.
It should show Cancel/Canceled; moving into range afterwards must not trigger a
press. At normal range verify a sent command still reports its real result and
an old cancellation cannot cancel a subsequent request.
