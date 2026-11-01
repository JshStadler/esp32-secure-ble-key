# Remote Key Android 2.8.15 (build 41)

Widgets now change colour and text as a press progresses: amber while connecting,
blue while sending, green only after the device confirms the press, and red when
a press fails or cannot be confirmed. Compact widgets show the action status in
place of the device name. After three seconds the confirmation returns to the
normal device name and ready status.

Widgets follow Settings → Background connections: Off, 30 seconds or 2 minutes.
The current saved duration starts after each confirmed press, and another
confirmed press restarts it. Off disconnects Bluetooth immediately after the
result; the confirmation stays visible for three seconds. The default is the
app's existing two-minute preference. Connection attempts still expire after ten
seconds; changing the idle duration does not authorize delayed or repeated presses.

No ESP or Garmin update is required. Existing widgets retain their device and icon.

Manual checks: confirm connecting/sending/result colours on small and enlarged
widgets; test each background duration, rapid taps during confirmation, and a
second device's widget during the three-second confirmation. An old confirmation
must not overwrite the new action. Check that failure never shows green and that
Off disconnects immediately after confirmation without interrupting the press.
