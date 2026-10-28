# Remote Key Android 2.8.14 (build 40)

Add a Remote Key press widget from your launcher's Widgets menu and choose an
existing device and a Car, Gate, Door, Garage or Key icon (Android 12 or newer).
Device and icon choices are saved per widget, so tapping never asks for a device
again. Reconfigure through the launcher's widget Edit/Settings option. Compact
widgets show an icon and label; enlarging them reveals connection/result text.
A tap authenticates according to the app's existing setting,
connects and sends one button press without opening the dashboard. Locked phones
still require device authentication. Bluetooth permission can be granted from
the brief widget activity; Bluetooth itself must already be on.

After a confirmed press, the widget's foreground service holds its connection
for 30 seconds. Further taps reuse that connection and restart the 30-second
window after their result. Taps during an in-flight command are ignored rather
than queued. Each unsent press expires after ten seconds; already-sent commands
are never automatically repeated. An uncertain outcome instructs the user to
check the device. The notification supports cancellation before dispatch and
disconnection while idle. Process recreation never replays a press.

Each widget selects one configured device; multiple widgets may target different
devices. The widget service holds one connection at a time and switches devices
only while idle. It is independent of the dashboard's connection lifetime. If
the dashboard already has its own connection, that connection follows the app's
existing settings. Widget presses use the existing operation history and
best-effort optional location capture; location denial does not affect a press.
No ESP or Garmin update is required for the widget.

Widgets are offered on Android 12+ using the existing Nearby devices permission.
Android 10/11 background scanning requires additional location access; this
release keeps the existing permission footprint and normal app support on older
Android versions.

Manual validation: add Car and Gate widgets, grant/deny permissions, enable/disable
app authentication, cancel the biometric/PIN prompt, turn Bluetooth off, and
confirm no hardware action occurs on rejection. Verify one press per completed
tap, busy taps do not queue, successive presses within 30 seconds reuse the
connection, and it disconnects after the last 30-second idle period. Test an
out-of-range tap followed by returning after ten seconds: no stale press should
execute. Check large text/display sizes on the real launcher. Swiping the
dashboard away must not interrupt a separate widget operation.
