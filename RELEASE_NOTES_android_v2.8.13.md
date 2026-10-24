# Remote Key Android 2.8.13 (build 39)

Device cards now expand to fit their name and complete status. At larger font or
display sizes, the Press/Cancel button moves below the details when needed.
Settings buttons can wrap onto multiple lines, the header can grow, and log
controls and entries share a scrolling page so large controls cannot hide the
history. Font scaling remains enabled.

Automatic retries keep one continuous Connecting or Reconnecting label and an
amber indicator through scanning, direct connection, authentication and retry
backoff. Precise failure reasons and stages remain in Diagnostics. A connected
device no longer briefly looks disconnected while fetching health or performing
an operation. Bluetooth-off, cancellation, timeouts and uncertain command
outcomes remain visible. Pending presses keep their ten-second connection limit.

No ESP or Garmin update is required.

Validation: native Android layout measurements at 280/320/380 dp card widths and
1.0/1.3/1.5/2.0 font scales, with full text/button visibility and changing status
length; connection presentation sequence tests; existing Android regression
tests, lint, debug build and optimized release build.

Quick phone checks: increase both Display size and Font size in Android settings;
check a long device name, Connected/Reconnecting, Press/Cancel, app settings and
log controls in portrait and landscape. Move out of range and back: retries
should keep a steady label, then turn green only after authentication. Turn
Bluetooth off and cancel a pending press to confirm those messages remain clear.
