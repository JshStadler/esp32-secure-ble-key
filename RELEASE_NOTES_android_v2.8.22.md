# Remote Key Android 2.8.22 (build 48)

- Tapping a waiting widget cancels its pending button press while allowing the existing BLE connection attempt to finish. It never sends the canceled command.
- Cancellation feedback clears after three seconds. **Link… / Connect only** identifies a connection attempt without a queued press; the widget returns to its connected blue state when ready.
- The connection attempt retains its original ten-second deadline. On connection, the saved **Background connections** duration starts: Off disconnects immediately, otherwise 30 seconds or 2 minutes.
- A new explicit widget tap can request another press while connecting or connected. Duplicate requests, stale cancellation actions and late callbacks cannot restore the canceled press or extend the connection lease.
- The notification's **Disconnect** action can end a connection-only attempt. Other devices' pending presses and connections remain independent.

No ESP or Garmin update is required. Commands already sent cannot be recalled.

## Quick manual checks

1. With background connections set to 30 seconds or 2 minutes, tap a disconnected widget and tap again while it shows Wait. Verify it connects without triggering the remote, then disconnects after the saved duration.
2. After canceling, explicitly tap again and verify exactly one press occurs. Check only when it is safe for the real device to operate.
3. With a device out of range, cancel near the original connection deadline. Verify it times out without continuing indefinitely or sending a press after moving back into range.
