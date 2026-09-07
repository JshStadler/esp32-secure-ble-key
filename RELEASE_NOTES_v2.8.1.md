# v2.8.1 — responsive presses and filtered log exports

- Restore the short command/status path for normal Android and Garmin Car
  presses. Remove the extra press receipt, completion-query, and acknowledgment
  exchanges that caused noticeable delays in v2.8.0. A ready Android connection
  sends one command write at the normal negotiated MTU and uses the ESP status
  notification. The UI shows Pressing, then the result.
- If the connection drops before a result arrives, show an uncertain outcome
  and never automatically repeat the press. Reconnect lookup of press results
  is no longer used by these clients. The firmware's 30-second RAM cache remains
  compatible with v2.8.0 clients.
- Keep authenticated device proof and durable interrupted PSK-change recovery.
  Reuse Android's freshly read challenge for device proof, avoiding a redundant
  read during connection setup.
- Logs now support a local-day picker, All dates, and case-insensitive text
  search alongside category/device filters. Filters survive screen recreation.
- Export saves or shares a text file containing exactly the displayed matching
  entries, with timestamps, timezone, and filter details. Files avoid Android's
  large share-text limits. Clear removes only entries matching the filters.
- Retain the newest entries when the 2,000-record log limit is reached.

## Installing

Install the signed Android APK and the Garmin Car PRG matching your watch model.
Garmin Gate packages are included because the shared connection code also
preserves uncertain outcomes across reconnects.

**No new firmware is required. Keep Car firmware v2.8.0 installed.** The
three-hour reboot stays disabled; daily fallback and watchdog recovery remain.

Log retention is unchanged: diagnostics 24 hours, operations seven days,
locations the latest 30 sessions. Date filters only select retained records.

## Validation

Android unit tests and lint, plus Garmin exports for all supported watch models.
Date tests cover local midnight, daylight-saving boundaries, and combined
device/date/search filtering. Device radio latency still needs checking on the
installed phone/watch and Car; no physical devices were connected for testing.
