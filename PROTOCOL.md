# Secure BLE Key protocol

## Car press receipts (rcp1, v2.8.0)

Car appends read/write characteristic `a1b2c3d4-e5f6-7890-abcd-ef123456789c`.
Existing characteristics/handles and legacy API-v2 commands remain unchanged.
Version 2.8.0 clients detect this characteristic and use RCP1 for mutual
authentication, presses, result queries, and receipt acknowledgment. Version
2.8.1 clients use RCP1 only for device proof; normal presses use the shorter
API-v2 command/status path to avoid the additional round-trip latency. Older
Car firmware and Gate retain their existing protocol.

For every exchange, read a fresh 16-byte challenge. Choose a cryptographically
random 16-byte request ID for PROVE or a new press. Retain the press ID across
reconnects. QUERY and ACK use that same ID with a fresh challenge/MAC.

```
op = 1 PROVE | 2 PRESS | 3 QUERY | 4 ACK
request = ASCII("BLEKEY-RCP1") || 0 || ASCII("car-main") || 0 ||
          op || request_id[16] || nonce[16]                  # 54 bytes
MAC = HMAC-SHA256(PSK, request)
```

Write three fragments with response, strictly in order, to `...789c`:
`F0 || request_id`, `F1 || op || MAC[0..15]`, `F2 || MAC[16..31]`.
They are 17, 18 and 17 bytes. Each connection has its own staging buffers;
the sequence expires five seconds after F0. F2 consumes the sequence and
rotates its challenge even when verification fails. Five authentication
failures close the session. No action occurs before full authentication.

Read the 19-byte response from the same characteristic:

```
reply = B1 || op || result || tag[16]
tag = HMAC-SHA256(PSK,
      ASCII("BLEKEY-RCP1-ACK") || 0 || ASCII("car-main") || 0 ||
      op || request_id[16] || request_nonce[16] || result)[0..15]
```

The authenticated reply transcript is 59 bytes. Result values: 0 UNKNOWN,
1 PENDING, 2 PRESSED (GPIO pulse finished), 3 BUSY (not pressed), 4 ACKED
(outcome discarded), 5 FULL (not pressed; cache capacity), 6 PROVED. A PROVE
exchange performs no GPIO operation. The independent random client ID binds
the peripheral's proof to the current client request.

The ESP reserves a cache entry before starting a pulse, then marks it PRESSED
on the BLE host queue after the timer has returned the GPIO to high impedance.
32 entries are held in RAM, independent of connection handles. Entries expire
at **30 seconds from initial reservation**; reads, reconnects and ACK do not
extend that deadline. No unexpired entry is evicted to admit another press.
Duplicate PRESS IDs return their cached state without pulsing the output.
ACK discards a completed outcome, retaining only the ID/expiry tombstone until
the original deadline. Pending actions cannot be acknowledged away.

After a lost RCP1 press response, v2.8.0 clients reconnect and QUERY, never
automatically PRESS again. They stop recovery 25 seconds after beginning the original exchange.
UNKNOWN, expired records or ESP restart mean “Unable to confirm”, not “not
pressed”. PRESSED confirms only the GPIO pulse, not the car's physical lock
state. No flash write is made for a press. Planned daily reboot waits for
unexpired unacknowledged outcomes; fault/watchdog recovery can still restart.

New Android key changes require RCP1-capable Car firmware so interrupted
changes can be recovered with authenticated, non-actuating key proofs. Before
transmission, the phone durably encrypts both old/candidate keys in a journal.
It removes the journal only after a verified storage receipt and durable local
save, or successful explicit recovery. Fresh firmware provisioning persists a
customized bootstrap key in NVS; failure leaves commands disabled.

All integer command values are one byte. Strings in authenticated transcripts
use the exact UTF-8/ASCII bytes shown. HMAC is HMAC-SHA256 using the per-device
pre-shared key, and each challenge is a fresh 16-byte random nonce.

## API v2

The Car binding is `car-main`; the Gate binding is `gate-main`.

```text
transcript = ASCII("BLEKEY-V2") || 0x00 ||
             UTF8(device_binding) || 0x00 ||
             command || nonce

MAC        = HMAC-SHA256(PSK, transcript)
payload    = command || MAC
```

The domain separator prevents cross-protocol reuse. Binding the stable device
identity and command prevents one valid response from authorizing a different
BLE Key device or action. Rotating the nonce after every verification attempt
prevents replay.

Android sends the 33-byte payload to characteristic `...7892`. Garmin sends
the same logical payload over `...7895` as `command + MAC[0..15]`, followed by
`MAC[16..31]` on `...7896`, to fit the default BLE ATT MTU.

Current command values:

- `0x01`: authenticate only
- `0x02`: press/open
- `0x03`: reserved legacy PSK command; plaintext updates are rejected

Current service families:

- Car API v2: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- Gate API v2: `b1b2c3d4-e5f6-7890-abcd-ef1234567890`

Gate API v2 also exposes the decoded controller state on read-only
characteristic `b1b2c3d4-e5f6-7890-abcd-ef123456789b`. It returns
`ERR:AUTH_REQUIRED` until command `0x01` or `0x02` has authenticated that BLE
connection. State is therefore not broadcast publicly; an authenticated app
may poll it while connected. Current values are `Unknown`, `Closed`, `Open`,
`Opening`, `Closing`, `Pillar override`, `No mains`, and `Low battery`.

## On-demand Car health (v2.7.0)

The existing read-only identity characteristic `a1b2c3d4-e5f6-7890-abcd-ef1234567897`
keeps its UUID and handle. A read before authentication returns only
`blekey|2|car-main|car|press,ota1,psk2,health1,radio1`. On an authenticated, non-closing
connection, an explicit read appends comma-separated health fields to this
capability list:
The two lines below are concatenated without a newline on the wire.

```text
,fw=2.7.0,build=012345abcdef,idf=v6.0.1,up=123,reset=power_on,ota=valid,heap=120000,minheap=100000,links=1,advrec=0,ghost=0
,fastmin=80,fastmax=160,slowmin=320,slowmax=640,idlesec=60,advmode=recent
```

`fw` is the running ESP app descriptor version, `build` is the first six bytes
of its ELF SHA-256 as hex, `up` is uptime in seconds, and memory values are bytes.
Recovery counters are RAM counters since boot. `reset` reports the ESP reset
reason; application-triggered software resets add a reason retained in RTC RAM
without writing flash. `ota` is `pending`, `valid`, `initial`, or `unknown`.
Advertising min/max values use 0.625ms BLE units, `idlesec` is seconds, and
`advmode` is `recent`, `inactive`, or `off` (all connection slots may be occupied).
Health is a maximum 512-byte ASCII read; clients must support long reads if
the negotiated MTU is smaller. Unknown capabilities/fields can be ignored.

Android reads static identity before authentication during setup, then requests
the detailed snapshot only from the health view or its Refresh button. Health
reads do not press the remote or rotate its challenge. Existing API-v2 clients
remain compatible; the service/characteristic layout has not changed.

New firmware refuses another OTA START with `ERR:OTA_PROBATION` until its pending
image has passed the startup health check. The normal single-use OTA START
authentication is still required before returning this status.

## Car advertising configuration (radio1, v2.7.0)

Write to the existing OTA-control characteristic `...7898` on an authenticated
connection. Its properties and handle are unchanged. Configuration is:

```text
config = LE16(fast_min) || LE16(fast_max) || LE16(slow_min) ||
         LE16(slow_max) || LE16(idle_seconds)  # 10 bytes
transcript = ASCII("BLEKEY-RADIO1") || 0x00 || ASCII("car-main") ||
             0x00 || nonce[16] || config       # 49 bytes
packet = 0x04 || config || HMAC-SHA256(PSK, transcript)  # 43 bytes
```

The challenge rotates after each authenticated-session verification attempt.
All settings are authenticated, range-checked, and committed as one versioned
NVS blob before changing the live configuration. Intervals are 32-3200 units
(20-2000ms); min must not exceed max, inactive endpoints cannot be smaller than
their recent endpoints, and inactivity is 5-3600 seconds. Defaults are
80/160/320/640 units and 60 seconds. Invalid/missing stored settings fall back
to defaults without touching the PSK. Identical, already persisted settings
avoid another flash write.

The requesting connection receives `RADIO:OK` on the existing OTA status
characteristic, or `ERR:RADIO_AUTH`, `ERR:RADIO_RANGE`, `ERR:RADIO_SAVE`, or
`ERR:RADIO_BUSY` (OTA transfer/probation). A missing acknowledgement is an
uncertain outcome: never repeat the write automatically; read health to inspect
the actual values. After Save, Android explicitly reads them back. Saving
starts the recent-activity window and restarts advertising with the new values;
existing connections are retained. A host callout handles the inactive deadline.

## Car PSK2 (v2.6.0)

The identity characteristic advertises `psk2`. Updating a key requires an
authenticated connection and a fresh challenge. The old plaintext update
format is disabled. Existing API-v2 authentication and press commands remain
compatible with previous clients.

```text
context(domain) = UTF8(domain) || 0x00 || UTF8("car-main") || 0x00 || nonce
encryption_key = HMAC-SHA256(old_PSK, context("BLEKEY-PSK2-ENC"))
receipt_key    = HMAC-SHA256(old_PSK, context("BLEKEY-PSK2-ACK"))
AAD            = context("BLEKEY-PSK2")
packet         = 0xA2 || random_IV[12] || AES-256-GCM(encryption_key, IV, new_PSK, AAD)
```

The GCM output is ciphertext followed by its 16-byte tag. New keys must be
1–128 UTF-8 bytes without NUL. Send the packet to the existing PSK-update
characteristic. The nonce rotates after verification. No key change occurs
unless GCM verification and persistent storage both succeed.

The per-connection status returns `PSK2:OK:<tag>` or `PSK2:FAIL:<tag>`.
The lowercase hex tag is HMAC-SHA256 with `receipt_key` over one byte
(`0x01` for persisted, `0x00` for failed), followed by SHA256 of the exact
packet. Clients update their saved key only after verifying an OK receipt.
Missing acknowledgement leaves the result uncertain; retain both keys until
the device key is confirmed. Other authenticated connections are revoked
after a successful change.

Clients serialize ATT requests and reconnect on missing callbacks. They never
automatically retransmit an unconfirmed press. Car and Gate expire sessions
that have not authenticated within 20 seconds, regardless of challenge reads.
