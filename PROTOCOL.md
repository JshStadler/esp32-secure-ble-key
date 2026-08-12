# Secure BLE Key protocol

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
- `0x03`: update the Car PSK

Current service families:

- Car API v2: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- Gate API v2: `b1b2c3d4-e5f6-7890-abcd-ef1234567890`
