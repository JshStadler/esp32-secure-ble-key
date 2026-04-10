<h1>
  <img src="https://github.com/user-attachments/assets/df0752f4-f48e-4ef4-8ece-912d6552f2eb"
       width="48"
       align="left"
       style="margin-right: 12px;" />
  BLE Car Key Solution
</h1>

A Bluetooth Low Energy (BLE) system that turns your phone and/or Garmin watch into a car key. An ESP32-C3 wired to your car remote's button acts as a bridge — your phone or watch authenticates over BLE and triggers the remote, unlocking or locking the car.

While designed for automotive use, the system can be adapted to any application requiring a secure BLE-triggered action, such as doors, gates, or other access control systems.
*(This is not for keyless ignition/starting.)*

Designed for both convenience and security:
- No need to carry physical keys for everyday access
- Lost keys alone cannot unlock the car without the additional authentication layer
- Access can be restored on a new device if your phone or watch is lost, with proper authentication
- Power-optimised for always-on operation in a parked vehicle

## 🛠️ How It Works

The ESP32-C3 sits inside the car, powered from the 12V system via a buck converter. A GPIO pin is wired directly across the car remote's button — no MOSFET or relay needed since both share the same 3.3V supply. When you want to unlock the car, the Flutter app on your phone (or the Garmin watch app) connects over BLE, completes an HMAC-SHA256 challenge-response handshake using a pre-shared key (PSK), and sends a command. The ESP32-C3 verifies the HMAC and drives the GPIO to simulate a button press on the remote.

The C3 firmware is built on ESP-IDF (no longer Arduino) so it can use FreeRTOS tickless idle, dynamic frequency scaling, and automatic light sleep — keeping the device draw very low for operation off a parked car's battery.

## 🧱 Project Structure

```
Android_Flutter_Application/     Flutter mobile app (Android; iOS untested)
Garmin_Watch_App/                Garmin Connect IQ watch app
ESP32-C3_Firmware/               ESP32-C3 ESP-IDF firmware (PlatformIO) — recommended
ESP32_Arduino_Firmware/          ESP32 Arduino firmware (PlatformIO) — POC, not maintained
ESP32-C3_Arduino_Firmware/       ESP32 Arduino firmware (PlatformIO) — POC, not maintained
```

## 🔒 Security

Authentication uses HMAC-SHA256 with a challenge-response protocol:

1. The ESP32 generates a random 16-byte nonce
2. The phone/watch reads the nonce and computes `HMAC-SHA256(nonce, PSK)`
3. The phone/watch sends the HMAC along with a command byte
4. The ESP32 verifies using constant-time comparison
5. The nonce is rotated unconditionally after every verification attempt (success or failure) to prevent replay

Additional protections include biometric gating on the phone (fingerprint/face), auto-disconnect timeouts (15s unauthenticated, 5min authenticated), and secure storage for the PSK on both the phone/watch and ESP32 (stored in NVS).

The PSK can be updated over BLE from the phone app after initial setup — the update itself is authenticated against the existing PSK, so only an already-authorised client can change it.

> **Important:** The firmware ships with a placeholder PSK (`CHANGE_ME_before_flashing_32chars!`). You **must** change this before deploying.

## ⚡ Power Efficiency (ESP32-C3)

The C3 firmware is designed for long term always-on operation in a parked vehicle:

| Metric             | Value                            |
|--------------------|----------------------------------|
| Idle current draw  | AI estimated at ~2-5 mA             |
| CPU idle frequency | 10 MHz (auto-scaled via DFS)     |
| CPU active freq    | 80 MHz                           |
| Sleep mode         | Auto light sleep (tickless idle) |
| Wi-Fi              | Excluded at build time           |
| BLE modem sleep    | Cooperates with PM light sleep   |

Achieved through ESP-IDF features unavailable in the Arduino framework:
- `CONFIG_PM_ENABLE` + `CONFIG_FREERTOS_USE_TICKLESS_IDLE`
- Dynamic frequency scaling between 10 MHz and 80 MHz
- Wi-Fi stack stripped from the build (saves ~100 KB flash, ~40 KB RAM)
- USB-CDC console disabled in production
- Button GPIO held in high-impedance idle (zero quiescent current)
- Periodic restart every 3 hours when idle (state hygiene, while no device connected)
- Hard restart after 24 hours regardless of state

## 🖥️ Hardware

- **MCU:** ESP32-C3 SuperMini (recommended) or standard ESP32 (POC, not maintained)
- **Power:** Car 12V through a buck converter to 3.3V (powers both the ESP32 and the remote)
- **Remote:** Car remote with a physical button — GPIO wired directly across the button
- **No MOSFET needed** when the remote runs on the same 3.3V supply as the ESP32

### 🔌 Wiring Diagram (Single button remote)

```
Car 12V ──► Buck Converter ──► 3.3V ──┬──► ESP32-C3 VIN
                                       └──► Remote (replaces batteries)

ESP32-C3 GPIO 5 ──► Remote button (non-supply leg)
                     Remote button (other leg) ──► 3.3V or GND (depends on remote)
```

GPIO 5 is used because it has no strapping function on the C3 and is safe for clean digital I/O. Avoid GPIO 2/8/9 (strapping/LED/boot button) and GPIO 18/19 (USB-CDC needed for flashing).

### 🔄 Button Polarity

Use a multimeter to check which side of the remote's button connects to the supply rail:

- **One leg on 3.3V:** The button pulls the encoder input HIGH when pressed. Set `BUTTON_ACTIVE_HIGH true`.
- **One leg on GND:** The button pulls the encoder input LOW when pressed. Set `BUTTON_ACTIVE_HIGH false`.

Wire GPIO 5 to the **other leg** (the encoder input side).

> **Note:** If your remote operates at a different voltage than 3.3V, you'll need a relay or N-Channel MOSFET (e.g. BS170) between the GPIO and the button, plus a separate regulator for the remote.

<img width="360" height="506" alt="image" src="https://github.com/user-attachments/assets/f285ad65-6825-4cf8-b721-fcc585502ffc" />

## 🚀 Getting Started

### 💻 ESP32-C3 Firmware

**Requirements:** [PlatformIO](https://platformio.org/) (CLI or VS Code extension). The ESP-IDF toolchain is installed automatically by PlatformIO on first build.

1. Open `ESP32-C3_Firmware/` in PlatformIO
2. Edit `main/main.c` and change `DEFAULT_PSK` to your own secret (32+ characters recommended)
3. Optionally adjust `BUTTON_GPIO`, `BUTTON_ACTIVE_HIGH`, `BUTTON_PULSE_MS`, `BLE_DEVICE_NAME`, and other configuration constants near the top of the file
4. Build and flash:
   ```
   pio run -e esp32c3 -t upload
   ```
5. Production builds disable the serial console for power savings. To enable logging during development, see `BUILD_NOTES.md` for the debug build steps.

### 📱 Android App (Flutter)

**Requirements:** [Flutter SDK](https://flutter.dev/docs/get-started/install) (3.0+)

1. Navigate to `Android_Flutter_Application/`
2. Install dependencies:
   ```
   flutter pub get
   ```
3. Build apk:
   ```
   flutter clean
   dart run flutter_launcher_icons
   flutter build apk --release -v
   ```

On first launch, set the PSK in the app's settings to match what you flashed onto the ESP32-C3. The app stores it in encrypted secure storage and gates access behind biometric authentication on supported devices.

<img width="360" height="707" alt="image" src="https://github.com/user-attachments/assets/e33acc7a-7c9c-415d-9772-41116ede4fe0" /><img width="360" height="707" alt="image" src="https://github.com/user-attachments/assets/94fad788-adde-4d8a-987b-6423a58d1854" />

### ⌚ Garmin Watch App

**Requirements:** Connect IQ SDK with `minSdkVersion 5.2.0` or newer. Currently targets the Forerunner 165 — other devices need to be added to the manifest.

> **Note:** The minimum SDK version can likely be lowered (down to around 3.x) to support older devices. The app only uses the standard BLE central API and the native HMAC-SHA256 cryptography API. This is untested as the app is only built for the FR165, so you may need to experiment with different `minSdkVersion` values to find what works for your device.

> **Note:** PSK needs to be set before compiling the app (via `properties.xml` or the app's runtime settings).

**Controls:**
- **SELECT** — send unlock command (works whether connected or disconnected; auto-connects if needed)
- **BACK** — exit app (preserves BLE pairing for fast reconnect on next launch)
- **MENU** (long-press UP) — force unpair, useful after firmware updates that change the GATT service table

The watch persists its BLE pairing across app sessions, so subsequent launches reconnect in 1-2 seconds instead of repeating the full GATT service discovery (~15s).

<img width="360" height="539" alt="image" src="https://github.com/user-attachments/assets/28264123-9bf5-41ac-bad2-cb6732b7731b" />

## 📡 BLE Service Details

| Characteristic | UUID (suffix) | Properties | Purpose |
|---|---|---|---|
| Challenge | `...7891` | Read, Notify | 16-byte random nonce |
| Command | `...7892` | Write, WriteNR | 1-byte command + 32-byte HMAC (single write) |
| Status | `...7893` | Read, Notify | Result of last operation |
| PSK Update | `...7894` | Write | Change PSK (requires HMAC of current PSK) |
| Command Pt1 | `...7895` | Write, WriteNR | Split write path: 1-byte cmd + first 16 HMAC bytes |
| Command Pt2 | `...7896` | Write, WriteNR | Split write path: last 16 HMAC bytes |

Service UUID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`

The split Pt1/Pt2 path exists because Garmin Connect IQ doesn't expose MTU negotiation, leaving the watch stuck at the default 23-byte ATT MTU. A 33-byte command can't fit in a single write at that MTU, so the watch sends it as two writes. The phone app uses the single-write path since it can negotiate a larger MTU.

### Commands

- `0x01` — Authenticate only (no button press)
- `0x02` — Authenticate and press remote button

> **Note:** Additional commands will be needed for multi-button remotes or additional triggers.

### Status messages

| Status              | Meaning                                            |
|---------------------|----------------------------------------------------|
| `READY`             | Device booted, awaiting commands                   |
| `OK:AUTH`           | Authentication succeeded (no action)               |
| `OK:PRESSED`        | Button press triggered                             |
| `OK:PSK_UPDATED`    | PSK changed and persisted to NVS                   |
| `WARN:PSK_VOLATILE` | PSK changed in memory but NVS write failed         |
| `ERR:AUTH`          | HMAC verification failed                           |
| `ERR:BUSY`          | Button press rejected — previous press still active |
| `ERR:UNKNOWN_CMD`   | Unrecognised command byte                          |
| `ERR:PSK_FORMAT`    | PSK update payload malformed                       |

## 🧰 Configuration

Key constants in `main/main.c`:

| Constant | Default | Description |
|---|---|---|
| `DEFAULT_PSK` | `CHANGE_ME_before_flashing_32chars!` | Pre-shared key (change before flashing) |
| `BUTTON_GPIO` | `GPIO_NUM_5` | GPIO pin wired to remote button |
| `BUTTON_ACTIVE_HIGH` | `true` | `true` if button connects to VCC, `false` if to GND |
| `BUTTON_PULSE_MS` | `300` | Button press duration in ms |
| `DEBUG_LED_ENABLED` | undefined | Define to enable debug LED on button press |
| `DEBUG_LED_GPIO` | `GPIO_NUM_8` | GPIO for debug LED (SuperMini onboard LED) |
| `BLE_DEVICE_NAME` | `BLE-Device` | BLE advertised name |
| `BLE_TX_POWER` | `3` | TX power in dBm |
| `ADV_INTERVAL_MIN` | `1600` | Min advertising interval (×0.625 ms) |
| `ADV_INTERVAL_MAX` | `3200` | Max advertising interval (×0.625 ms) |
| `MAX_CONNECTIONS` | `3` | Simultaneous BLE connections |
| `UNAUTH_TIMEOUT_SEC` | `15` | Auto-disconnect for unauthenticated clients |
| `AUTH_TIMEOUT_SEC` | `300` | Auto-disconnect for authenticated clients |
| `RESTART_INTERVAL_SEC` | `10800` | Soft restart when idle (3 hours) |
| `HARD_RESTART_SEC` | `86400` | Hard restart regardless of state (24 hours) |
| `PM_MAX_FREQ_MHZ` | `80` | DFS max CPU frequency |
| `PM_MIN_FREQ_MHZ` | `10` | DFS min CPU frequency |

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
