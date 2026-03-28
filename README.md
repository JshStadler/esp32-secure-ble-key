<h1>
  <img src="https://github.com/user-attachments/assets/df0752f4-f48e-4ef4-8ece-912d6552f2eb"
       width="48"
       align="left"
       style="margin-right: 12px;" />
  BLE Car Key
</h1>

A Bluetooth Low Energy (BLE) system that turns your phone into a car key. An ESP32 wired to your car remote's button acts as a bridge — your phone authenticates over BLE and triggers the remote, unlocking or locking the car.

## How It Works

The ESP32 sits inside the car, powered from the 12V system via a buck converter. A GPIO pin is wired directly across the car remote's button — no MOSFET or relay needed since both share the same 3.3V supply. When you want to unlock the car, the Flutter app on your phone connects over BLE, completes an HMAC-SHA256 challenge-response handshake using a pre-shared key (PSK), and sends a command. The ESP32 verifies the HMAC and drives the GPIO to simulate a button press on the remote.

## Project Structure

```
ESP32_Firmware/           ESP32 Arduino firmware (PlatformIO)
Android_Flutter_Application/   Flutter mobile app (Android; iOS is untested)
```

## Security

Authentication uses HMAC-SHA256 with a challenge-response protocol:

1. The ESP32 generates a random 16-byte nonce
2. The phone reads the nonce and computes `HMAC-SHA256(nonce, PSK)`
3. The phone sends the HMAC along with a command byte
4. The ESP32 verifies using constant-time comparison, then rotates the nonce

Additional protections include biometric gating on the phone (fingerprint/face), auto-disconnect timeouts (15s unauthenticated, 5min authenticated), and secure storage for the PSK on both the phone and ESP32.

> **Important:** The firmware ships with a placeholder PSK (`CHANGE_ME_before_flashing_32chars!`). You **must** change this before deploying. You can update the PSK over BLE from the app after initial setup.

## Hardware

- **MCU:** ESP32-C3 or standard ESP32 (C3 variant is better for low power draw like in vehicle running off battery)
- **Power:** Car 12V through a buck converter to 3.3V (powers both the ESP32 and the remote)
- **Remote:** Car remote with a physical button — GPIO wired directly across the button
- **No MOSFET needed** when the remote runs on the same 3.3V supply as the ESP32

### Wiring Diagram

```
Car 12V ──► Buck Converter ──► 3.3V ──┬──► ESP32 VIN
                                       └──► Remote (replaces batteries)

ESP32 GPIO 4 ──► Remote button (non-supply leg)
                  Remote button (other leg) ──► 3.3V or GND (depends on remote)
```

### Button Polarity

Use a multimeter to check which side of the remote's button connects to the supply rail:

- **One leg on 3.3V:** The button pulls the encoder input HIGH when pressed. Set `BUTTON_ACTIVE_HIGH true`.
- **One leg on GND:** The button pulls the encoder input LOW when pressed. Set `BUTTON_ACTIVE_HIGH false`.

Wire GPIO 4 to the **other leg** (the encoder input side).

> **Note:** If your remote operates at a different voltage than 3.3V, you'll need a relay or N-Channel MOSFET (e.g. BS170) between the GPIO and the button, plus a separate regulator for the remote.

<img width="360" height="506" alt="image" src="https://github.com/user-attachments/assets/f285ad65-6825-4cf8-b721-fcc585502ffc" />

## Getting Started

### ESP32 Firmware

**Requirements:** [PlatformIO](https://platformio.org/) (CLI or VS Code extension)

1. Open `ESP32_Firmware/` in PlatformIO
2. Edit `src/car_unlock_firmware.ino` and change `DEFAULT_PSK` to your own secret (32+ characters recommended)
3. Optionally adjust `BUTTON_GPIO`, `BUTTON_ACTIVE_HIGH`, `BUTTON_PULSE_MS`, `BLE_DEVICE_NAME`, and other configuration constants at the top of the file
4. Build and flash:
   ```
   pio run -t upload
   ```
5. Monitor serial output:
   ```
   pio device monitor
   ```

### Flutter App

**Requirements:** [Flutter SDK](https://flutter.dev/docs/get-started/install) (3.0+)

1. Navigate to `Android_Flutter_Application/`
2. Install dependencies:
   ```
   flutter pub get
   ```
3. Run on a connected device:
   ```
   flutter run
   ```

On first launch, set the PSK in the app's settings to match what you flashed onto the ESP32.

## BLE Service Details

| Characteristic | UUID (suffix) | Properties | Purpose |
|---|---|---|---|
| Challenge | `...7891` | Read, Notify | 16-byte random nonce |
| Command | `...7892` | Write | 1-byte command + 32-byte HMAC |
| Status | `...7893` | Read, Notify | Result of last operation |
| PSK Update | `...7894` | Write | Change PSK (requires auth first) |

Service UUID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`

### Commands

- `0x01` — Authenticate only (no button press)
- `0x02` — Authenticate and press remote button

## Configuration

Key constants in `car_unlock_firmware.ino`:

| Constant | Default | Description |
|---|---|---|
| `DEFAULT_PSK` | `CHANGE_ME_before_flashing_32chars!` | Pre-shared key (change before flashing) |
| `BUTTON_GPIO` | `4` | GPIO pin wired to remote button |
| `BUTTON_ACTIVE_HIGH` | `true` | `true` if button connects to VCC, `false` if to GND |
| `BUTTON_PULSE_MS` | `300` | Button press duration in ms |
| `DEBUG_LED_ENABLED` | defined | Comment out to disable debug LED |
| `DEBUG_LED_GPIO` | `2` | GPIO for debug LED (active during button press) |
| `BLE_DEVICE_NAME` | `BLE-Device` | BLE advertised name |
| `MAX_CONNECTIONS` | `3` | Simultaneous BLE connections |
| `BLE_TX_POWER` | `3` | TX power in dBm (-12 to 9) |
| `UNAUTH_TIMEOUT_SEC` | `15` | Auto-disconnect for unauthenticated clients |
| `AUTH_TIMEOUT_SEC` | `300` | Auto-disconnect for authenticated clients |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
