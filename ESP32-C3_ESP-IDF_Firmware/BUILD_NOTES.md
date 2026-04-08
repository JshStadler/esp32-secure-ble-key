# BLE Car Unlock Bridge — ESP-IDF Migration Notes

## What changed (Arduino → ESP-IDF)

### Power: the whole point

| Metric             | Arduino framework       | ESP-IDF                          |
|--------------------|-------------------------|----------------------------------|
| Idle draw (no BLE) | ~15-20 mA               | ~2-5 mA (auto light sleep + DFS) |
| CPU idle freq      | 80 MHz (fixed)          | 10 MHz (DFS auto-scales)         |
| CPU active freq    | 80 MHz (fixed)          | 80 MHz (DFS auto-scales)         |
| Sleep mode         | None (busy idle loop)   | Auto light sleep (tickless idle) |
| Wi-Fi stack        | Disabled at runtime     | Excluded at build time           |
| BLE modem sleep    | Yes (NimBLE flag)       | Yes + cooperates with PM sleep   |

The key unlock: `CONFIG_PM_ENABLE` + `CONFIG_FREERTOS_USE_TICKLESS_IDLE` are only
available in ESP-IDF because Arduino's FreeRTOS libs are precompiled without them.

### API mapping

| Arduino                 | ESP-IDF                                          |
|-------------------------|--------------------------------------------------|
| `pinMode/digitalWrite`  | `gpio_config()` / `gpio_set_level()`             |
| `delay(ms)`             | `vTaskDelay(pdMS_TO_TICKS(ms))`                  |
| `millis()`              | `esp_timer_get_time() / 1000`                    |
| `Serial.printf`         | `ESP_LOGI/W/E()` macros (via LOG_I/W/E wrappers) |
| `Preferences`           | `nvs_flash` / `nvs_open/get/set/close`           |
| `NimBLE-Arduino classes`| Native NimBLE C API (`ble_gatts_*`, `ble_gap_*`)  |
| `esp_task_wdt_init`     | `esp_task_wdt_reconfigure` (IDF 5.x)             |
| `setup() + loop()`      | `app_main()` + FreeRTOS task                     |

### Architecture changes

- **No `loop()`**: The ghost reaper, timeout checks, and periodic restart logic
  now run in a dedicated FreeRTOS task (`main_loop_task`) at priority 5. The
  NimBLE host runs in its own task via `nimble_port_freertos_init()`.

- **GATT registration**: Instead of NimBLE-Arduino's `createService()` /
  `createCharacteristic()` chain, we declare a static GATT service table
  (`gatt_svcs[]`) with access callbacks. NimBLE registers everything at init.

- **Notifications**: `ble_gatts_notify_custom()` replaces `characteristic->notify()`.
  We iterate active client slots and notify each subscribed connection.

- **GAP events**: A single `gap_event_handler()` replaces the `ServerCallbacks`
  class. Handles connect, disconnect, advertising complete, MTU, and subscribe.

## Building

```bash
# First build (generates sdkconfig from sdkconfig.defaults):
pio run -e esp32c3

# Flash:
pio run -e esp32c3 -t upload

# Monitor (production build won't show logs — see Debug Builds below):
pio device monitor
```

## Debug builds

To enable serial logging during development:

1. In `main.c`, uncomment `#define DEBUG`
2. In `platformio.ini`, uncomment `build_flags = -DDEBUG`
3. In `sdkconfig.defaults`, change:
   - `CONFIG_ESP_CONSOLE_NONE=y` → `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y`
   - `CONFIG_LOG_DEFAULT_LEVEL=1` → `CONFIG_LOG_DEFAULT_LEVEL=3`
4. **Delete `sdkconfig`** so it regenerates from defaults: `rm sdkconfig`
5. Rebuild: `pio run -e esp32c3`

## NVS compatibility

The NVS namespace (`car_unlock`) and key (`psk`) match the Arduino version.
If you've already flashed a custom PSK with the Arduino firmware, it will
carry over — NVS persists across framework changes as long as you don't
erase the flash.

## Flash erasing

If you hit NVS corruption or want a clean start:

```bash
pio run -e esp32c3 -t erase
pio run -e esp32c3 -t upload
```

## Known differences from Arduino version

1. **TX power API**: ESP-IDF uses `esp_ble_tx_power_set()` with enum levels
   (e.g. `ESP_PWR_LVL_P3` = 3 dBm). The exact dBm mapping is in
   `esp_bt.h`. The firmware sets `ESP_PWR_LVL_P3` to match the Arduino
   version's 3 dBm.

2. **MTU**: Set via `ble_att_set_preferred_mtu(185)` in the sync callback,
   matching the Arduino version's `NimBLEDevice::setMTU(185)`.

3. **Watchdog**: IDF 5.1 uses `esp_task_wdt_reconfigure()` instead of the
   older `esp_task_wdt_init()`. The main loop task subscribes itself with
   `esp_task_wdt_add(NULL)`.

4. **LED pin parking**: Still parks GPIO 8 low in production, same as the
   Arduino version. Only runs when `DEBUG_LED_ENABLED` is not defined.
