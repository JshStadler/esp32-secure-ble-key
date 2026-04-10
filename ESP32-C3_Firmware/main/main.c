/*
 * BLE Car Unlock Bridge - ESP32-C3 Firmware (ESP-IDF)
 *
 * Bridges a phone/watch (via BLE) to a car alarm remote's button.
 * Authentication: HMAC-SHA256 challenge-response with PSK.
 *
 * Target: ESP32-C3-DevKitM-1 / ESP32-C3 SuperMini (external antenna)
 *
 * Hardware:
 *   - ESP32-C3 SuperMini (external antenna)
 *   - GPIO 5 wired to the non-supply leg of the remote's button
 *   - Powered from car 12V via buck converter to 3.3V (also powers remote)
 *
 * Power optimisations (ESP-IDF):
 *   - Wi-Fi fully excluded at build time (CONFIG_ESP_WIFI_ENABLED=n)
 *   - DFS: CPU scales 80 MHz <-> 10 MHz automatically via PM framework
 *   - Auto light sleep: CPU enters light sleep during FreeRTOS tickless
 *     idle (~2-5 mA idle vs ~15-20 mA with Arduino framework)
 *   - NimBLE modem sleep cooperates with PM light sleep
 *   - USB-CDC console disabled in production (CONFIG_ESP_CONSOLE_NONE)
 *   - Button GPIO held in high-impedance (INPUT) at idle
 *   - Conservative advertising interval (1s)
 *   - Periodic restart every 3 hours (when idle)
 *
 * BLE GATT Service:
 *   - Challenge characteristic (read/notify): 16-byte random nonce
 *   - Command characteristic (write): 1-byte cmd type + 32-byte HMAC
 *   - Command Pt1/Pt2 (write): split-write path for low-MTU clients
 *   - Status characteristic (read/notify): result of last command
 *   - PSK Update characteristic (write): change PSK (requires auth)
 *
 * Build: ESP-IDF 5.1.x via PlatformIO (espressif32@6.13.0)
 * Board: ESP32-C3-DevKitM-1
 */

#include <string.h>
#include <stdio.h>

/* FreeRTOS */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ESP system */
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_pm.h"
#include "esp_sleep.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"

/* mbedTLS for HMAC-SHA256 */
#include "mbedtls/md.h"

/* BLE TX power control (NimBLE on C3) */
#include "esp_bt.h"

/* NimBLE */
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "CAR_UNLOCK";

/* ============================================================
 * Debug toggle
 * ============================================================
 * Define DEBUG to enable ESP_LOG output and keep USB console
 * active. Undefine for production (console disabled via
 * CONFIG_ESP_CONSOLE_NONE in sdkconfig.defaults).
 *
 * To enable: add -DDEBUG to build_flags in platformio.ini,
 * and override CONFIG_ESP_CONSOLE_NONE -> CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
 * and CONFIG_LOG_DEFAULT_LEVEL -> 3 in sdkconfig.defaults.
 */
/* #define DEBUG */

#ifdef DEBUG
#define LOG_I(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)
#define LOG_W(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
#define LOG_E(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
#else
#define LOG_I(tag, fmt, ...) do {} while(0)
#define LOG_W(tag, fmt, ...) do {} while(0)
#define LOG_E(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
#endif

/* ============================================================
 * Configuration
 * ============================================================ */

/* Default PSK - change this before flashing! 32+ chars recommended. */
#define DEFAULT_PSK "CHANGE_ME_before_flashing_32chars!"

/* ---- GPIO: Button ----
 * GPIO 5: no strapping function, clean digital I/O on C3 SuperMini.
 * Avoid: GPIO 2 (strapping), GPIO 8 (strapping/LED), GPIO 9 (boot btn),
 *        GPIO 18/19 (USB-CDC needed for flashing). */
#define BUTTON_GPIO GPIO_NUM_5

/* Button trigger polarity:
 *   true  = button connects encoder input to VCC (active HIGH)
 *   false = button connects encoder input to GND (active LOW) */
#define BUTTON_ACTIVE_HIGH true

/* Button press pulse duration in milliseconds */
#define BUTTON_PULSE_MS 300

/* ---- Debug LED (compile-time flag) ----
 * GPIO 8 is the onboard LED on most C3 SuperMini boards.
 * Comment out for production. */
/* #define DEBUG_LED_ENABLED */
/* #define DEBUG_LED_GPIO GPIO_NUM_8 */

/* ---- BLE ---- */
#define BLE_DEVICE_NAME "BLE-Device"

/* BLE TX power in dBm. 3 dBm good for car cabin with external antenna. */
#define BLE_TX_POWER 3

/* BLE advertising interval (in 0.625ms units).
 * 1600 = 1000ms, 3200 = 2000ms. Giving a range lets the
 * controller jitter the interval for better coexistence
 * and reduced peak current from synchronized wake-ups. */
#define ADV_INTERVAL_MIN 1600
#define ADV_INTERVAL_MAX 3200

/* Max simultaneous BLE connections */
#define MAX_CONNECTIONS 3

/* Auto-disconnect timeouts (seconds) */
#define UNAUTH_TIMEOUT_SEC 15
#define AUTH_TIMEOUT_SEC   300

/* Periodic restart interval (seconds). 3 hours = 10800s. */
#define RESTART_INTERVAL_SEC 10800

/* Hard restart: force restart after this many seconds regardless
 * of connection state. Guards against slow memory leaks or NimBLE
 * state drift. 24 hours = 86400s. */
#define HARD_RESTART_SEC 86400

/* ---- Crypto ---- */
#define HMAC_LEN  32
#define NONCE_LEN 16

/* Command type prefixes */
#define CMD_AUTH_ONLY 0x01
#define CMD_PRESS     0x02

/* Max PSK length */
#define MAX_PSK_LEN 128

/* Loop tick interval in ms. 10s is sufficient for timeout checks
 * (15s minimum granularity) and ghost reaping, while letting the
 * CPU stay in light sleep for longer stretches. */
#define LOOP_INTERVAL_MS 10000

/* Task watchdog timeout in seconds. Must exceed LOOP_INTERVAL_MS
 * to avoid false triggers during normal sleep. */
#define WDT_TIMEOUT_SEC 30

/* ---- Power Management ----
 * DFS frequency limits (MHz). CPU scales between these automatically.
 * 80 MHz = PLL clock, 10 MHz = lowest stable with NimBLE active. */
#define PM_MAX_FREQ_MHZ 80
#define PM_MIN_FREQ_MHZ 10

/* ============================================================
 * UUIDs
 * ============================================================
 * NimBLE native API uses ble_uuid128_t structs.
 * Bytes are in REVERSE order (little-endian). */

/* Helper: define a 128-bit UUID from the standard string representation.
 * "a1b2c3d4-e5f6-7890-abcd-ef12345678XX" */
#define UUID128_INIT(b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15) \
    { .u = { .type = BLE_UUID_TYPE_128 }, \
      .value = { b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15 } }

/* Base: a1b2c3d4-e5f6-7890-abcd-ef1234567890 */
static const ble_uuid128_t service_uuid =
    UUID128_INIT(0x90,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7891 */
static const ble_uuid128_t challenge_uuid =
    UUID128_INIT(0x91,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7892 */
static const ble_uuid128_t command_uuid =
    UUID128_INIT(0x92,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7893 */
static const ble_uuid128_t status_uuid =
    UUID128_INIT(0x93,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7894 */
static const ble_uuid128_t psk_update_uuid =
    UUID128_INIT(0x94,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7895 */
static const ble_uuid128_t command_pt1_uuid =
    UUID128_INIT(0x95,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7896 */
static const ble_uuid128_t command_pt2_uuid =
    UUID128_INIT(0x96,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ============================================================
 * Globals
 * ============================================================ */

static uint8_t current_nonce[NONCE_LEN];
static char    current_psk[MAX_PSK_LEN + 1];

/* GATT attribute handles (populated by NimBLE after registration) */
static uint16_t challenge_val_handle;
static uint16_t status_val_handle;

/* Status string (persists between reads) */
static char status_str[32] = "READY";

typedef struct {
    uint16_t conn_handle;
    bool     in_use;
    bool     authenticated;
    int64_t  connected_at;  /* milliseconds from now_ms() */
} client_state_t;

static client_state_t clients[MAX_CONNECTIONS];

/* Split command buffer for low-MTU clients (Garmin watches) */
typedef struct {
    bool     has_part1;
    uint8_t  cmd_type;
    uint8_t  hmac_part1[16];
    uint16_t conn_handle;
    int64_t  part1_time;  /* milliseconds from now_ms() */
} split_cmd_state_t;

static split_cmd_state_t split_cmd = {0};

/* Track whether advertising is currently active */
static bool adv_active = false;

/* Non-blocking button press: one-shot timer releases the GPIO */
static esp_timer_handle_t button_timer = NULL;
static bool button_busy = false;

/* ============================================================
 * Forward declarations
 * ============================================================ */
static void start_advertising(void);
static void generate_nonce(void);
static struct os_mbuf *om_from_buf(const void *buf, uint16_t len);
static int  gap_event_handler(struct ble_gap_event *event, void *arg);

/* ============================================================
 * Utility: time helpers
 * ============================================================ */

static inline int64_t now_ms(void) {
    return esp_timer_get_time() / 1000;
}

/* ============================================================
 * GPIO: button control
 * ============================================================ */

static void gpio_init_button(void) {
    /* INPUT (high-impedance) at boot.
     * The remote's encoder pull-down holds the line low = not pressed.
     * This draws zero current through the ESP32 GPIO. */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BUTTON_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
}

static void button_timer_callback(void *arg) {
    /* Return to high-impedance idle (zero quiescent current) */
    gpio_set_direction(BUTTON_GPIO, GPIO_MODE_INPUT);

#ifdef DEBUG_LED_ENABLED
    gpio_set_level(DEBUG_LED_GPIO, 0);
#endif

    button_busy = false;
}

static bool press_remote_button(void) {
    if (button_busy) return false;  /* press already in progress */
    button_busy = true;

    /* Drive to active state */
    gpio_set_direction(BUTTON_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(BUTTON_GPIO, BUTTON_ACTIVE_HIGH ? 1 : 0);

#ifdef DEBUG_LED_ENABLED
    gpio_set_level(DEBUG_LED_GPIO, 1);
#endif

    /* Release after BUTTON_PULSE_MS via one-shot timer (non-blocking) */
    esp_err_t err = esp_timer_start_once(button_timer, (uint64_t)BUTTON_PULSE_MS * 1000);
    if (err != ESP_OK) {
        /* Timer failed — release GPIO immediately to avoid stuck press */
        gpio_set_direction(BUTTON_GPIO, GPIO_MODE_INPUT);
        button_busy = false;
        LOG_E(TAG, "Button timer start failed: %s", esp_err_to_name(err));
        return false;
    }
    return true;
}

#ifdef DEBUG_LED_ENABLED
static void gpio_init_led(void) {
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << DEBUG_LED_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(DEBUG_LED_GPIO, 0);
}
#endif

#ifndef DEBUG_LED_ENABLED
static void park_led_pin(void) {
    /* Park GPIO 8 (LED) to 0V to prevent leakage current */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << GPIO_NUM_8),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(GPIO_NUM_8, 0);
}
#endif

/* ============================================================
 * NVS: PSK storage
 * ============================================================ */

static void load_psk(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("car_unlock", NVS_READONLY, &handle);
    if (err == ESP_OK) {
        size_t len = MAX_PSK_LEN;
        err = nvs_get_str(handle, "psk", current_psk, &len);
        nvs_close(handle);
        /* len includes null terminator, so len > 1 means non-empty */
        if (err == ESP_OK && len > 1) {
            LOG_I(TAG, "PSK loaded from NVS (%d chars)", (int)len);
            return;
        }
    }

    /* Fall back to default PSK */
    strncpy(current_psk, DEFAULT_PSK, MAX_PSK_LEN);
    current_psk[MAX_PSK_LEN] = '\0';
    LOG_W(TAG, "Using default PSK");
}

static bool save_psk(const char *new_psk) {
    nvs_handle_t handle;
    bool persisted = false;
    esp_err_t err = nvs_open("car_unlock", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, "psk", new_psk);
        if (err == ESP_OK) {
            err = nvs_commit(handle);
            if (err == ESP_OK) {
                persisted = true;
            }
        }
        nvs_close(handle);
    }
    if (!persisted) {
        LOG_E(TAG, "NVS PSK write failed: %s", esp_err_to_name(err));
    }

    /* Always update in-memory PSK so current session works */
    strncpy(current_psk, new_psk, MAX_PSK_LEN);
    current_psk[MAX_PSK_LEN] = '\0';
    return persisted;
}

/* ============================================================
 * Power management: DFS + auto light sleep
 * ============================================================ */

static void configure_power_management(void) {
    esp_pm_config_t pm_config = {
        .max_freq_mhz = PM_MAX_FREQ_MHZ,
        .min_freq_mhz = PM_MIN_FREQ_MHZ,
        .light_sleep_enable = true,
    };

    esp_err_t err = esp_pm_configure(&pm_config);
    if (err == ESP_OK) {
        LOG_I(TAG, "PM configured: DFS %d-%d MHz, light sleep enabled",
              PM_MIN_FREQ_MHZ, PM_MAX_FREQ_MHZ);
    } else {
        LOG_E(TAG, "PM configure failed: %s", esp_err_to_name(err));
    }
}

/* ============================================================
 * Crypto: HMAC-SHA256
 * ============================================================ */

static bool compute_hmac(const uint8_t *nonce, size_t nonce_len,
                         const char *key, uint8_t *out_hmac) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0)    goto fail;
    if (mbedtls_md_hmac_starts(&ctx, (const uint8_t *)key, strlen(key)) != 0) goto fail;
    if (mbedtls_md_hmac_update(&ctx, nonce, nonce_len) != 0)                  goto fail;
    if (mbedtls_md_hmac_finish(&ctx, out_hmac) != 0)                          goto fail;
    mbedtls_md_free(&ctx);
    return true;

fail:
    mbedtls_md_free(&ctx);
    return false;
}

/* ============================================================
 * Client state management
 * ============================================================ */

static int find_client_slot(void) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].in_use) return i;
    }
    return -1;
}

static int find_client_by_handle(uint16_t conn_handle) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (clients[i].in_use && clients[i].conn_handle == conn_handle) return i;
    }
    return -1;
}

static void mark_authenticated(uint16_t conn_handle) {
    int slot = find_client_by_handle(conn_handle);
    if (slot >= 0) {
        clients[slot].authenticated = true;
    }
}

static int count_active_slots(void) {
    int count = 0;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (clients[i].in_use) count++;
    }
    return count;
}

static void invalidate_split_cmd_for(uint16_t conn_handle) {
    if (split_cmd.has_part1 && split_cmd.conn_handle == conn_handle) {
        split_cmd.has_part1 = false;
    }
}

/* ============================================================
 * BLE: nonce & status helpers
 * ============================================================ */

static void generate_nonce(void) {
    esp_fill_random(current_nonce, NONCE_LEN);

    /* Notify subscribed clients of new nonce */
    struct ble_gap_conn_desc desc;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].in_use) continue;
        if (ble_gap_conn_find(clients[i].conn_handle, &desc) == 0) {
            ble_gatts_notify_custom(clients[i].conn_handle,
                                    challenge_val_handle,
                                    om_from_buf(current_nonce, NONCE_LEN));
        }
    }
}

/* Helper: create an mbuf from a buffer */
static struct os_mbuf *om_from_buf(const void *buf, uint16_t len) {
    struct os_mbuf *om = ble_hs_mbuf_from_flat(buf, len);
    return om;
}

static void set_status(const char *msg) {
    strncpy(status_str, msg, sizeof(status_str) - 1);
    status_str[sizeof(status_str) - 1] = '\0';

    /* Notify subscribed clients */
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].in_use) continue;
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(clients[i].conn_handle, &desc) == 0) {
            ble_gatts_notify_custom(clients[i].conn_handle,
                                    status_val_handle,
                                    om_from_buf(status_str, strlen(status_str)));
        }
    }
}

/**
 * Verify HMAC payload against current nonce and PSK.
 * Always rotates the nonce afterwards (even on failure) to prevent replay.
 */
static bool verify_auth(const uint8_t *payload, size_t len) {
    if (len != HMAC_LEN) return false;

    uint8_t expected[HMAC_LEN];
    if (!compute_hmac(current_nonce, NONCE_LEN, current_psk, expected)) {
        generate_nonce();
        return false;
    }

    /* Constant-time comparison to prevent timing side-channels */
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_LEN; i++) {
        diff |= payload[i] ^ expected[i];
    }

    generate_nonce();  /* rotate unconditionally */
    return (diff == 0);
}

/* ============================================================
 * GATT access callbacks
 * ============================================================ */

/* Challenge characteristic: read returns current nonce */
static int chr_access_challenge(uint16_t conn_handle, uint16_t attr_handle,
                                struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int rc = os_mbuf_append(ctxt->om, current_nonce, NONCE_LEN);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* Status characteristic: read returns current status string */
static int chr_access_status(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int rc = os_mbuf_append(ctxt->om, status_str, strlen(status_str));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* Command characteristic: write with full 33-byte payload (1 cmd + 32 HMAC) */
static int chr_access_command(uint16_t conn_handle, uint16_t attr_handle,
                              struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len < 1 || len > 33) {
        set_status("ERR:EMPTY");
        return 0;
    }

    uint8_t buf[33];
    os_mbuf_copydata(ctxt->om, 0, len, buf);

    uint8_t cmd_type = buf[0];
    const uint8_t *hmac_payload = buf + 1;
    size_t hmac_len = len - 1;

    if (cmd_type != CMD_AUTH_ONLY && cmd_type != CMD_PRESS) {
        set_status("ERR:UNKNOWN_CMD");
        return 0;
    }

    if (verify_auth(hmac_payload, hmac_len)) {
        mark_authenticated(conn_handle);
        if (cmd_type == CMD_PRESS) {
            set_status(press_remote_button() ? "OK:PRESSED" : "ERR:BUSY");
        } else {
            set_status("OK:AUTH");
        }
    } else {
        set_status("ERR:AUTH");
    }
    return 0;
}

/* Command Part 1: first 17 bytes (1 cmd + 16 HMAC part 1) */
static int chr_access_command_pt1(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len != 17) {
        set_status("ERR:PT1_LEN");
        return 0;
    }

    uint8_t buf[17];
    os_mbuf_copydata(ctxt->om, 0, len, buf);

    split_cmd.cmd_type    = buf[0];
    memcpy(split_cmd.hmac_part1, buf + 1, 16);
    split_cmd.has_part1   = true;
    split_cmd.conn_handle = conn_handle;
    split_cmd.part1_time  = now_ms();

    return 0;
}

/* Command Part 2: last 16 bytes of HMAC, reassemble and verify */
static int chr_access_command_pt2(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len != 16) {
        split_cmd.has_part1 = false;
        set_status("ERR:PT2_LEN");
        return 0;
    }

    if (!split_cmd.has_part1) {
        set_status("ERR:NO_PT1");
        return 0;
    }

    if (split_cmd.conn_handle != conn_handle) {
        split_cmd.has_part1 = false;
        set_status("ERR:CONN_MISMATCH");
        return 0;
    }

    /* Timeout: part 2 must arrive within 5 seconds of part 1 */
    if (now_ms() - split_cmd.part1_time > 5000) {
        split_cmd.has_part1 = false;
        set_status("ERR:TIMEOUT");
        return 0;
    }

    uint8_t buf[16];
    os_mbuf_copydata(ctxt->om, 0, 16, buf);

    /* Reassemble full HMAC */
    uint8_t full_hmac[HMAC_LEN];
    memcpy(full_hmac, split_cmd.hmac_part1, 16);
    memcpy(full_hmac + 16, buf, 16);
    uint8_t cmd_type = split_cmd.cmd_type;
    split_cmd.has_part1 = false;

    if (cmd_type != CMD_AUTH_ONLY && cmd_type != CMD_PRESS) {
        set_status("ERR:UNKNOWN_CMD");
        return 0;
    }

    if (verify_auth(full_hmac, HMAC_LEN)) {
        mark_authenticated(conn_handle);
        if (cmd_type == CMD_PRESS) {
            set_status(press_remote_button() ? "OK:PRESSED" : "ERR:BUSY");
        } else {
            set_status("OK:AUTH");
        }
    } else {
        set_status("ERR:AUTH");
    }
    return 0;
}

/* PSK Update characteristic: write with [HMAC(32)] [0x00] [newPSK] */
static int chr_access_psk_update(uint16_t conn_handle, uint16_t attr_handle,
                                 struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len > HMAC_LEN + 1 + MAX_PSK_LEN) {
        set_status("ERR:PSK_FORMAT");
        return 0;
    }

    uint8_t buf[HMAC_LEN + 1 + MAX_PSK_LEN];
    os_mbuf_copydata(ctxt->om, 0, len, buf);

    /* The separator must be at exactly position HMAC_LEN (byte 32).
     * Bytes 0..31 are the HMAC (which can legitimately contain 0x00),
     * byte 32 must be 0x00, and the rest is the new PSK. */
    if (len < HMAC_LEN + 2 || buf[HMAC_LEN] != 0x00) {
        set_status("ERR:PSK_FORMAT");
        return 0;
    }

    int sep_idx = HMAC_LEN;

    if (!verify_auth(buf, sep_idx)) {
        set_status("ERR:PSK_AUTH");
        return 0;
    }

    size_t new_psk_len = len - sep_idx - 1;
    if (new_psk_len == 0 || new_psk_len > MAX_PSK_LEN) {
        set_status("ERR:PSK_LENGTH");
        return 0;
    }

    char new_psk[MAX_PSK_LEN + 1];
    memcpy(new_psk, buf + sep_idx + 1, new_psk_len);
    new_psk[new_psk_len] = '\0';

    bool persisted = save_psk(new_psk);
    mark_authenticated(conn_handle);
    set_status(persisted ? "OK:PSK_UPDATED" : "WARN:PSK_VOLATILE");
    return 0;
}

/* ============================================================
 * GATT service definition
 * ============================================================ */

static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &service_uuid.u,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                /* Challenge: read + notify */
                .uuid       = &challenge_uuid.u,
                .access_cb  = chr_access_challenge,
                .val_handle = &challenge_val_handle,
                .flags      = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            },
            {
                /* Command: write (full 33-byte).
                 * WRITE_NO_RSP lets clients choose lower-latency writes. */
                .uuid       = &command_uuid.u,
                .access_cb  = chr_access_command,
                .flags      = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
            },
            {
                /* Status: read + notify */
                .uuid       = &status_uuid.u,
                .access_cb  = chr_access_status,
                .val_handle = &status_val_handle,
                .flags      = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            },
            {
                /* PSK Update: write */
                .uuid       = &psk_update_uuid.u,
                .access_cb  = chr_access_psk_update,
                .flags      = BLE_GATT_CHR_F_WRITE,
            },
            {
                /* Command Part 1: write */
                .uuid       = &command_pt1_uuid.u,
                .access_cb  = chr_access_command_pt1,
                .flags      = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
            },
            {
                /* Command Part 2: write */
                .uuid       = &command_pt2_uuid.u,
                .access_cb  = chr_access_command_pt2,
                .flags      = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
            },
            { 0 }, /* Terminator */
        },
    },
    { 0 }, /* Terminator */
};

/* ============================================================
 * GAP event handler
 * ============================================================ */

static int gap_event_handler(struct ble_gap_event *event, void *arg) {
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT: {
        uint16_t conn_handle = event->connect.conn_handle;

        if (event->connect.status != 0) {
            /* Connection failed, restart advertising */
            LOG_W(TAG, "Connect failed, status=%d", event->connect.status);
            start_advertising();
            return 0;
        }

        int slot = find_client_slot();
        if (slot >= 0) {
            clients[slot].in_use        = true;
            clients[slot].authenticated = false;
            clients[slot].connected_at  = now_ms();
            clients[slot].conn_handle   = conn_handle;
            LOG_I(TAG, "Client connected, slot %d, handle %d", slot, conn_handle);
        } else {
            /* No free slots, disconnect immediately */
            LOG_W(TAG, "No free slots, disconnecting handle %d", conn_handle);
            ble_gap_terminate(conn_handle, BLE_ERR_CONN_LIMIT);
            return 0;
        }

        /* Tighten link supervision: 4s timeout.
         * Params: min_itvl, max_itvl (1.25ms units), latency,
         *         supervision_timeout (10ms units) */
        struct ble_gap_upd_params params = {
            .itvl_min            = 24,   /* 30ms */
            .itvl_max            = 48,   /* 60ms */
            .latency             = 0,
            .supervision_timeout = 400,  /* 4s */
            .min_ce_len          = 0,
            .max_ce_len          = 0,
        };
        ble_gap_update_params(conn_handle, &params);

        generate_nonce();

        /* Continue advertising if we have capacity */
        if (count_active_slots() < MAX_CONNECTIONS) {
            start_advertising();
        } else {
            adv_active = false;
        }
        break;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        uint16_t conn_handle = event->disconnect.conn.conn_handle;
        LOG_I(TAG, "Disconnect handle %d, reason 0x%02x",
              conn_handle, event->disconnect.reason);

        int slot = find_client_by_handle(conn_handle);
        if (slot >= 0) {
            clients[slot].in_use        = false;
            clients[slot].authenticated = false;
        }

        invalidate_split_cmd_for(conn_handle);

        /* Always restart advertising after disconnect */
        start_advertising();
        break;
    }

    case BLE_GAP_EVENT_ADV_COMPLETE:
        LOG_I(TAG, "Advertising complete");
        adv_active = false;
        /* Restart if we have capacity */
        if (count_active_slots() < MAX_CONNECTIONS) {
            start_advertising();
        }
        break;

    case BLE_GAP_EVENT_MTU:
        LOG_I(TAG, "MTU update: conn_handle=%d, mtu=%d",
              event->mtu.conn_handle, event->mtu.value);
        break;

    case BLE_GAP_EVENT_SUBSCRIBE:
        LOG_I(TAG, "Subscribe: conn_handle=%d, attr_handle=%d",
              event->subscribe.conn_handle, event->subscribe.attr_handle);
        break;

    default:
        break;
    }

    return 0;
}

/* ============================================================
 * BLE advertising
 * ============================================================ */

static void start_advertising(void) {
    struct ble_gap_adv_params adv_params = {0};
    struct ble_hs_adv_fields fields = {0};
    struct ble_hs_adv_fields rsp_fields = {0};

    /* Advertising data: flags + service UUID */
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = &service_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        LOG_E(TAG, "adv_set_fields failed: %d", rc);
        return;
    }

    /* Scan response: device name */
    rsp_fields.name = (uint8_t *)BLE_DEVICE_NAME;
    rsp_fields.name_len = strlen(BLE_DEVICE_NAME);
    rsp_fields.name_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        LOG_E(TAG, "adv_rsp_set_fields failed: %d", rc);
        return;
    }

    /* Advertising parameters */
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;  /* undirected connectable */
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;  /* general discoverable */
    adv_params.itvl_min  = ADV_INTERVAL_MIN;
    adv_params.itvl_max  = ADV_INTERVAL_MAX;

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, gap_event_handler, NULL);
    if (rc == 0) {
        adv_active = true;
        LOG_I(TAG, "Advertising started");
    } else if (rc == BLE_HS_EALREADY) {
        adv_active = true;  /* already advertising */
    } else {
        LOG_E(TAG, "adv_start failed: %d", rc);
    }
}

/* ============================================================
 * BLE host task + sync callback
 * ============================================================ */

static void ble_on_sync(void) {
    /* Make sure we have a public address */
    int rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    /* Set preferred MTU */
    rc = ble_att_set_preferred_mtu(185);
    if (rc != 0) {
        LOG_W(TAG, "Failed to set preferred MTU: %d", rc);
    }

    /* Set TX power */
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P3);

    start_advertising();
    LOG_I(TAG, "BLE synced, advertising started (TX %d dBm, interval %d ms)",
          BLE_TX_POWER, (ADV_INTERVAL_MAX * 625) / 1000);
}

static void ble_on_reset(int reason) {
    LOG_E(TAG, "BLE host reset, reason=%d", reason);
}

static void nimble_host_task(void *param) {
    /* This function returns only when nimble_port_stop() is called */
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* ============================================================
 * Main loop task: ghost reaper, timeouts, periodic restart
 * ============================================================ */

static void main_loop_task(void *param) {
    /* Subscribe this task to the task watchdog */
    esp_task_wdt_add(NULL);
    LOG_I(TAG, "Main loop started, WDT subscribed");

    while (1) {
        esp_task_wdt_reset();
        int64_t now = now_ms();

        /* ---- Ghost slot reaper ----
         * If we have more in_use slots than NimBLE has active connections,
         * at least one slot is orphaned. Find and free them. */
        int nimble_count = 0;

        /* Count actual NimBLE connections by probing handles */
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!clients[i].in_use) continue;
            struct ble_gap_conn_desc desc;
            if (ble_gap_conn_find(clients[i].conn_handle, &desc) != 0) {
                /* Handle no longer valid in NimBLE — ghost slot */
                LOG_I(TAG, "Reaped ghost slot %d (handle %d)",
                      i, clients[i].conn_handle);
                invalidate_split_cmd_for(clients[i].conn_handle);
                clients[i].in_use = false;
                clients[i].authenticated = false;
            } else {
                nimble_count++;
            }
        }

        /* If we freed slots and aren't at capacity, re-enable advertising */
        if (nimble_count < MAX_CONNECTIONS && !adv_active) {
            start_advertising();
        }

        /* ---- Client timeout check ---- */
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!clients[i].in_use) continue;

            int64_t elapsed = now - clients[i].connected_at;
            int64_t timeout = clients[i].authenticated
                ? (int64_t)AUTH_TIMEOUT_SEC * 1000
                : (int64_t)UNAUTH_TIMEOUT_SEC * 1000;

            if (elapsed > timeout) {
                LOG_I(TAG, "Timeout slot %d (handle %d, auth=%d)",
                      i, clients[i].conn_handle, clients[i].authenticated);

                /* Force-free slot BEFORE disconnect */
                uint16_t handle = clients[i].conn_handle;
                clients[i].in_use = false;
                clients[i].authenticated = false;
                invalidate_split_cmd_for(handle);

                /* Ask NimBLE to tear down the link */
                ble_gap_terminate(handle, BLE_ERR_CONN_TERM_LOCAL);
            }
        }

        /* ---- Periodic restart (only when idle) ---- */
        if (now > (int64_t)RESTART_INTERVAL_SEC * 1000 && count_active_slots() == 0) {
            LOG_I(TAG, "Periodic restart (no active connections)");
            vTaskDelay(pdMS_TO_TICKS(50));  /* allow log flush */
            esp_restart();
        }

        /* ---- Hard restart (unconditional, guards against long-running drift) ---- */
        if (now > (int64_t)HARD_RESTART_SEC * 1000) {
            LOG_E(TAG, "Hard restart after %d hours", HARD_RESTART_SEC / 3600);
            vTaskDelay(pdMS_TO_TICKS(50));
            esp_restart();
        }

        vTaskDelay(pdMS_TO_TICKS(LOOP_INTERVAL_MS));
    }
}

/* ============================================================
 * app_main: entry point
 * ============================================================ */

void app_main(void) {
    LOG_I(TAG, "ESP32-C3 BLE Car Unlock starting...");

    /* ---- GPIO init ---- */
    gpio_init_button();

    /* ---- Button release timer (non-blocking pulse) ---- */
    const esp_timer_create_args_t btn_timer_args = {
        .callback = button_timer_callback,
        .name     = "btn_release",
    };
    ESP_ERROR_CHECK(esp_timer_create(&btn_timer_args, &button_timer));

#ifdef DEBUG_LED_ENABLED
    gpio_init_led();
#else
    park_led_pin();
#endif

    /* ---- Client state init ---- */
    memset(clients, 0, sizeof(clients));

    /* ---- Power management: DFS + auto light sleep ---- */
    configure_power_management();

    /* ---- NVS init ---- */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* ---- Load PSK ---- */
    load_psk();

    /* ---- Generate initial nonce ---- */
    esp_fill_random(current_nonce, NONCE_LEN);

    /* ---- Init NimBLE ---- */
    ret = nimble_port_init();
    assert(ret == ESP_OK);

    /* Configure NimBLE host */
    ble_hs_cfg.sync_cb  = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;

    /* Set device name for GAP */
    ble_svc_gap_device_name_set(BLE_DEVICE_NAME);

    /* Register mandatory GAP and GATT services */
    ble_svc_gap_init();
    ble_svc_gatt_init();

    /* Register our GATT services */
    int rc = ble_gatts_count_cfg(gatt_svcs);
    assert(rc == 0);
    rc = ble_gatts_add_svcs(gatt_svcs);
    assert(rc == 0);

    /* ---- Task watchdog ---- */
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms  = WDT_TIMEOUT_SEC * 1000,
        .idle_core_mask = 0,       /* don't watch idle task */
        .trigger_panic = true,
    };
    esp_task_wdt_reconfigure(&wdt_config);
    LOG_I(TAG, "Task watchdog configured (%ds)", WDT_TIMEOUT_SEC);

    /* ---- Start NimBLE host task ---- */
    nimble_port_freertos_init(nimble_host_task);

    /* ---- Start main loop task ----
     * Stack: 4096 bytes is plenty for ghost reaper + timeout logic.
     * Priority 5: above tIDLE(0) but below NimBLE host task. */
    xTaskCreate(main_loop_task, "main_loop", 4096, NULL, 5, NULL);
}
