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
 *   - Wi-Fi is never initialized; only the BLE radio is active at runtime
 *   - DFS: CPU scales 80 MHz <-> 10 MHz automatically via PM framework
 *   - Automatic light sleep requested; actual savings depend on radio locks
 *   - BLE modem sleep remains disabled for connection reliability
 *   - USB-CDC console disabled in production (CONFIG_ESP_CONSOLE_NONE)
 *   - Button GPIO held in high-impedance (INPUT) at idle
 *   - Advertising: 50-100ms fast window, 200-400ms afterwards
 *   - Periodic restart every 3 hours (when idle)
 *
 * BLE GATT Service:
 *   - Challenge characteristic (read/notify): 16-byte random nonce
 *   - Command characteristic (write): 1-byte cmd type + 32-byte HMAC
 *   - Command Pt1/Pt2 (write): split-write path for low-MTU clients
 *   - Status characteristic (read/notify): result of last command
 *   - PSK Update characteristic (write): change PSK (requires auth)
 *
 * Build: ESP-IDF 6.0.1 via PlatformIO (espressif32@7.0.1)
 * Board: ESP32-C3-DevKitM-1
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

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
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "ota_health.h"
#include "device_health.h"
#include "radio_config.h"
#include "esp_partition.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"

/* PSA Crypto for HMAC-SHA256 (ESP-IDF 6 / mbedTLS 4 public API) */
#include "psa/crypto.h"
#include "psk_update.h"

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
 * Define DEBUG to enable ESP_LOG output and a USB console. Undefine for
 * production (both console routes and the application USB Serial/JTAG
 * controller are disabled via sdkconfig.defaults).
 *
 * To enable: add -DDEBUG to build_flags in platformio.ini,
 * enable CONFIG_USJ_ENABLE_USB_SERIAL_JTAG, override CONFIG_ESP_CONSOLE_NONE
 * -> CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG, and set
 * CONFIG_LOG_DEFAULT_LEVEL -> 3 in sdkconfig.defaults.
 */
/* #define DEBUG */

#ifdef DEBUG
#define LOG_I(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)
#define LOG_W(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
#define LOG_E(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
#else
/* Production has no console, so compile application log formatting out too. */
#define LOG_I(tag, fmt, ...) do { (void)(tag); } while (0)
#define LOG_W(tag, fmt, ...) do { (void)(tag); } while (0)
#define LOG_E(tag, fmt, ...) do { (void)(tag); } while (0)
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

/* BLE advertising intervals (in 0.625ms units).
 * Fast mode improves Garmin discovery after boot/disconnect/activity.
 * Idle mode stays responsive enough for short Garmin scan windows while
 * remaining substantially less active than the reconnect burst. */
/* Defaults remain 50-100ms recent, 200-400ms idle, with a 60-second window.
 * Authenticated app settings may override them; see radio_config.h. */
static radio_config_t radio_config = RADIO_DEFAULTS;
static bool radio_config_persisted = false;

/* Max simultaneous BLE connections */
#define MAX_CONNECTIONS 3

/* Auto-disconnect timeouts (seconds) */
#define UNAUTH_TIMEOUT_SEC 20
#define AUTH_TIMEOUT_SEC   1800
#define MAX_AUTH_FAILURES 5

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
#define CMD_PSK_UPDATE 0x03
#define COMMAND_AUTH_DOMAIN "BLEKEY-V2"
#define COMMAND_DEVICE_BINDING "car-main"

/* Max PSK length */
#define MAX_PSK_LEN 128

/* Loop tick interval in ms. 10s is sufficient for timeout checks
 * (15s minimum granularity) and ghost reaping, while letting the
 * CPU stay in light sleep for longer stretches. */
#define LOOP_INTERVAL_MS 10000

/* Task watchdog timeout in seconds. Must exceed LOOP_INTERVAL_MS
 * to avoid false triggers during normal sleep. */
#define WDT_TIMEOUT_SEC 30

/* BLE host heartbeat: the maintenance task posts an event to NimBLE's own
 * queue every LOOP_INTERVAL_MS. Five missed acknowledgements means the host
 * event loop has stopped making progress and the safest recovery is a reboot. */
#define BLE_HEALTH_MAX_MISSED_HEARTBEATS 5
#define BLE_ADV_HEALTH_MAX_FAILURES 3

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

/* ...7897: stable device identity/capabilities */
static const ble_uuid128_t identity_uuid =
    UUID128_INIT(0x97,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ...7898 / ...7899 / ...789a: authenticated BLE OTA */
static const ble_uuid128_t ota_control_uuid =
    UUID128_INIT(0x98,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);
static const ble_uuid128_t ota_data_uuid =
    UUID128_INIT(0x99,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);
static const ble_uuid128_t ota_status_uuid =
    UUID128_INIT(0x9a,0x78,0x56,0x34,0x12,0xef,0xcd,0xab,
                 0x90,0x78,0xf6,0xe5,0xd4,0xc3,0xb2,0xa1);

/* ============================================================
 * Globals
 * ============================================================ */

static char    current_psk[MAX_PSK_LEN + 1];

/* GATT attribute handles (populated by NimBLE after registration) */
static uint16_t challenge_val_handle;
static uint16_t status_val_handle;
static uint16_t ota_status_val_handle;

static char ota_status_str[32] = "OTA:IDLE";

#define OTA_OP_START 0x01
#define OTA_OP_FINISH 0x02
#define OTA_OP_ABORT 0x03
#define OTA_START_LEN (1 + 4 + 32 + HMAC_LEN)
#define OTA_AUTH_DOMAIN "BLEKEY-OTA1"
#define OTA_MAX_IMAGE_SIZE (0x1e0000)

typedef struct {
    bool active;
    bool hash_started;
    uint16_t conn_handle;
    esp_ota_handle_t handle;
    const esp_partition_t *partition;
    uint32_t expected_size;
    uint32_t received;
    uint8_t expected_sha256[32];
    psa_hash_operation_t hash_operation;
} ota_session_t;

static ota_session_t ota_session;
static esp_timer_handle_t ota_reboot_timer = NULL;

typedef struct {
    uint16_t conn_handle;
    bool     in_use;
    bool     authenticated;
    bool     closing;
    uint8_t  nonce[NONCE_LEN];
    int64_t  connected_at;
    uint8_t  auth_failures;
    char     status[PSK2_RECEIPT_SIZE];
    int64_t  last_activity_at;  /* milliseconds from now_ms() */
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

static split_cmd_state_t split_cmds[MAX_CONNECTIONS];

/* Track whether advertising is currently active */
static bool adv_active = false;
static uint8_t adv_failure_count = 0;
static bool adv_using_fast_interval = false;
static int64_t fast_adv_until_ms = 0;
static bool task_wdt_enabled = false;
static volatile bool task_wdt_monitored = false;
static struct ble_npl_event ble_health_event;
static struct ble_npl_callout slow_adv_callout;
static volatile uint32_t ble_heartbeat_ack_count = 0;
static uint8_t adv_health_failure_count = 0;
static bool ble_synced = false;
static bool ota_pending_verify = false;
static ota_health_t ota_health;
static uint32_t adv_recoveries = 0;
static uint32_t ghost_reaps = 0;

/* Retain a small reason code over software restarts without wearing NVS.
 * Ignore RTC contents after power loss, brownout, or a different reset type. */
enum reboot_cause { REBOOT_OTHER, REBOOT_OTA, REBOOT_PERIODIC, REBOOT_DAILY,
    REBOOT_BLE_RESET, REBOOT_BLE_EXIT, REBOOT_BLE_STALL, REBOOT_ADVERTISING,
    REBOOT_TASK, REBOOT_OTA_HEALTH };
static RTC_NOINIT_ATTR uint32_t reboot_magic;
static RTC_NOINIT_ATTR uint32_t reboot_cause;
static uint32_t previous_reboot_cause;

static void restart_with_reason(enum reboot_cause cause) {
    reboot_cause = cause;
    reboot_magic = 0x424c4831;
    esp_restart();
}

/* Non-blocking button press: one-shot timer releases the GPIO */
static esp_timer_handle_t button_timer = NULL;
static bool button_busy = false;

/* ============================================================
 * Forward declarations
 * ============================================================ */
static void start_advertising(void);
static void force_restart_advertising(void);
static void mark_ble_activity(void);
static int  count_active_slots(void);
static void log_client_state(const char *reason);
static void generate_nonce_for_slot(int slot, bool notify);
static int  ensure_client_slot(uint16_t conn_handle);
static struct os_mbuf *om_from_buf(const void *buf, uint16_t len);
static int  gap_event_handler(struct ble_gap_event *event, void *arg);
static void ble_health_event_callback(struct ble_npl_event *event);
static void ota_abort_session(void);
static void maintain_ble_state(void);

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
        size_t len = sizeof(current_psk);
        err = nvs_get_str(handle, "psk", current_psk, &len);
        nvs_close(handle);
        /* len includes null terminator, so len > 1 means non-empty */
        if (err == ESP_OK && len > 1) {
            LOG_I(TAG, "PSK loaded from NVS (%d chars)", (int)len);
            return;
        }
    }

    /* Only a genuinely unprovisioned device may use an explicitly customized
     * compile-time key. Never restore a public placeholder on storage errors. */
    current_psk[0] = '\0';
    if ((err == ESP_ERR_NVS_NOT_FOUND) &&
        strcmp(DEFAULT_PSK, "CHANGE_ME_before_flashing_32chars!") != 0) {
        strncpy(current_psk, DEFAULT_PSK, MAX_PSK_LEN);
        current_psk[MAX_PSK_LEN] = '\0';
    } else {
        LOG_E(TAG, "No valid provisioned PSK; remote commands disabled");
    }
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

    if (persisted) {
        strncpy(current_psk, new_psk, MAX_PSK_LEN);
        current_psk[MAX_PSK_LEN] = '\0';
    }
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
    const size_t key_len = strlen(key);
    const psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    size_t hmac_len = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

    psa_status_t status = psa_import_key(&attributes,
                                         (const uint8_t *)key, key_len,
                                         &key_id);
    if (status == PSA_SUCCESS) {
        status = psa_mac_compute(key_id, alg,
                                 nonce, nonce_len,
                                 out_hmac, HMAC_LEN,
                                 &hmac_len);
        psa_destroy_key(key_id);
    }
    psa_reset_key_attributes(&attributes);

    return status == PSA_SUCCESS && hmac_len == HMAC_LEN;
}

static void ble_health_event_callback(struct ble_npl_event *event) {
    (void)event;
    maintain_ble_state();
    ble_heartbeat_ack_count++;
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

static int ensure_client_slot(uint16_t conn_handle) {
    int slot = find_client_by_handle(conn_handle);
    if (slot >= 0) return clients[slot].closing ? -1 : slot;

    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn_handle, &desc) != 0) return -1;

    slot = find_client_slot();
    if (slot < 0) return -1;

    memset(&clients[slot], 0, sizeof(clients[slot]));
    clients[slot].in_use        = true;
    clients[slot].connected_at = now_ms();
    strcpy(clients[slot].status, "READY");
    clients[slot].authenticated = false;
    clients[slot].last_activity_at = now_ms();
    clients[slot].conn_handle   = conn_handle;
    generate_nonce_for_slot(slot, false);
    mark_ble_activity();
    LOG_W(TAG, "Repaired missing client slot %d for handle %d", slot, conn_handle);
    log_client_state("slot-repaired");

    if (count_active_slots() < MAX_CONNECTIONS) {
        start_advertising();
    }

    return slot;
}

static void mark_authenticated(uint16_t conn_handle) {
    int slot = find_client_by_handle(conn_handle);
    if (slot >= 0) {
        clients[slot].authenticated = true;
        clients[slot].auth_failures = 0;
        clients[slot].last_activity_at = now_ms();
    }
}

static int count_active_slots(void) {
    int count = 0;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (clients[i].in_use) count++;
    }
    return count;
}

static void log_client_state(const char *reason) {
    char slots[96];
    int used = snprintf(slots, sizeof(slots), "slots=");
    for (int i = 0; i < MAX_CONNECTIONS && used > 0 && used < (int)sizeof(slots); i++) {
        used += snprintf(slots + used, sizeof(slots) - used,
                         "%s%d:%s/h%d/auth%d",
                         i == 0 ? "" : ",",
                         i,
                         clients[i].in_use ? "used" : "free",
                         clients[i].conn_handle,
                         clients[i].authenticated ? 1 : 0);
    }
    LOG_I(TAG, "%s: active=%d adv=%d fast=%d split=%d %s",
          reason,
          count_active_slots(),
          adv_active ? 1 : 0,
          adv_using_fast_interval ? 1 : 0,
          (split_cmds[0].has_part1 || split_cmds[1].has_part1 ||
           split_cmds[2].has_part1) ? 1 : 0,
          slots);
}

static void invalidate_split_cmd_for(uint16_t conn_handle) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (split_cmds[i].has_part1 &&
            split_cmds[i].conn_handle == conn_handle) {
            split_cmds[i].has_part1 = false;
        }
    }
}

/* ============================================================
 * BLE: nonce & status helpers
 * ============================================================ */

static void generate_nonce_for_slot(int slot, bool notify) {
    if (slot < 0 || slot >= MAX_CONNECTIONS || !clients[slot].in_use) return;

    esp_fill_random(clients[slot].nonce, NONCE_LEN);
    if (!notify) return;

    /* Notify only this connection so other clients keep their own challenge. */
    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(clients[slot].conn_handle, &desc) == 0) {
        int rc = ble_gatts_notify_custom(clients[slot].conn_handle,
                                         challenge_val_handle,
                                         om_from_buf(clients[slot].nonce, NONCE_LEN));
        if (rc != 0) {
            LOG_W(TAG, "Challenge notify failed handle=%d rc=%d",
                  clients[slot].conn_handle, rc);
        }
    }
}

/* Helper: create an mbuf from a buffer */
static struct os_mbuf *om_from_buf(const void *buf, uint16_t len) {
    struct os_mbuf *om = ble_hs_mbuf_from_flat(buf, len);
    return om;
}

static void set_status(uint16_t conn_handle, const char *msg) {
    int slot = find_client_by_handle(conn_handle);
    if (slot < 0) return;
    char *status_str = clients[slot].status;
    strncpy(status_str, msg, sizeof(clients[slot].status) - 1);
    status_str[sizeof(clients[slot].status) - 1] = '\0';

    /* A command result belongs only to its initiating client. Broadcasting it
     * makes another connected phone/watch report a command it did not send. */
    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn_handle, &desc) == 0) {
        int rc = ble_gatts_notify_custom(conn_handle, status_val_handle,
                                         om_from_buf(status_str, strlen(status_str)));
        if (rc != 0) {
            LOG_W(TAG, "Status notify failed handle=%d rc=%d msg=%s",
                  conn_handle, rc, status_str);
        }
    }
}

static void set_ota_status(uint16_t conn_handle, const char *msg) {
    strncpy(ota_status_str, msg, sizeof(ota_status_str) - 1);
    ota_status_str[sizeof(ota_status_str) - 1] = '\0';

    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn_handle, &desc) == 0) {
        int rc = ble_gatts_notify_custom(conn_handle, ota_status_val_handle,
                                         om_from_buf(ota_status_str, strlen(ota_status_str)));
        if (rc != 0) {
            LOG_W(TAG, "OTA status notify failed handle=%d rc=%d msg=%s",
                  conn_handle, rc, ota_status_str);
        }
    }
}

static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void ota_abort_session(void) {
    if (ota_session.active) esp_ota_abort(ota_session.handle);
    if (ota_session.hash_started) psa_hash_abort(&ota_session.hash_operation);
    memset(&ota_session, 0, sizeof(ota_session));
    ota_session.hash_operation = psa_hash_operation_init();
}

static void ota_reboot_callback(void *arg) {
    (void)arg;
    restart_with_reason(REBOOT_OTA);
}

static bool ota_client_is_authenticated(uint16_t conn_handle) {
    int slot = find_client_by_handle(conn_handle);
    return slot >= 0 && clients[slot].authenticated;
}

static bool ota_verify_start_auth(uint16_t conn_handle, uint32_t image_size,
                                  const uint8_t digest[32], const uint8_t supplied[HMAC_LEN]) {
    int slot = find_client_by_handle(conn_handle);
    if (slot < 0 || !clients[slot].authenticated) return false;

    /* Domain || NUL || size-LE || SHA-256 || the client's current nonce. */
    uint8_t transcript[sizeof(OTA_AUTH_DOMAIN) - 1 + 1 + 4 + 32 + NONCE_LEN];
    size_t offset = 0;
    memcpy(transcript + offset, OTA_AUTH_DOMAIN, sizeof(OTA_AUTH_DOMAIN) - 1);
    offset += sizeof(OTA_AUTH_DOMAIN) - 1;
    transcript[offset++] = 0;
    transcript[offset++] = (uint8_t)(image_size);
    transcript[offset++] = (uint8_t)(image_size >> 8);
    transcript[offset++] = (uint8_t)(image_size >> 16);
    transcript[offset++] = (uint8_t)(image_size >> 24);
    memcpy(transcript + offset, digest, 32);
    offset += 32;
    memcpy(transcript + offset, clients[slot].nonce, NONCE_LEN);

    uint8_t expected[HMAC_LEN];
    bool computed = compute_hmac(transcript, sizeof(transcript), current_psk, expected);
    bool valid = computed && constant_time_equal(expected, supplied, HMAC_LEN);
    generate_nonce_for_slot(slot, true); /* a START token is always single-use */
    return valid;
}

static void init_ota_health(void) {
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        ota_pending_verify = true;
    }
}

static void load_radio_config(void) {
    radio_config_persisted = false;
    nvs_handle_t handle;
    if (nvs_open("car_unlock", NVS_READONLY, &handle) != ESP_OK) return;
    uint8_t data[1 + RADIO_CONFIG_SIZE];
    size_t length = sizeof(data);
    esp_err_t err = nvs_get_blob(handle, "radio1", data, &length);
    nvs_close(handle);
    radio_config_t loaded;
    if (err == ESP_OK && length == sizeof(data) && data[0] == 1 &&
        radio_config_decode(&loaded, data + 1)) {
        radio_config = loaded;
        radio_config_persisted = true;
    }
}

static bool save_radio_config(const radio_config_t *config) {
    if (!radio_config_valid(config)) return false;
    uint8_t data[1 + RADIO_CONFIG_SIZE] = {1}, current[RADIO_CONFIG_SIZE];
    radio_config_encode(data + 1, config);
    radio_config_encode(current, &radio_config);
    if (radio_config_persisted && memcmp(data + 1, current, sizeof(current)) == 0) return true;
    nvs_handle_t handle;
    if (nvs_open("car_unlock", NVS_READWRITE, &handle) != ESP_OK) return false;
    esp_err_t err = nvs_set_blob(handle, "radio1", data, sizeof(data));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) return false;
    radio_config = *config;
    radio_config_persisted = true;
    return true;
}

static void check_running_ota_image(bool healthy) {
    if (!ota_pending_verify) return;
    switch (ota_health_check(&ota_health, now_ms(), healthy)) {
        case OTA_HEALTH_CONFIRM:
            ESP_ERROR_CHECK(esp_ota_mark_app_valid_cancel_rollback());
            ota_pending_verify = false;
            break;
        case OTA_HEALTH_ROLLBACK:
            reboot_cause = REBOOT_OTA_HEALTH;
            reboot_magic = 0x424c4831;
            esp_ota_mark_app_invalid_rollback_and_reboot();
            /* If there is no rollback candidate, leave the image unconfirmed. */
            restart_with_reason(REBOOT_OTA_HEALTH);
            break;
        case OTA_HEALTH_WAIT: break;
    }
}

static void mark_ble_activity(void) {
    fast_adv_until_ms = now_ms() + ((int64_t)radio_config.idle_seconds * 1000);
    ble_npl_callout_reset(&slow_adv_callout,
        ble_npl_time_ms_to_ticks32((uint32_t)radio_config.idle_seconds * 1000));
    if (ble_synced && adv_active && !adv_using_fast_interval) start_advertising();
}

static void slow_adv_callback(struct ble_npl_event *event) {
    (void)event;
    if (adv_active && now_ms() >= fast_adv_until_ms) start_advertising();
}

static void request_ota_connection_params(uint16_t conn_handle) {
    /* OTA is powered from the car and benefits from a short interval with no
     * slave latency. Normal low-power parameters return after the OTA reboot. */
    struct ble_gap_upd_params params = {
        .itvl_min            = 6,    /* 7.5ms */
        .itvl_max            = 12,   /* 15ms */
        .latency             = 0,
        .supervision_timeout = 800,  /* 8s */
        .min_ce_len          = 0,
        .max_ce_len          = 0,
    };
    int rc = ble_gap_update_params(conn_handle, &params);
    if (rc != 0) {
        LOG_W(TAG, "OTA connection parameter request failed handle=%d rc=%d",
              conn_handle, rc);
    }
}

/**
 * Verify HMAC payload against current nonce and PSK.
 * Always rotates the nonce afterwards (even on failure) to prevent replay.
 */
static bool verify_auth(uint16_t conn_handle, uint8_t command,
                        const uint8_t *payload, size_t len) {
    int slot = ensure_client_slot(conn_handle);
    if (slot < 0) {
        LOG_W(TAG, "Auth failed: no client slot handle=%d", conn_handle);
        return false;
    }

    if (!current_psk[0] || clients[slot].auth_failures >= 5) return false;
    if (len != HMAC_LEN) {
        LOG_W(TAG, "Auth failed: bad HMAC len handle=%d len=%d",
              conn_handle, (int)len);
        generate_nonce_for_slot(slot, true);
        return false;
    }

    /* API v2: domain || NUL || device binding || NUL || command || nonce. */
    uint8_t transcript[(sizeof(COMMAND_AUTH_DOMAIN) - 1) + 1 +
                       (sizeof(COMMAND_DEVICE_BINDING) - 1) + 1 + 1 + NONCE_LEN];
    size_t offset = 0;
    memcpy(transcript + offset, COMMAND_AUTH_DOMAIN, sizeof(COMMAND_AUTH_DOMAIN) - 1);
    offset += sizeof(COMMAND_AUTH_DOMAIN) - 1;
    transcript[offset++] = 0;
    memcpy(transcript + offset, COMMAND_DEVICE_BINDING, sizeof(COMMAND_DEVICE_BINDING) - 1);
    offset += sizeof(COMMAND_DEVICE_BINDING) - 1;
    transcript[offset++] = 0;
    transcript[offset++] = command;
    memcpy(transcript + offset, clients[slot].nonce, NONCE_LEN);

    uint8_t expected[HMAC_LEN];
    if (!compute_hmac(transcript, sizeof(transcript), current_psk, expected)) {
        LOG_E(TAG, "Auth failed: HMAC compute error handle=%d slot=%d",
              conn_handle, slot);
        generate_nonce_for_slot(slot, true);
        return false;
    }

    /* Constant-time comparison to prevent timing side-channels */
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_LEN; i++) {
        diff |= payload[i] ^ expected[i];
    }

    generate_nonce_for_slot(slot, true);  /* rotate unconditionally */
    bool ok = (diff == 0);
    if (!ok) {
        clients[slot].auth_failures++;
        if (clients[slot].auth_failures >= 5) {
            clients[slot].closing = true;
            ble_gap_terminate(conn_handle, BLE_ERR_CONN_TERM_LOCAL);
        }
    }
    LOG_I(TAG, "Auth %s handle=%d slot=%d", ok ? "OK" : "FAIL", conn_handle, slot);
    return ok;
}

/* ============================================================
 * GATT access callbacks
 * ============================================================ */

/* Challenge characteristic: read returns current nonce */
static int chr_access_challenge(uint16_t conn_handle, uint16_t attr_handle,
                                struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int slot = ensure_client_slot(conn_handle);
        if (slot < 0) return BLE_ATT_ERR_UNLIKELY;

        LOG_I(TAG, "Challenge read handle=%d slot=%d", conn_handle, slot);
        if (clients[slot].authenticated) clients[slot].last_activity_at = now_ms();
        int rc = os_mbuf_append(ctxt->om, clients[slot].nonce, NONCE_LEN);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

/* Status characteristic: read returns current status string */
static int chr_access_status(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        int slot = ensure_client_slot(conn_handle);
        if (slot < 0) return BLE_ATT_ERR_UNLIKELY;
        int rc = os_mbuf_append(ctxt->om, clients[slot].status, strlen(clients[slot].status));
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
    LOG_I(TAG, "Command write handle=%d len=%d", conn_handle, len);
    if (len < 1 || len > 33) {
        LOG_W(TAG, "Command write bad length handle=%d len=%d", conn_handle, len);
        set_status(conn_handle, "ERR:EMPTY");
        return 0;
    }

    uint8_t buf[33];
    os_mbuf_copydata(ctxt->om, 0, len, buf);

    uint8_t cmd_type = buf[0];
    const uint8_t *hmac_payload = buf + 1;
    size_t hmac_len = len - 1;
    LOG_I(TAG, "Command write parsed handle=%d cmd=0x%02x hmac_len=%d",
          conn_handle, cmd_type, (int)hmac_len);

    if (cmd_type != CMD_AUTH_ONLY && cmd_type != CMD_PRESS) {
        LOG_W(TAG, "Command write unknown cmd handle=%d cmd=0x%02x",
              conn_handle, cmd_type);
        set_status(conn_handle, "ERR:UNKNOWN_CMD");
        return 0;
    }

    if (verify_auth(conn_handle, cmd_type, hmac_payload, hmac_len)) {
        mark_ble_activity();
        mark_authenticated(conn_handle);
        if (cmd_type == CMD_PRESS) {
            set_status(conn_handle, press_remote_button() ? "OK:PRESSED" : "ERR:BUSY");
        } else {
            set_status(conn_handle, "OK:AUTH");
        }
    } else {
        set_status(conn_handle, "ERR:AUTH");
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
    LOG_I(TAG, "Command pt1 write handle=%d len=%d", conn_handle, len);
    if (len != 17) {
        LOG_W(TAG, "Command pt1 bad length handle=%d len=%d", conn_handle, len);
        set_status(conn_handle, "ERR:PT1_LEN");
        return 0;
    }

    int slot = ensure_client_slot(conn_handle);
    if (slot < 0) {
        set_status(conn_handle, "ERR:NO_SLOT");
        return 0;
    }
    split_cmd_state_t *split_cmd = &split_cmds[slot];

    uint8_t buf[17];
    os_mbuf_copydata(ctxt->om, 0, len, buf);

    split_cmd->cmd_type    = buf[0];
    memcpy(split_cmd->hmac_part1, buf + 1, 16);
    split_cmd->has_part1   = true;
    split_cmd->conn_handle = conn_handle;
    split_cmd->part1_time  = now_ms();
    LOG_I(TAG, "Command pt1 stored handle=%d cmd=0x%02x", conn_handle, split_cmd->cmd_type);

    return 0;
}

/* Command Part 2: last 16 bytes of HMAC, reassemble and verify */
static int chr_access_command_pt2(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    int slot = find_client_by_handle(conn_handle);
    if (slot < 0) {
        set_status(conn_handle, "ERR:NO_SLOT");
        return 0;
    }
    split_cmd_state_t *split_cmd = &split_cmds[slot];
    LOG_I(TAG, "Command pt2 write handle=%d len=%d has_part1=%d part1_handle=%d",
          conn_handle, len, split_cmd->has_part1 ? 1 : 0, split_cmd->conn_handle);
    if (len != 16) {
        split_cmd->has_part1 = false;
        LOG_W(TAG, "Command pt2 bad length handle=%d len=%d", conn_handle, len);
        set_status(conn_handle, "ERR:PT2_LEN");
        return 0;
    }

    if (!split_cmd->has_part1) {
        LOG_W(TAG, "Command pt2 missing pt1 handle=%d", conn_handle);
        set_status(conn_handle, "ERR:NO_PT1");
        return 0;
    }

    if (split_cmd->conn_handle != conn_handle) {
        split_cmd->has_part1 = false;
        LOG_W(TAG, "Command pt2 conn mismatch handle=%d part1_handle=%d",
              conn_handle, split_cmd->conn_handle);
        set_status(conn_handle, "ERR:CONN_MISMATCH");
        return 0;
    }

    /* Timeout: part 2 must arrive within 5 seconds of part 1 */
    if (now_ms() - split_cmd->part1_time > 5000) {
        split_cmd->has_part1 = false;
        LOG_W(TAG, "Command pt2 timeout handle=%d elapsed_ms=%lld",
              conn_handle, (long long)(now_ms() - split_cmd->part1_time));
        set_status(conn_handle, "ERR:TIMEOUT");
        return 0;
    }

    uint8_t buf[16];
    os_mbuf_copydata(ctxt->om, 0, 16, buf);

    /* Reassemble full HMAC */
    uint8_t full_hmac[HMAC_LEN];
    memcpy(full_hmac, split_cmd->hmac_part1, 16);
    memcpy(full_hmac + 16, buf, 16);
    uint8_t cmd_type = split_cmd->cmd_type;
    split_cmd->has_part1 = false;
    LOG_I(TAG, "Command split parsed handle=%d cmd=0x%02x", conn_handle, cmd_type);

    if (cmd_type != CMD_AUTH_ONLY && cmd_type != CMD_PRESS) {
        LOG_W(TAG, "Command split unknown cmd handle=%d cmd=0x%02x",
              conn_handle, cmd_type);
        set_status(conn_handle, "ERR:UNKNOWN_CMD");
        return 0;
    }

    if (verify_auth(conn_handle, cmd_type, full_hmac, HMAC_LEN)) {
        mark_ble_activity();
        mark_authenticated(conn_handle);
        if (cmd_type == CMD_PRESS) {
            set_status(conn_handle, press_remote_button() ? "OK:PRESSED" : "ERR:BUSY");
        } else {
            set_status(conn_handle, "OK:AUTH");
        }
    } else {
        set_status(conn_handle, "ERR:AUTH");
    }
    return 0;
}

/* PSK2 rejects the old plaintext update format. The ordinary API-v2
 * command and Garmin characteristic table remain unchanged. */
static int chr_access_psk_update(uint16_t conn_handle, uint16_t attr_handle,
                                 struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;
    int slot = ensure_client_slot(conn_handle);
    if (slot < 0) return BLE_ATT_ERR_UNLIKELY;
    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len < 30 || len > PSK2_MAX_PACKET) {
        set_status(conn_handle, "ERR:PSK_FORMAT");
        return 0;
    }
    uint8_t packet[PSK2_MAX_PACKET], receipt_key[32];
    char replacement[PSK2_MAX_KEY + 1], receipt[PSK2_RECEIPT_SIZE];
    if (os_mbuf_copydata(ctxt->om, 0, len, packet) != 0) return BLE_ATT_ERR_UNLIKELY;
    bool valid = clients[slot].authenticated && !clients[slot].closing &&
        psk2_decrypt(current_psk, COMMAND_DEVICE_BINDING, clients[slot].nonce,
                     packet, len, replacement, receipt_key);
    generate_nonce_for_slot(slot, true);
    if (!valid) {
        psk2_zero(replacement, sizeof(replacement));
        psk2_zero(receipt_key, sizeof(receipt_key));
        set_status(conn_handle, "ERR:PSK_AUTH");
        if (++clients[slot].auth_failures >= 5) {
            clients[slot].closing = true;
            ble_gap_terminate(conn_handle, BLE_ERR_CONN_TERM_LOCAL);
        }
        return 0;
    }
    /* Prepare both authenticated outcomes BEFORE committing. Crypto failure
     * cannot change the key without a receipt we can return. */
    char failure_receipt[PSK2_RECEIPT_SIZE];
    bool receipts_ok = psk2_receipt(receipt_key, packet, len, true, receipt) &&
        psk2_receipt(receipt_key, packet, len, false, failure_receipt);
    psk2_zero(receipt_key, sizeof(receipt_key));
    if (!receipts_ok) {
        psk2_zero(replacement, sizeof(replacement));
        set_status(conn_handle, "ERR:PSK_CRYPTO");
        return 0;
    }
    bool persisted = save_psk(replacement);
    psk2_zero(replacement, sizeof(replacement));
    mark_authenticated(conn_handle);
    set_status(conn_handle, persisted ? receipt : failure_receipt);
    if (persisted) {
        /* Revoke other sessions authorized with the old key. */
        for (int i = 0; i < MAX_CONNECTIONS; ++i) {
            if (i != slot && clients[i].in_use) {
                clients[i].closing = true;
                clients[i].authenticated = false;
                invalidate_split_cmd_for(clients[i].conn_handle);
                if (ota_session.active && ota_session.conn_handle == clients[i].conn_handle) ota_abort_session();
                ble_gap_terminate(clients[i].conn_handle, BLE_ERR_CONN_TERM_LOCAL);
            }
        }
    }
    return 0;
}

static const char *health_reset_reason(void) {
    if (esp_reset_reason() == ESP_RST_SW) {
        switch (previous_reboot_cause) {
            case REBOOT_OTA: return "ota_update";
            case REBOOT_PERIODIC: return "scheduled_idle";
            case REBOOT_DAILY: return "scheduled_daily";
            case REBOOT_BLE_RESET: return "ble_host_reset";
            case REBOOT_BLE_EXIT: return "ble_host_exit";
            case REBOOT_BLE_STALL: return "ble_host_stall";
            case REBOOT_ADVERTISING: return "advertising_failure";
            case REBOOT_TASK: return "task_start_failure";
            case REBOOT_OTA_HEALTH: return "ota_health_failure";
            default: return "software";
        }
    }
    switch (esp_reset_reason()) {
        case ESP_RST_POWERON: return "power_on";
        case ESP_RST_EXT: return "external";
        case ESP_RST_PANIC: return "panic";
        case ESP_RST_INT_WDT: return "interrupt_watchdog";
        case ESP_RST_TASK_WDT: return "task_watchdog";
        case ESP_RST_WDT: return "watchdog";
        case ESP_RST_DEEPSLEEP: return "deep_sleep";
        case ESP_RST_BROWNOUT: return "brownout";
        case ESP_RST_SDIO: return "sdio";
        default: return "unknown";
    }
}

static int chr_access_identity(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) return BLE_ATT_ERR_UNLIKELY;
    int slot = find_client_by_handle(conn_handle);
    if (slot < 0 || !clients[slot].authenticated || clients[slot].closing) {
        return os_mbuf_append(ctxt->om, CAR_IDENTITY, sizeof(CAR_IDENTITY) - 1) == 0
            ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    const esp_app_desc_t *app = esp_app_get_description();
    char build[13];
    for (int i = 0; i < 6; ++i) snprintf(build + i * 2, 3, "%02x", app->app_elf_sha256[i]);
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    const char *ota = "unknown";
    esp_err_t state_result = esp_ota_get_state_partition(running, &state);
    if (state_result == ESP_OK) {
        switch (state) {
            case ESP_OTA_IMG_PENDING_VERIFY: ota = "pending"; break;
            case ESP_OTA_IMG_VALID: ota = "valid"; break;
            case ESP_OTA_IMG_UNDEFINED: ota = "initial"; break;
            default: break;
        }
    } else if (state_result == ESP_ERR_NOT_FOUND || running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) ota = "initial";
    device_health_t health = {
        .version = app->version, .build = build, .idf = app->idf_ver,
        .reset = health_reset_reason(), .ota = ota,
        .uptime_s = (uint64_t)(now_ms() / 1000),
        .free_heap = esp_get_free_heap_size(), .min_heap = esp_get_minimum_free_heap_size(),
        .connections = count_active_slots(), .adv_recoveries = adv_recoveries,
        .ghost_reaps = ghost_reaps,
        .radio = radio_config,
        .adv_mode = !ble_gap_adv_active() ? "off" : adv_using_fast_interval ? "recent" : "inactive",
    };
    char response[512];
    int length = device_health_format(response, sizeof(response), &health);
    if (length < 0 || (size_t)length >= sizeof(response)) return BLE_ATT_ERR_INSUFFICIENT_RES;
    clients[slot].last_activity_at = now_ms();
    return os_mbuf_append(ctxt->om, response, length) == 0
        ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int chr_access_ota_status(uint16_t conn_handle, uint16_t attr_handle,
                                 struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) return BLE_ATT_ERR_UNLIKELY;
    return os_mbuf_append(ctxt->om, ota_status_str, strlen(ota_status_str)) == 0
        ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int chr_access_ota_control(uint16_t conn_handle, uint16_t attr_handle,
                                  struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;

    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    uint8_t payload[OTA_START_LEN];
    if (len == 0 || len > sizeof(payload)) {
        set_ota_status(conn_handle, "ERR:OTA_FORMAT");
        return 0;
    }
    os_mbuf_copydata(ctxt->om, 0, len, payload);

    if (payload[0] == 0x04) {
        int slot = find_client_by_handle(conn_handle);
        if (len != RADIO_PACKET_SIZE || slot < 0 || !clients[slot].authenticated || clients[slot].closing) {
            set_ota_status(conn_handle, "ERR:RADIO_AUTH");
            return 0;
        }
        uint8_t transcript[RADIO_TRANSCRIPT_SIZE], expected[HMAC_LEN];
        radio_transcript(transcript, clients[slot].nonce, payload + 1);
        bool valid = compute_hmac(transcript, sizeof(transcript), current_psk, expected) &&
            constant_time_equal(expected, payload + 1 + RADIO_CONFIG_SIZE, HMAC_LEN);
        generate_nonce_for_slot(slot, true);
        if (!valid) {
            set_ota_status(conn_handle, "ERR:RADIO_AUTH");
            if (++clients[slot].auth_failures >= MAX_AUTH_FAILURES) {
                clients[slot].closing = true;
                clients[slot].authenticated = false;
                ble_gap_terminate(conn_handle, BLE_ERR_CONN_TERM_LOCAL);
            }
            return 0;
        }
        if (ota_session.active || ota_pending_verify) {
            set_ota_status(conn_handle, "ERR:RADIO_BUSY");
            return 0;
        }
        radio_config_t requested;
        if (!radio_config_decode(&requested, payload + 1)) {
            set_ota_status(conn_handle, "ERR:RADIO_RANGE");
            return 0;
        }
        if (!save_radio_config(&requested)) {
            set_ota_status(conn_handle, "ERR:RADIO_SAVE");
            return 0;
        }
        mark_authenticated(conn_handle);
        mark_ble_activity();
        if (count_active_slots() < MAX_CONNECTIONS) force_restart_advertising();
        set_ota_status(conn_handle, "RADIO:OK");
        return 0;
    }

    if (payload[0] == OTA_OP_ABORT) {
        if (ota_session.active && ota_session.conn_handle == conn_handle) {
            ota_abort_session();
            set_ota_status(conn_handle, "OTA:ABORTED");
        }
        return 0;
    }

    if (payload[0] == OTA_OP_START) {
        if (len != OTA_START_LEN) {
            set_ota_status(conn_handle, "ERR:OTA_FORMAT");
            return 0;
        }
        uint32_t image_size = (uint32_t)payload[1] |
                              ((uint32_t)payload[2] << 8) |
                              ((uint32_t)payload[3] << 16) |
                              ((uint32_t)payload[4] << 24);
        if (image_size == 0 || image_size > OTA_MAX_IMAGE_SIZE) {
            set_ota_status(conn_handle, "ERR:OTA_SIZE");
            return 0;
        }
        if (!ota_client_is_authenticated(conn_handle) ||
            !ota_verify_start_auth(conn_handle, image_size, payload + 5, payload + 37)) {
            set_ota_status(conn_handle, "ERR:OTA_AUTH");
            return 0;
        }
        if (ota_pending_verify) {
            set_ota_status(conn_handle, "ERR:OTA_PROBATION");
            return 0;
        }
        if (ota_session.active && ota_session.conn_handle != conn_handle) {
            set_ota_status(conn_handle, "ERR:OTA_BUSY");
            return 0;
        }
        if (ota_session.active) ota_abort_session();

        const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
        if (partition == NULL || partition->size < image_size) {
            set_ota_status(conn_handle, "ERR:OTA_SIZE");
            return 0;
        }

        esp_ota_handle_t handle = 0;
        esp_err_t err = esp_ota_begin(partition, image_size, &handle);
        if (err != ESP_OK) {
            set_ota_status(conn_handle, "ERR:OTA_BEGIN");
            return 0;
        }

        memset(&ota_session, 0, sizeof(ota_session));
        ota_session.active = true;
        ota_session.conn_handle = conn_handle;
        ota_session.handle = handle;
        ota_session.partition = partition;
        ota_session.expected_size = image_size;
        memcpy(ota_session.expected_sha256, payload + 5, 32);
        ota_session.hash_operation = psa_hash_operation_init();
        psa_status_t hash_status = psa_hash_setup(&ota_session.hash_operation, PSA_ALG_SHA_256);
        if (hash_status != PSA_SUCCESS) {
            ota_abort_session();
            set_ota_status(conn_handle, "ERR:OTA_HASH");
            return 0;
        }
        ota_session.hash_started = true;
        request_ota_connection_params(conn_handle);
        mark_ble_activity();
        set_ota_status(conn_handle, "OTA:READY");
        return 0;
    }

    if (payload[0] == OTA_OP_FINISH) {
        if (len != 1 || !ota_session.active || ota_session.conn_handle != conn_handle) {
            set_ota_status(conn_handle, "ERR:OTA_STATE");
            return 0;
        }
        if (ota_session.received != ota_session.expected_size) {
            set_ota_status(conn_handle, "ERR:OTA_SIZE");
            return 0;
        }

        uint8_t actual_sha256[32];
        size_t actual_len = 0;
        psa_status_t hash_status = psa_hash_finish(&ota_session.hash_operation,
                                                   actual_sha256, sizeof(actual_sha256),
                                                   &actual_len);
        ota_session.hash_started = false;
        if (hash_status != PSA_SUCCESS || actual_len != sizeof(actual_sha256) ||
            !constant_time_equal(actual_sha256, ota_session.expected_sha256, 32)) {
            ota_abort_session();
            set_ota_status(conn_handle, "ERR:OTA_DIGEST");
            return 0;
        }

        esp_ota_handle_t handle = ota_session.handle;
        const esp_partition_t *partition = ota_session.partition;
        ota_session.active = false;
        esp_err_t err = esp_ota_end(handle); /* also verifies signed images */
        if (err != ESP_OK || esp_ota_set_boot_partition(partition) != ESP_OK) {
            memset(&ota_session, 0, sizeof(ota_session));
            ota_session.hash_operation = psa_hash_operation_init();
            set_ota_status(conn_handle, "ERR:OTA_IMAGE");
            return 0;
        }

        memset(&ota_session, 0, sizeof(ota_session));
        ota_session.hash_operation = psa_hash_operation_init();
        set_ota_status(conn_handle, "OTA:OK");
        esp_timer_start_once(ota_reboot_timer, 1000 * 1000);
        return 0;
    }

    set_ota_status(conn_handle, "ERR:OTA_OP");
    return 0;
}

static int chr_access_ota_data(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg) {
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;
    uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (!ota_session.active || ota_session.conn_handle != conn_handle) {
        set_ota_status(conn_handle, "ERR:OTA_STATE");
        return 0;
    }
    if (len <= 4 || len > 512) {
        set_ota_status(conn_handle, "ERR:OTA_CHUNK");
        return 0;
    }

    uint8_t payload[512];
    os_mbuf_copydata(ctxt->om, 0, len, payload);
    uint32_t offset = (uint32_t)payload[0] |
                      ((uint32_t)payload[1] << 8) |
                      ((uint32_t)payload[2] << 16) |
                      ((uint32_t)payload[3] << 24);
    uint32_t chunk_len = len - 4;
    if (offset != ota_session.received || chunk_len > ota_session.expected_size - ota_session.received) {
        set_ota_status(conn_handle, "ERR:OTA_OFFSET");
        return 0;
    }

    esp_err_t err = esp_ota_write(ota_session.handle, payload + 4, chunk_len);
    psa_status_t hash_status = err == ESP_OK
        ? psa_hash_update(&ota_session.hash_operation, payload + 4, chunk_len)
        : PSA_ERROR_GENERIC_ERROR;
    if (err != ESP_OK || hash_status != PSA_SUCCESS) {
        ota_abort_session();
        set_ota_status(conn_handle, "ERR:OTA_WRITE");
        return 0;
    }
    ota_session.received += chunk_len;
    mark_authenticated(conn_handle);
    mark_ble_activity();
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
            {
                .uuid       = &identity_uuid.u,
                .access_cb  = chr_access_identity,
                .flags      = BLE_GATT_CHR_F_READ,
            },
            {
                .uuid       = &ota_control_uuid.u,
                .access_cb  = chr_access_ota_control,
                .flags      = BLE_GATT_CHR_F_WRITE,
            },
            {
                .uuid       = &ota_data_uuid.u,
                .access_cb  = chr_access_ota_data,
                .flags      = BLE_GATT_CHR_F_WRITE,
            },
            {
                .uuid       = &ota_status_uuid.u,
                .access_cb  = chr_access_ota_status,
                .val_handle = &ota_status_val_handle,
                .flags      = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
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
            /* Connection failed. The controller may already have stopped
             * advertising, so force our cached state back to inactive before
             * restarting. */
            LOG_W(TAG, "Connect failed, status=%d", event->connect.status);
            adv_active = false;
            log_client_state("connect-failed");
            start_advertising();
            return 0;
        }

        /* A successful connection consumes the advertising procedure on many
         * controllers. Treat advertising as stopped so we really restart it
         * below when more connection slots are available. */
        adv_active = false;

        int slot = find_client_slot();
        if (slot >= 0) {
            memset(&clients[slot], 0, sizeof(clients[slot]));
            clients[slot].in_use        = true;
            clients[slot].connected_at = now_ms();
            strcpy(clients[slot].status, "READY");
            clients[slot].authenticated = false;
            clients[slot].last_activity_at = now_ms();
            clients[slot].conn_handle   = conn_handle;
            generate_nonce_for_slot(slot, false);
            mark_ble_activity();
            LOG_I(TAG, "Client connected, slot %d, handle %d", slot, conn_handle);
            log_client_state("connect");
        } else {
            /* No free slots, disconnect immediately */
            LOG_W(TAG, "No free slots, disconnecting handle %d", conn_handle);
            log_client_state("connect-no-slot");
            ble_gap_terminate(conn_handle, BLE_ERR_CONN_LIMIT);
            return 0;
        }

        /* Tighten link supervision: 4s timeout.
         * Params: min_itvl, max_itvl (1.25ms units), latency,
         *         supervision_timeout (10ms units) */
        struct ble_gap_upd_params params = {
            .itvl_min            = 24,   /* 30ms */
            .itvl_max            = 48,   /* 60ms */
            .latency             = 4,    /* skip up to 4 idle events */
            .supervision_timeout = 800,  /* 8s tolerates noisy multi-client links */
            .min_ce_len          = 0,
            .max_ce_len          = 0,
        };
        int update_rc = ble_gap_update_params(conn_handle, &params);
        if (update_rc != 0) {
            LOG_W(TAG, "Connection parameter request failed handle=%d rc=%d",
                  conn_handle, update_rc);
        }

        /* Continue advertising if we have capacity */
        if (count_active_slots() < MAX_CONNECTIONS) {
            start_advertising();
        } else {
            adv_active = false;
            log_client_state("advertising-stopped-at-capacity");
        }
        break;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        uint16_t conn_handle = event->disconnect.conn.conn_handle;
        LOG_I(TAG, "Disconnect handle %d, reason 0x%02x",
              conn_handle, event->disconnect.reason);

        /* Do not trust cached advertising state across disconnect. If the
         * controller stopped advertising, an early return here creates the
         * reconnect delay seen in logs until the next interval switch. */
        adv_active = false;

        int slot = find_client_by_handle(conn_handle);
        if (slot >= 0) {
            clients[slot].in_use        = false;
            clients[slot].authenticated = false;
        }

        invalidate_split_cmd_for(conn_handle);
        if (ota_session.active && ota_session.conn_handle == conn_handle) {
            ota_abort_session();
        }

        /* Use fast advertising after disconnect because reconnects are likely. */
        mark_ble_activity();
        force_restart_advertising();
        log_client_state("disconnect");
        break;
    }

    case BLE_GAP_EVENT_ADV_COMPLETE:
        LOG_I(TAG, "Advertising complete");
        adv_active = false;
        /* Restart if we have capacity */
        if (count_active_slots() < MAX_CONNECTIONS) {
            start_advertising();
        }
        log_client_state("adv-complete");
        break;

    case BLE_GAP_EVENT_MTU:
        LOG_I(TAG, "MTU update: conn_handle=%d, mtu=%d",
              event->mtu.conn_handle, event->mtu.value);
        break;

    case BLE_GAP_EVENT_CONN_UPDATE:
        LOG_I(TAG, "Connection update: conn_handle=%d status=%d",
              event->conn_update.conn_handle, event->conn_update.status);
        break;

    case BLE_GAP_EVENT_SUBSCRIBE:
        LOG_I(TAG, "Subscribe: conn_handle=%d, attr_handle=%d",
              event->subscribe.conn_handle, event->subscribe.attr_handle);
        ensure_client_slot(event->subscribe.conn_handle);
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
    bool use_fast_adv = now_ms() < fast_adv_until_ms;

    if (adv_active) {
        if (adv_using_fast_interval == use_fast_adv) {
            return;
        }
        int stop_rc = ble_gap_adv_stop();
        if (stop_rc != 0 && stop_rc != BLE_HS_EALREADY) {
            LOG_W(TAG, "adv_stop for interval switch failed: %d", stop_rc);
        }
        adv_active = false;
    }

    /* Advertising data: flags + service UUID */
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = &service_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        LOG_E(TAG, "adv_set_fields failed: %d", rc);
        if (++adv_failure_count >= 3 && count_active_slots() == 0) {
            LOG_E(TAG, "Advertising setup failed repeatedly while idle, restarting");
            restart_with_reason(REBOOT_ADVERTISING);
        }
        return;
    }

    /* Scan response: device name */
    rsp_fields.name = (uint8_t *)BLE_DEVICE_NAME;
    rsp_fields.name_len = strlen(BLE_DEVICE_NAME);
    rsp_fields.name_is_complete = 1;

    rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
    if (rc != 0) {
        LOG_E(TAG, "adv_rsp_set_fields failed: %d", rc);
        if (++adv_failure_count >= 3 && count_active_slots() == 0) {
            LOG_E(TAG, "Advertising response setup failed repeatedly while idle, restarting");
            restart_with_reason(REBOOT_ADVERTISING);
        }
        return;
    }

    /* Advertising parameters */
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;  /* undirected connectable */
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;  /* general discoverable */
    adv_params.itvl_min  = use_fast_adv ? radio_config.fast_min : radio_config.slow_min;
    adv_params.itvl_max  = use_fast_adv ? radio_config.fast_max : radio_config.slow_max;

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, gap_event_handler, NULL);
    if (rc == 0) {
        adv_active = true;
        adv_using_fast_interval = use_fast_adv;
        adv_failure_count = 0;
        LOG_I(TAG, "Advertising started (%s interval)",
              use_fast_adv ? "fast" : "slow");
        log_client_state("adv-start");
    } else if (rc == BLE_HS_EALREADY) {
        adv_active = true;  /* already advertising */
        adv_failure_count = 0;
        log_client_state("adv-already");
    } else {
        LOG_E(TAG, "adv_start failed: %d", rc);
        log_client_state("adv-start-failed");
        if (++adv_failure_count >= 3 && count_active_slots() == 0) {
            LOG_E(TAG, "Advertising failed repeatedly while idle, restarting");
            restart_with_reason(REBOOT_ADVERTISING);
        }
    }
}

static void force_restart_advertising(void) {
    int stop_rc = ble_gap_adv_stop();
    if (stop_rc != 0 && stop_rc != BLE_HS_EALREADY) {
        LOG_W(TAG, "forced adv_stop failed: %d", stop_rc);
    }

    adv_active = false;
    start_advertising();
}

/* ============================================================
 * BLE host task + sync callback
 * ============================================================ */

static void ble_on_sync(void) {
    ble_synced = true;
    /* Make sure we have a public address */
    int rc = ble_hs_util_ensure_addr(0);
    assert(rc == 0);

    /* Set preferred MTU */
    rc = ble_att_set_preferred_mtu(517);
    if (rc != 0) {
        LOG_W(TAG, "Failed to set preferred MTU: %d", rc);
    }

    /* Set TX power */
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P3);

    mark_ble_activity();
    start_advertising();
    LOG_I(TAG, "BLE synced, advertising started (TX %d dBm)", BLE_TX_POWER);
}

static void ble_on_reset(int reason) {
    LOG_E(TAG, "BLE host reset, reason=%d", reason);
    restart_with_reason(REBOOT_BLE_RESET);
}

static void nimble_host_task(void *param) {
    /* This function returns only when nimble_port_stop() is called */
    nimble_port_run();
    nimble_port_freertos_deinit();
    /* The host loop should never exit during normal operation. */
    restart_with_reason(REBOOT_BLE_EXIT);
}

/* ============================================================
 * Main loop task: ghost reaper, timeouts, periodic restart
 * ============================================================ */

/* Called only on the NimBLE event queue: client slots, advertising, and
 * OTA handles now have one owner. The independent task only watches its heartbeat. */
static void maintain_ble_state(void) {
    int64_t now = now_ms();
    uint32_t recoveries_before = adv_recoveries;
    uint32_t ghosts_before = ghost_reaps;
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
                ghost_reaps++;
                LOG_I(TAG, "Reaped ghost slot %d (handle %d)",
                      i, clients[i].conn_handle);
                invalidate_split_cmd_for(clients[i].conn_handle);
                if (ota_session.active && ota_session.conn_handle == clients[i].conn_handle) {
                    ota_abort_session();
                }
                clients[i].in_use = false;
                clients[i].authenticated = false;
                log_client_state("ghost-reaped");
            } else {
                nimble_count++;
            }
        }

        /* Reconcile the cached flag with NimBLE's actual GAP state. This
         * prevents a stale true adv_active value from suppressing recovery. */
        if (nimble_count < MAX_CONNECTIONS) {
            bool actual_adv_active = ble_gap_adv_active() != 0;
            if (adv_active != actual_adv_active) {
                LOG_W(TAG, "Advertising state corrected: cached=%d actual=%d",
                      adv_active ? 1 : 0, actual_adv_active ? 1 : 0);
                adv_active = actual_adv_active;
            }
            if (!actual_adv_active) {
                adv_recoveries++;
                start_advertising();
                if (!ble_gap_adv_active()) {
                    if (++adv_health_failure_count >= BLE_ADV_HEALTH_MAX_FAILURES) {
                        LOG_E(TAG, "Advertising health recovery failed, restarting");
                        restart_with_reason(REBOOT_ADVERTISING);
                    }
                } else {
                    adv_health_failure_count = 0;
                }
            } else {
                adv_health_failure_count = 0;
            }
        } else {
            adv_health_failure_count = 0;
        }

        /* Drop back to low-power advertising after the fast reconnect window. */
        if (adv_active && adv_using_fast_interval && now >= fast_adv_until_ms) {
            start_advertising();
        }

        /* ---- Client timeout check ---- */
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!clients[i].in_use) continue;

            int64_t elapsed = now - (clients[i].authenticated
                ? clients[i].last_activity_at : clients[i].connected_at);
            int64_t timeout = clients[i].authenticated
                ? (int64_t)AUTH_TIMEOUT_SEC * 1000
                : (int64_t)UNAUTH_TIMEOUT_SEC * 1000;

            if (clients[i].closing || elapsed > timeout) {
                LOG_I(TAG, "Timeout slot %d (handle %d, auth=%d)",
                      i, clients[i].conn_handle, clients[i].authenticated);

                /* Reserve the slot until NimBLE confirms teardown. A late
                 * packet must not repair it into a new unauthenticated session. */
                uint16_t handle = clients[i].conn_handle;
                clients[i].closing = true;
                clients[i].authenticated = false;
                invalidate_split_cmd_for(handle);
                if (ota_session.active && ota_session.conn_handle == handle) {
                    ota_abort_session();
                }
                log_client_state("client-timeout");

                /* Ask NimBLE to tear down the link */
                ble_gap_terminate(handle, BLE_ERR_CONN_TERM_LOCAL);
            }
        }

        check_running_ota_image(ble_synced && task_wdt_monitored &&
            recoveries_before == adv_recoveries && ghosts_before == ghost_reaps &&
            (nimble_count >= MAX_CONNECTIONS || ble_gap_adv_active()));

        /* ---- Periodic restart (only when idle) ---- */
        if (now > (int64_t)RESTART_INTERVAL_SEC * 1000 && count_active_slots() == 0) {
            LOG_I(TAG, "Periodic restart (no active connections)");
            restart_with_reason(REBOOT_PERIODIC);
        }

        /* ---- Hard restart (unconditional, guards against long-running drift) ---- */
        if (now > (int64_t)HARD_RESTART_SEC * 1000 && !ota_session.active && !button_busy) {
            LOG_E(TAG, "Hard restart after %d hours", HARD_RESTART_SEC / 3600);
            restart_with_reason(REBOOT_DAILY);
        }

}

static void main_loop_task(void *param) {
    /* Subscribe this task to the task watchdog */
    bool subscribed_to_wdt = false;
    if (task_wdt_enabled) {
        esp_err_t wdt_ret = esp_task_wdt_add(NULL);
        if (wdt_ret == ESP_OK) {
            subscribed_to_wdt = true;
            task_wdt_monitored = true;
            LOG_I(TAG, "Main loop started, WDT subscribed");
        } else {
            LOG_E(TAG, "Failed to subscribe main loop to TWDT: %s",
                  esp_err_to_name(wdt_ret));
        }
    }

    uint32_t last_ble_heartbeat_ack = ble_heartbeat_ack_count;
    uint8_t missed_ble_heartbeats = 0;

    while (1) {
        if (subscribed_to_wdt) {
            esp_task_wdt_reset();
        }
        /* ---- NimBLE host event-loop watchdog ----
         * This event can only be acknowledged by the NimBLE host task. If the
         * queue stops progressing, the normal task watchdog may still be fed
         * by this maintenance task, so detect that failure independently. */
        if (!ble_npl_event_is_queued(&ble_health_event)) {
            ble_npl_eventq_put(nimble_port_get_dflt_eventq(), &ble_health_event);
        }
        uint32_t heartbeat_ack = ble_heartbeat_ack_count;
        if (heartbeat_ack == last_ble_heartbeat_ack) {
            if (++missed_ble_heartbeats >= BLE_HEALTH_MAX_MISSED_HEARTBEATS) {
                LOG_E(TAG, "NimBLE host heartbeat stalled, restarting");
                restart_with_reason(REBOOT_BLE_STALL);
            }
        } else {
            last_ble_heartbeat_ack = heartbeat_ack;
            missed_ble_heartbeats = 0;
        }

        vTaskDelay(pdMS_TO_TICKS(LOOP_INTERVAL_MS));
    }
}

/* ============================================================
 * app_main: entry point
 * ============================================================ */

void app_main(void) {
    previous_reboot_cause = esp_reset_reason() == ESP_RST_SW && reboot_magic == 0x424c4831
        && reboot_cause <= REBOOT_OTA_HEALTH ? reboot_cause : REBOOT_OTHER;
    reboot_magic = 0;
    init_ota_health();
#ifdef DEBUG
    esp_log_level_set(TAG, ESP_LOG_INFO);
#endif
    LOG_I(TAG, "ESP32-C3 BLE Car Unlock starting...");

    /* ---- GPIO init ---- */
    gpio_init_button();

    /* ---- Button release timer (non-blocking pulse) ---- */
    const esp_timer_create_args_t btn_timer_args = {
        .callback = button_timer_callback,
        .name     = "btn_release",
    };
    ESP_ERROR_CHECK(esp_timer_create(&btn_timer_args, &button_timer));

    const esp_timer_create_args_t ota_reboot_timer_args = {
        .callback = ota_reboot_callback,
        .name     = "ota_reboot",
    };
    ESP_ERROR_CHECK(esp_timer_create(&ota_reboot_timer_args, &ota_reboot_timer));

#ifdef DEBUG_LED_ENABLED
    gpio_init_led();
#else
    park_led_pin();
#endif

    /* ---- Client state init ---- */
    memset(clients, 0, sizeof(clients));
    memset(&ota_session, 0, sizeof(ota_session));
    ota_session.hash_operation = psa_hash_operation_init();

    /* ---- Power management: DFS + auto light sleep ---- */
    configure_power_management();

    /* ---- NVS init ---- */
    esp_err_t ret = nvs_flash_init();
    ESP_ERROR_CHECK(ret); /* Preserve credentials on all storage failures. */

    /* ---- Init PSA Crypto for HMAC ---- */
    psa_status_t psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        LOG_E(TAG, "PSA crypto init failed: %d", (int)psa_status);
        abort();
    }

    /* ---- Load PSK ---- */
    load_psk();
    load_radio_config();

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

    ble_npl_event_init(&ble_health_event, ble_health_event_callback, NULL);
    ble_npl_callout_init(&slow_adv_callout, nimble_port_get_dflt_eventq(), slow_adv_callback, NULL);

    /* ---- Task watchdog ---- */
    esp_task_wdt_config_t wdt_config = {
        .timeout_ms  = WDT_TIMEOUT_SEC * 1000,
        .idle_core_mask = 0,       /* don't watch idle task */
        .trigger_panic = true,
    };
    ret = esp_task_wdt_init(&wdt_config);
    if (ret == ESP_ERR_INVALID_STATE) {
        ret = esp_task_wdt_reconfigure(&wdt_config);
    }
    if (ret == ESP_OK) {
        task_wdt_enabled = true;
        LOG_I(TAG, "Task watchdog configured (%ds)", WDT_TIMEOUT_SEC);
    } else {
        task_wdt_enabled = false;
        LOG_E(TAG, "Task watchdog setup failed: %s", esp_err_to_name(ret));
    }

    /* ---- Start NimBLE host task ---- */
    nimble_port_freertos_init(nimble_host_task);

    /* ---- Start main loop task ----
     * Stack: 4096 bytes is plenty for ghost reaper + timeout logic.
     * Priority 5: above tIDLE(0) but below NimBLE host task. */
    BaseType_t task_created =
        xTaskCreate(main_loop_task, "main_loop", 4096, NULL, 5, NULL);
    if (task_created != pdPASS) {
        LOG_E(TAG, "Failed to create main maintenance task, restarting");
        restart_with_reason(REBOOT_TASK);
    }

    /* OTA validation runs on the BLE host only after sustained healthy service. */
}
