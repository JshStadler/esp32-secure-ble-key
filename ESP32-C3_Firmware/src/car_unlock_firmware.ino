/*
 * BLE Car Unlock Bridge - ESP32-C3 SuperMini Firmware
 *
 * Bridges a phone/watch (via BLE) to a car alarm remote's button.
 * Authentication: HMAC-SHA256 challenge-response with PSK.
 *
 * Target: ESP32-C3-DevKitM-1 / ESP32-C3 SuperMini (external antenna variant)
 *
 * Hardware:
 *   - ESP32-C3 SuperMini (external antenna)
 *   - GPIO 5 wired to the non-supply leg of the remote's button
 *   - Powered from car 12V via buck converter to 3.3V (also powers remote)
 *
 * Power optimisations (C3-specific):
 *   - Wi-Fi radio fully disabled at startup (~70mA saved)
 *   - USB-CDC serial console disabled at runtime (re-enabled by ROM for flashing)
 *   - BLE modem sleep via CONFIG_BT_NIMBLE_SLEEP_ENABLE (set in platformio.ini)
 *   - CPU clocked at 80 MHz (set via board_build.f_cpu in platformio.ini)
 *   - Button GPIO held in INPUT (high-impedance) at idle; remote's own
 *     pull-down keeps encoder line low, drawing zero current through GPIO
 *   - Conservative advertising interval (1s)
 *   - Periodic restart every 3 hours (when idle) to clear leaked resources
 *
 * BLE GATT Service:
 *   - Challenge characteristic (read/notify): 16-byte random nonce
 *   - Command characteristic (write): 1-byte cmd type + 32-byte HMAC
 *   - Command Pt1/Pt2 (write): split-write path for low-MTU clients (Garmin)
 *   - Status characteristic (read/notify): reports result of last command
 *   - PSK Update characteristic (write): change PSK (requires current auth)
 *
 * Requires: NimBLE-Arduino 2.x (h2zero/NimBLE-Arduino@^2.1.0)
 *
 * Board: ESP32-C3-DevKitM-1  (Arduino ESP32 core 3.x)
 * Flash: via onboard USB-C (USB-Serial/JTAG, GPIO 18/19)
 */

#include <NimBLEDevice.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <driver/gpio.h>

// On ESP32-C3, USB-CDC console can be disabled to save power.
// The ROM bootloader always re-enables USB for flashing, so this is safe.
#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG || CONFIG_ESP_CONSOLE_USB_CDC
#include <hal/usb_serial_jtag_ll.h>
#endif

// ============================================================
// Configuration
// ============================================================

// Default PSK - change this before flashing! 32+ chars recommended.
#define DEFAULT_PSK "CHANGE_ME_before_flashing_32chars!"

// ---- GPIO: Button ----
// GPIO 5: no strapping function, clean digital I/O on C3 SuperMini.
// Avoid: GPIO 2 (strapping), GPIO 8 (strapping/LED), GPIO 9 (boot btn),
//        GPIO 18/19 (USB-CDC needed for flashing).
#define BUTTON_GPIO 5

// Button trigger polarity:
//   true  = button connects encoder input to VCC (active HIGH)
//   false = button connects encoder input to GND (active LOW)
//
// For active-high: idle state is INPUT (high-impedance).
//   The remote's encoder has its own pull-down holding the line low.
//   To press: briefly drive OUTPUT HIGH, then return to INPUT.
//   This draws zero quiescent current through the GPIO.
//
// For active-low: idle state is also INPUT (high-impedance).
//   The remote's encoder pull-up holds the line high.
//   To press: briefly drive OUTPUT LOW, then return to INPUT.
#define BUTTON_ACTIVE_HIGH true

// Button press pulse duration in milliseconds
#define BUTTON_PULSE_MS 300

// ---- DEBUG LED (compile-time flag) ----
// GPIO 8 is the onboard LED on most C3 SuperMini boards.
// Also a strapping pin (must be HIGH at boot for normal SPI flash boot).
// Safe to drive after boot. Comment out for production to save a few uA.
// #define DEBUG_LED_ENABLED
// #define DEBUG_LED_GPIO 8

// ---- BLE ----

// BLE device name
#define BLE_DEVICE_NAME "BLE-Device"

// BLE TX power in dBm. C3 supports: -27, -24, -21, -18, -15, -12, -9,
// -6, -3, 0, 3, 6, 9, 12, 15, 18, 20 (board-dependent max).
//
// This board has an external antenna (better gain than chip antennas).
// 3 dBm is a good default for car cabin range (~3-5m) with external antenna.
// With a chip antenna you'd want 9+ dBm to compensate for lower gain.
// Increase to 6-9 if mounted behind metal panels or if range is marginal.
#define BLE_TX_POWER 3

// BLE advertising interval (in 0.625ms units)
// 1600 = 1000ms. Good balance of discoverability vs power.
// For even lower power: 3200 = 2000ms (slower discovery, ~0.5mA less).
#define ADV_INTERVAL_MIN 1600
#define ADV_INTERVAL_MAX 1600

// Max simultaneous BLE connections
// Note: each connection costs ~3-4KB RAM on C3 (single-core, 400KB total).
// 3 connections is fine, but reduces free heap. Set to 1 if only phone is used.
#define MAX_CONNECTIONS 3

// Auto-disconnect unauthenticated clients after this many seconds
#define UNAUTH_TIMEOUT_SEC 15

// Auto-disconnect authenticated clients after this many seconds (5 min)
#define AUTH_TIMEOUT_SEC 300

// Periodic restart interval in seconds (3 hours = 10800s).
// Prevents memory fragmentation and clears any leaked resources.
// Only triggers when no clients are connected, so it never interrupts
// an active session. Cost: ~200ms reboot every 3 hours = negligible.
#define RESTART_INTERVAL_SEC 10800

// ---- Crypto ----
#define HMAC_LEN  32
#define NONCE_LEN 16

// Command type prefixes (first byte of command characteristic payload)
#define CMD_AUTH_ONLY 0x01
#define CMD_PRESS     0x02

// Max PSK length
#define MAX_PSK_LEN 128

// Loop tick interval in ms.
// delay() yields to the FreeRTOS idle task between ticks.
// BLE callbacks fire instantly regardless of this value.
#define LOOP_INTERVAL_MS 1000

// ============================================================
// UUIDs
// ============================================================

#define SERVICE_UUID           "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
#define CHALLENGE_CHAR_UUID    "a1b2c3d4-e5f6-7890-abcd-ef1234567891"
#define COMMAND_CHAR_UUID      "a1b2c3d4-e5f6-7890-abcd-ef1234567892"
#define STATUS_CHAR_UUID       "a1b2c3d4-e5f6-7890-abcd-ef1234567893"
#define PSK_UPDATE_CHAR_UUID   "a1b2c3d4-e5f6-7890-abcd-ef1234567894"
#define COMMAND_PT1_CHAR_UUID  "a1b2c3d4-e5f6-7890-abcd-ef1234567895"
#define COMMAND_PT2_CHAR_UUID  "a1b2c3d4-e5f6-7890-abcd-ef1234567896"

// ============================================================
// Globals
// ============================================================

Preferences prefs;
NimBLEServer* pServer = nullptr;
NimBLECharacteristic* challengeChar   = nullptr;
NimBLECharacteristic* commandChar     = nullptr;
NimBLECharacteristic* statusChar      = nullptr;
NimBLECharacteristic* pskUpdateChar   = nullptr;
NimBLECharacteristic* commandPt1Char  = nullptr;
NimBLECharacteristic* commandPt2Char  = nullptr;

uint8_t currentNonce[NONCE_LEN];
char    currentPSK[MAX_PSK_LEN + 1];

struct ClientState {
    uint16_t      connHandle;   // NimBLE connection handle for targeted disconnect
    bool          inUse;
    bool          authenticated;
    unsigned long connectedAt;
};
ClientState clients[MAX_CONNECTIONS];

// Buffer for split command (low-MTU clients like Garmin watches)
struct SplitCommandState {
    bool          hasPart1;
    uint8_t       cmdType;
    uint8_t       hmacPart1[16];
    uint16_t      connHandle;   // tie part1 to a specific connection
    unsigned long part1Time;
};
SplitCommandState splitCmd = {false, 0, {0}, 0, 0};

// ============================================================
// Power management: disable unused peripherals
// ============================================================

static void disableWiFi() {
    // Fully shut down the Wi-Fi radio and release its memory.
    // This saves ~70mA continuous draw and frees ~40KB heap.
    esp_wifi_stop();
    esp_wifi_deinit();
    // On C3, Wi-Fi and BLE share the radio but the stack can release
    // Wi-Fi-specific resources while BLE continues operating.
}

static void disableUSBConsole() {
    // Disable the USB-Serial/JTAG peripheral's clock to save power.
    // The ROM bootloader unconditionally re-enables it when you hold
    // the BOOT button and reset, so flashing via USB-C still works.
#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    // Disable USB-Serial/JTAG pull-ups and peripheral
    usb_serial_jtag_ll_disable_pad();
#endif
    // Stop Arduino Serial output (no-ops if already stopped)
    Serial.end();
}

static void configurePowerSaving() {
    // Arduino-ESP32 precompiled SDK does NOT have CONFIG_PM_ENABLE or
    // CONFIG_FREERTOS_USE_TICKLESS_IDLE enabled, so true CPU light-sleep
    // is not available. These cannot be enabled via -D build flags because
    // the FreeRTOS static libraries are precompiled without them.
    //
    // What IS working in this build:
    //   1. CPU at 80 MHz (via board_build.f_cpu in platformio.ini)
    //   2. Wi-Fi radio disabled (disableWiFi())
    //   3. NimBLE modem sleep (CONFIG_BT_NIMBLE_SLEEP_ENABLE=1 in
    //      platformio.ini — works because NimBLE compiles from source)
    //   4. delay() yields to FreeRTOS idle task (CPU stays clocked but
    //      doesn't execute user code between ticks)
    //
    // For true light-sleep (~2-5mA), migrate to framework = espidf
    // and enable CONFIG_PM_ENABLE + CONFIG_FREERTOS_USE_TICKLESS_IDLE
    // in sdkconfig.defaults. See ESP_IDF_MIGRATION_PROMPT.md.

    setCpuFrequencyMhz(80);
    Serial.printf("[PWR] CPU frequency: %d MHz\n", getCpuFrequencyMhz());
}

// ============================================================
// Utility functions
// ============================================================

/**
 * Find a free client slot, or return -1 if all are in use.
 */
int findClientSlot() {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].inUse) return i;
    }
    return -1;
}

/**
 * Find the client slot for a given BLE connection handle.
 * Returns -1 if not found.
 */
int findClientByHandle(uint16_t connHandle) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (clients[i].inUse && clients[i].connHandle == connHandle) return i;
    }
    return -1;
}

/**
 * Generate a fresh 16-byte random nonce and push it to subscribers.
 */
void generateNonce() {
    esp_fill_random(currentNonce, NONCE_LEN);
    challengeChar->setValue(currentNonce, NONCE_LEN);
    challengeChar->notify();
}

void loadPSK() {
    prefs.begin("car_unlock", true);  // read-only
    String storedPSK = prefs.getString("psk", "");
    prefs.end();

    if (storedPSK.length() > 0) {
        strncpy(currentPSK, storedPSK.c_str(), MAX_PSK_LEN);
    } else {
        strncpy(currentPSK, DEFAULT_PSK, MAX_PSK_LEN);
    }
    currentPSK[MAX_PSK_LEN] = '\0';
}

void savePSK(const char* newPSK) {
    prefs.begin("car_unlock", false);  // read-write
    prefs.putString("psk", newPSK);
    prefs.end();
    strncpy(currentPSK, newPSK, MAX_PSK_LEN);
    currentPSK[MAX_PSK_LEN] = '\0';
}

bool computeHMAC(const uint8_t* nonce, size_t nonceLen,
                 const char* key, uint8_t* outHMAC) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0)    goto fail;
    if (mbedtls_md_hmac_starts(&ctx, (const uint8_t*)key, strlen(key)) != 0) goto fail;
    if (mbedtls_md_hmac_update(&ctx, nonce, nonceLen) != 0)                  goto fail;
    if (mbedtls_md_hmac_finish(&ctx, outHMAC) != 0)                          goto fail;
    mbedtls_md_free(&ctx);
    return true;

fail:
    mbedtls_md_free(&ctx);
    return false;
}

/**
 * Verify an HMAC payload against the current nonce and PSK.
 * Always rotates the nonce afterwards (even on failure) to prevent replay.
 */
bool verifyAuth(const uint8_t* payload, size_t len) {
    if (len != HMAC_LEN) return false;

    uint8_t expectedHMAC[HMAC_LEN];
    if (!computeHMAC(currentNonce, NONCE_LEN, currentPSK, expectedHMAC)) {
        generateNonce();  // rotate even on compute failure
        return false;
    }

    // Constant-time comparison to prevent timing side-channels
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_LEN; i++) {
        diff |= payload[i] ^ expectedHMAC[i];
    }

    generateNonce();  // rotate nonce unconditionally
    return (diff == 0);
}

/**
 * Simulate a remote button press.
 *
 * Idle state: INPUT (high-impedance). The remote's encoder pull-down
 * holds the line low, drawing zero current through the ESP32 GPIO.
 *
 * Press: briefly drive OUTPUT HIGH (active-high) to pull the encoder
 * input up to 3.3V, simulating the physical button press.
 *
 * For active-low remotes: briefly drive OUTPUT LOW, then return to INPUT
 * (encoder pull-up holds the line high at idle).
 */
void pressRemoteButton() {
    // Drive to active state
    pinMode(BUTTON_GPIO, OUTPUT);
    digitalWrite(BUTTON_GPIO, BUTTON_ACTIVE_HIGH ? HIGH : LOW);

#ifdef DEBUG_LED_ENABLED
    digitalWrite(DEBUG_LED_GPIO, HIGH);
#endif

    delay(BUTTON_PULSE_MS);

    // Return to high-impedance idle (zero quiescent current)
    pinMode(BUTTON_GPIO, INPUT);

#ifdef DEBUG_LED_ENABLED
    digitalWrite(DEBUG_LED_GPIO, LOW);
#endif
}

void setStatus(const char* msg) {
    statusChar->setValue(msg);
    statusChar->notify();
}

/**
 * Mark the client identified by connHandle as authenticated.
 */
void markAuthenticated(uint16_t connHandle) {
    int slot = findClientByHandle(connHandle);
    if (slot >= 0) {
        clients[slot].authenticated = true;
    }
}

// ============================================================
// BLE Callbacks (NimBLE 2.x API)
// ============================================================

class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override {
        int slot = findClientSlot();
        if (slot >= 0) {
            clients[slot].inUse         = true;
            clients[slot].authenticated = false;
            clients[slot].connectedAt   = millis();
            clients[slot].connHandle    = connInfo.getConnHandle();
        } else {
            // No free slots — disconnect this client immediately
            pServer->disconnect(connInfo.getConnHandle());
            return;
        }
        generateNonce();

        // Continue advertising if we have capacity
        if (pServer->getConnectedCount() < MAX_CONNECTIONS) {
            NimBLEDevice::startAdvertising();
        }
    }

    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override {
        // Free the exact slot for this connection handle
        int slot = findClientByHandle(connInfo.getConnHandle());
        if (slot >= 0) {
            clients[slot].inUse         = false;
            clients[slot].authenticated = false;
        }

        // Invalidate any pending split command from this connection
        if (splitCmd.hasPart1 && splitCmd.connHandle == connInfo.getConnHandle()) {
            splitCmd.hasPart1 = false;
        }

        NimBLEDevice::startAdvertising();
    }
};

class CommandCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        NimBLEAttValue val = pCharacteristic->getValue();
        const uint8_t* data = val.data();
        size_t len = val.length();

        if (len < 1) {
            setStatus("ERR:EMPTY");
            return;
        }

        uint8_t cmdType = data[0];
        const uint8_t* hmacPayload = data + 1;
        size_t hmacLen = len - 1;

        if (cmdType != CMD_AUTH_ONLY && cmdType != CMD_PRESS) {
            setStatus("ERR:UNKNOWN_CMD");
            return;
        }

        if (verifyAuth(hmacPayload, hmacLen)) {
            markAuthenticated(connInfo.getConnHandle());

            if (cmdType == CMD_PRESS) {
                pressRemoteButton();
                setStatus("OK:PRESSED");
            } else {
                setStatus("OK:AUTH");
            }
        } else {
            setStatus("ERR:AUTH");
        }
    }
};

class PSKUpdateCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        NimBLEAttValue val = pCharacteristic->getValue();
        const uint8_t* data = val.data();
        size_t len = val.length();

        // Format: [HMAC (32 bytes)] [0x00 separator] [new PSK bytes]
        int separatorIdx = -1;
        for (size_t i = 0; i < len; i++) {
            if (data[i] == 0x00) {
                separatorIdx = i;
                break;
            }
        }

        if (separatorIdx < 1 || separatorIdx >= (int)len - 1) {
            setStatus("ERR:PSK_FORMAT");
            return;
        }

        if (!verifyAuth(data, separatorIdx)) {
            setStatus("ERR:PSK_AUTH");
            return;
        }

        size_t newPSKLen = len - separatorIdx - 1;
        if (newPSKLen == 0 || newPSKLen > MAX_PSK_LEN) {
            setStatus("ERR:PSK_LENGTH");
            return;
        }

        char newPSK[MAX_PSK_LEN + 1];
        memcpy(newPSK, data + separatorIdx + 1, newPSKLen);
        newPSK[newPSKLen] = '\0';

        savePSK(newPSK);
        markAuthenticated(connInfo.getConnHandle());
        setStatus("OK:PSK_UPDATED");
    }
};

class CommandPt1Callbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        NimBLEAttValue val = pCharacteristic->getValue();
        const uint8_t* data = val.data();
        size_t len = val.length();

        // Expect: 1 byte cmd + 16 bytes HMAC part 1 = 17 bytes
        if (len != 17) {
            setStatus("ERR:PT1_LEN");
            return;
        }

        splitCmd.cmdType    = data[0];
        memcpy(splitCmd.hmacPart1, data + 1, 16);
        splitCmd.hasPart1   = true;
        splitCmd.connHandle = connInfo.getConnHandle();
        splitCmd.part1Time  = millis();
    }
};

class CommandPt2Callbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        NimBLEAttValue val = pCharacteristic->getValue();
        const uint8_t* data = val.data();
        size_t len = val.length();

        // Expect: 16 bytes HMAC part 2
        if (len != 16) {
            splitCmd.hasPart1 = false;
            setStatus("ERR:PT2_LEN");
            return;
        }

        if (!splitCmd.hasPart1) {
            setStatus("ERR:NO_PT1");
            return;
        }

        // Ensure part 2 comes from the same connection as part 1
        if (splitCmd.connHandle != connInfo.getConnHandle()) {
            splitCmd.hasPart1 = false;
            setStatus("ERR:CONN_MISMATCH");
            return;
        }

        // Timeout: part 2 must arrive within 5 seconds of part 1
        if (millis() - splitCmd.part1Time > 5000) {
            splitCmd.hasPart1 = false;
            setStatus("ERR:TIMEOUT");
            return;
        }

        // Reassemble full HMAC
        uint8_t fullHMAC[HMAC_LEN];
        memcpy(fullHMAC, splitCmd.hmacPart1, 16);
        memcpy(fullHMAC + 16, data, 16);
        uint8_t cmdType = splitCmd.cmdType;
        splitCmd.hasPart1 = false;

        if (cmdType != CMD_AUTH_ONLY && cmdType != CMD_PRESS) {
            setStatus("ERR:UNKNOWN_CMD");
            return;
        }

        if (verifyAuth(fullHMAC, HMAC_LEN)) {
            markAuthenticated(connInfo.getConnHandle());

            if (cmdType == CMD_PRESS) {
                pressRemoteButton();
                setStatus("OK:PRESSED");
            } else {
                setStatus("OK:AUTH");
            }
        } else {
            setStatus("ERR:AUTH");
        }
    }
};

// ============================================================
// Setup
// ============================================================

void setup() {
    Serial.begin(115200);
    Serial.println("[BOOT] ESP32-C3 BLE Car Unlock starting...");

    // ---- GPIO init ----

    // Button: INPUT (high-impedance) at boot.
    // The remote's encoder pull-down holds the line low = not pressed.
    // This draws zero current through the ESP32 GPIO.
    pinMode(BUTTON_GPIO, INPUT);

#ifdef DEBUG_LED_ENABLED
    pinMode(DEBUG_LED_GPIO, OUTPUT);
    digitalWrite(DEBUG_LED_GPIO, LOW);
#endif

    // ---- Client state init ----
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        clients[i].inUse         = false;
        clients[i].authenticated = false;
        clients[i].connectedAt   = 0;
        clients[i].connHandle    = 0;
    }

    // ---- Power: disable Wi-Fi ----
    disableWiFi();
    Serial.println("[PWR] Wi-Fi disabled");

    // ---- Power: configure power saving ----
    configurePowerSaving();

    // ---- Load PSK ----
    loadPSK();

    // ---- Init BLE ----
    NimBLEDevice::init(BLE_DEVICE_NAME);
    NimBLEDevice::setMTU(185);
    NimBLEDevice::setPower(BLE_TX_POWER);

    // Create server
    pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    // Create service
    NimBLEService* pService = pServer->createService(SERVICE_UUID);

    // Challenge characteristic (read + notify)
    challengeChar = pService->createCharacteristic(
        CHALLENGE_CHAR_UUID,
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY
    );
    challengeChar->setValue(currentNonce, NONCE_LEN);

    // Command characteristic (write) - full 33-byte payload
    commandChar = pService->createCharacteristic(
        COMMAND_CHAR_UUID,
        NIMBLE_PROPERTY::WRITE
    );
    commandChar->setCallbacks(new CommandCallbacks());

    // Split command characteristics for low-MTU clients (e.g. Garmin watches)
    commandPt1Char = pService->createCharacteristic(
        COMMAND_PT1_CHAR_UUID,
        NIMBLE_PROPERTY::WRITE
    );
    commandPt1Char->setCallbacks(new CommandPt1Callbacks());

    commandPt2Char = pService->createCharacteristic(
        COMMAND_PT2_CHAR_UUID,
        NIMBLE_PROPERTY::WRITE
    );
    commandPt2Char->setCallbacks(new CommandPt2Callbacks());

    // Status characteristic (read + notify)
    statusChar = pService->createCharacteristic(
        STATUS_CHAR_UUID,
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY
    );
    statusChar->setValue("READY");

    // PSK Update characteristic (write)
    pskUpdateChar = pService->createCharacteristic(
        PSK_UPDATE_CHAR_UUID,
        NIMBLE_PROPERTY::WRITE
    );
    pskUpdateChar->setCallbacks(new PSKUpdateCallbacks());

    // NimBLE 2.x: services start automatically when the server starts.
    // No need to call pService->start() (deprecated no-op in 2.x).

    // Configure and start advertising
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setMinInterval(ADV_INTERVAL_MIN);
    pAdvertising->setMaxInterval(ADV_INTERVAL_MAX);
    pAdvertising->enableScanResponse(true);
    pAdvertising->start();

    Serial.println("[BLE] Advertising started");
    Serial.printf("[BLE] TX power: %d dBm, Adv interval: %d ms\n",
                  BLE_TX_POWER, (ADV_INTERVAL_MAX * 625) / 1000);

    // ---- Power: disable USB console (do this last so boot logs are visible) ----
#ifndef DEBUG_LED_ENABLED
    // Only disable USB console in production (when debug LED is also off).
    // During development, keep serial alive for debugging.
    disableUSBConsole();

    // 1. Park the LED pin to 0V potential (No current flow)
    pinMode(8, OUTPUT); 
    digitalWrite(8, LOW); // Assuming Active-Low; swap to LOW if it stays on
#endif
}

// ============================================================
// Main loop
// ============================================================

void loop() {
    unsigned long now = millis();

    // ---- Client timeout check ----
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].inUse) continue;

        unsigned long elapsed = now - clients[i].connectedAt;
        unsigned long timeout = clients[i].authenticated
            ? AUTH_TIMEOUT_SEC * 1000UL
            : UNAUTH_TIMEOUT_SEC * 1000UL;

        if (elapsed > timeout) {
            // Disconnect this specific client by its connection handle
            pServer->disconnect(clients[i].connHandle);
            clients[i].inUse = false;
            clients[i].authenticated = false;
        }
    }

    // ---- Periodic restart (only when idle) ----
    if (now > RESTART_INTERVAL_SEC * 1000UL && pServer->getConnectedCount() == 0) {
        Serial.println("[SYS] Periodic restart (no active connections)");
        delay(50);  // allow serial flush
        ESP.restart();
    }

    delay(LOOP_INTERVAL_MS);
}
