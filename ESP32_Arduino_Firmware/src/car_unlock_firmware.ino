/*
 * BLE Car Unlock Bridge - ESP32 Firmware
 *
 * Bridges a phone (via BLE) to a car alarm remote's button.
 * Authentication: HMAC-SHA256 challenge-response with PSK.
 *
 * Hardware:
 *   - ESP32-C3 SuperMini (or ESP32 WROOM)
 *   - GPIO wired to the non-supply leg of the remote's button
 *   - Powered from car 12V via buck converter to 3.3V (also powers remote)
 *
 * BLE GATT Service:
 *   - Challenge characteristic (read/notify): 16-byte random nonce
 *   - Command characteristic (write): 1-byte command type + 32-byte HMAC
 *   - Status characteristic (read/notify): reports result of last command
 *   - PSK Update characteristic (write): change PSK (requires current auth)
 *
 * Requires: NimBLE-Arduino 2.x (h2zero/NimBLE-Arduino@^2.1.0)
 */

#include <NimBLEDevice.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <esp_bt.h>

// ============================================================
// Configuration
// ============================================================

// Default PSK - change this before flashing! 32+ chars recommended.
#define DEFAULT_PSK "CHANGE_ME_before_flashing_32chars!"

// GPIO pin wired to the non-supply leg of the remote's button
#define BUTTON_GPIO 4

// Button trigger polarity:
//   true  = button connects encoder input to VCC (active HIGH)
//   false = button connects encoder input to GND (active LOW)
// Check with a multimeter: if one switch leg is on 3.3V, set true.
// If one switch leg is on GND, set false.
#define BUTTON_ACTIVE_HIGH true

// Button press pulse duration in milliseconds
#define BUTTON_PULSE_MS 300

// ---- DEBUG LED (comment out to disable) ----
#define DEBUG_LED_ENABLED
#define DEBUG_LED_GPIO 2

// BLE advertising interval (in 0.625ms units)
// Higher = less power, slower discovery. 1600 = 1000ms is a good balance.
#define ADV_INTERVAL_MIN 1600
#define ADV_INTERVAL_MAX 1600

// Auto-disconnect unauthenticated clients after this many seconds
#define UNAUTH_TIMEOUT_SEC 15

// Auto-disconnect authenticated clients after this many seconds (5 min)
#define AUTH_TIMEOUT_SEC 300

// BLE device name
#define BLE_DEVICE_NAME "BLE-Device"

// HMAC output length (SHA-256 = 32 bytes)
#define HMAC_LEN 32

// Nonce length
#define NONCE_LEN 16

// Command type prefixes (first byte of command characteristic payload)
#define CMD_AUTH_ONLY 0x01
#define CMD_PRESS     0x02

// Max PSK length
#define MAX_PSK_LEN 128

// Max simultaneous BLE connections
#define MAX_CONNECTIONS 3

// BLE TX power in dBm. Lower = less range but less power draw.
// Range: -12 to 9 dBm. 3 dBm is a good default for short range.
#define BLE_TX_POWER 3

// Loop tick interval in ms. Higher = less CPU wake, more power savings.
#define LOOP_INTERVAL_MS 500

// ============================================================
// UUIDs
// ============================================================

#define SERVICE_UUID        "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
#define CHALLENGE_CHAR_UUID "a1b2c3d4-e5f6-7890-abcd-ef1234567891"
#define COMMAND_CHAR_UUID   "a1b2c3d4-e5f6-7890-abcd-ef1234567892"
#define STATUS_CHAR_UUID    "a1b2c3d4-e5f6-7890-abcd-ef1234567893"
#define PSK_UPDATE_CHAR_UUID "a1b2c3d4-e5f6-7890-abcd-ef1234567894"
#define COMMAND_PT1_CHAR_UUID "a1b2c3d4-e5f6-7890-abcd-ef1234567895"
#define COMMAND_PT2_CHAR_UUID "a1b2c3d4-e5f6-7890-abcd-ef1234567896"

// ============================================================
// Globals
// ============================================================

Preferences prefs;
NimBLEServer* pServer = nullptr;
NimBLECharacteristic* challengeChar = nullptr;
NimBLECharacteristic* commandChar = nullptr;
NimBLECharacteristic* statusChar = nullptr;
NimBLECharacteristic* pskUpdateChar = nullptr;
NimBLECharacteristic* commandPt1Char = nullptr;
NimBLECharacteristic* commandPt2Char = nullptr;

uint8_t currentNonce[NONCE_LEN];
char currentPSK[MAX_PSK_LEN + 1];

struct ClientState {
    bool inUse;
    bool authenticated;
    unsigned long connectedAt;
};
ClientState clients[MAX_CONNECTIONS];

// Buffer for split command
struct SplitCommandState {
    bool hasPart1;
    uint8_t cmdType;
    uint8_t hmacPart1[16];
    unsigned long part1Time;
};
SplitCommandState splitCmd = {false, 0, {0}, 0};

// ============================================================
// Utility functions
// ============================================================

int findClientSlot() {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].inUse) return i;
    }
    return -1;
}

void generateNonce() {
    esp_fill_random(currentNonce, NONCE_LEN);
    challengeChar->setValue(currentNonce, NONCE_LEN);
    challengeChar->notify();
}

void loadPSK() {
    prefs.begin("car_unlock", true);
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
    prefs.begin("car_unlock", false);
    prefs.putString("psk", newPSK);
    prefs.end();
    strncpy(currentPSK, newPSK, MAX_PSK_LEN);
    currentPSK[MAX_PSK_LEN] = '\0';
}

bool computeHMAC(const uint8_t* nonce, size_t nonceLen, const char* key, uint8_t* outHMAC) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    if (mbedtls_md_setup(&ctx, info, 1) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    if (mbedtls_md_hmac_starts(&ctx, (const uint8_t*)key, strlen(key)) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    if (mbedtls_md_hmac_update(&ctx, nonce, nonceLen) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    if (mbedtls_md_hmac_finish(&ctx, outHMAC) != 0) {
        mbedtls_md_free(&ctx);
        return false;
    }
    mbedtls_md_free(&ctx);
    return true;
}

bool verifyAuth(const uint8_t* payload, size_t len) {
    if (len != HMAC_LEN) return false;

    uint8_t expectedHMAC[HMAC_LEN];
    if (!computeHMAC(currentNonce, NONCE_LEN, currentPSK, expectedHMAC)) {
        return false;
    }

    // Constant-time comparison
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_LEN; i++) {
        diff |= payload[i] ^ expectedHMAC[i];
    }

    bool match = (diff == 0);
    generateNonce();
    return match;
}

void pressRemoteButton() {
    // Drive pin to simulate button press
    pinMode(BUTTON_GPIO, OUTPUT);
    digitalWrite(BUTTON_GPIO, BUTTON_ACTIVE_HIGH ? HIGH : LOW);

#ifdef DEBUG_LED_ENABLED
    digitalWrite(DEBUG_LED_GPIO, HIGH);
#endif

    delay(BUTTON_PULSE_MS);

    // Release: return to idle state
    if (BUTTON_ACTIVE_HIGH) {
        // Active-high: idle LOW, no interference with encoder pull-down
        digitalWrite(BUTTON_GPIO, LOW);
    } else {
        // Active-low: go high-impedance so encoder pull-up holds line high
        pinMode(BUTTON_GPIO, INPUT);
    }

#ifdef DEBUG_LED_ENABLED
    digitalWrite(DEBUG_LED_GPIO, LOW);
#endif
}

void setStatus(const char* msg) {
    statusChar->setValue(msg);
    statusChar->notify();
}

// ============================================================
// BLE Callbacks (NimBLE 2.x API)
// ============================================================

class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override {
        int slot = findClientSlot();
        if (slot >= 0) {
            clients[slot].inUse = true;
            clients[slot].authenticated = false;
            clients[slot].connectedAt = millis();
        }
        generateNonce();
        if (pServer->getConnectedCount() < MAX_CONNECTIONS) {
            NimBLEDevice::startAdvertising();
        }
    }

    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override {
        for (int i = MAX_CONNECTIONS - 1; i >= 0; i--) {
            if (clients[i].inUse) {
                clients[i].inUse = false;
                clients[i].authenticated = false;
                break;
            }
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
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (clients[i].inUse && !clients[i].authenticated) {
                    clients[i].authenticated = true;
                    break;
                }
            }

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

        splitCmd.cmdType = data[0];
        memcpy(splitCmd.hmacPart1, data + 1, 16);
        splitCmd.hasPart1 = true;
        splitCmd.part1Time = millis();
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
        splitCmd.hasPart1 = false;

        uint8_t cmdType = splitCmd.cmdType;

        if (cmdType != CMD_AUTH_ONLY && cmdType != CMD_PRESS) {
            setStatus("ERR:UNKNOWN_CMD");
            return;
        }

        if (verifyAuth(fullHMAC, HMAC_LEN)) {
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (clients[i].inUse && !clients[i].authenticated) {
                    clients[i].authenticated = true;
                    break;
                }
            }

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

    // Button GPIO: set to idle state so it doesn't trigger the remote
    if (BUTTON_ACTIVE_HIGH) {
        // Active-high: hold LOW at boot (encoder input stays low = not pressed)
        pinMode(BUTTON_GPIO, OUTPUT);
        digitalWrite(BUTTON_GPIO, LOW);
    } else {
        // Active-low: high-impedance at boot (encoder pull-up holds line high)
        pinMode(BUTTON_GPIO, INPUT);
    }

#ifdef DEBUG_LED_ENABLED
    pinMode(DEBUG_LED_GPIO, OUTPUT);
    digitalWrite(DEBUG_LED_GPIO, LOW);
#endif

    // Init client slots
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        clients[i].inUse = false;
        clients[i].authenticated = false;
        clients[i].connectedAt = 0;
    }

    // Load PSK
    loadPSK();

    // Release classic BT memory (we only use BLE)
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);

    // Init BLE
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

    // Command characteristic (write)
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

    // Configure and start advertising
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(SERVICE_UUID);
    pAdvertising->setMinInterval(ADV_INTERVAL_MIN);
    pAdvertising->setMaxInterval(ADV_INTERVAL_MAX);
    pAdvertising->enableScanResponse(true);
    pAdvertising->start();
}

// ============================================================
// Main loop
// ============================================================

void loop() {
    unsigned long now = millis();

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!clients[i].inUse) continue;

        unsigned long elapsed = now - clients[i].connectedAt;
        unsigned long timeout = clients[i].authenticated
            ? AUTH_TIMEOUT_SEC * 1000UL
            : UNAUTH_TIMEOUT_SEC * 1000UL;

        if (elapsed > timeout) {
            if (pServer->getConnectedCount() > 0) {
                pServer->disconnect(0);
            }
            clients[i].inUse = false;
            break;
        }
    }

    delay(LOOP_INTERVAL_MS);
}
