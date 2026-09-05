using Toybox.BluetoothLowEnergy as Ble;
using Toybox.Cryptography;
using Toybox.System;
using Toybox.Application;
using Toybox.WatchUi;
using Toybox.Lang;
using Toybox.Timer;

// UUIDs matching the ESP32 firmware
class CarKeyProfile {
    static const READ_STATUS = true;
    static const DEVICE_NAME = "centurion-d5-evo";
    static const BINDING = "gate-main";
    // Address reported by the ESPHome test board. Address matching bypasses
    // differences in how watch firmware exposes ESPHome advertising fields.
    static const TARGET_ADDRESS        = "A0:B7:65:4A:15:EE";
    static const SERVICE_UUID         = Ble.longToUuid(0xb1b2c3d4e5f67890l, 0xabcdef1234567890l);
    static const CHALLENGE_CHAR_UUID  = Ble.longToUuid(0xb1b2c3d4e5f67890l, 0xabcdef1234567891l);
    static const COMMAND_CHAR_UUID    = Ble.longToUuid(0xb1b2c3d4e5f67890l, 0xabcdef1234567892l);
    static const STATUS_CHAR_UUID     = Ble.longToUuid(0xb1b2c3d4e5f67890l, 0xabcdef1234567893l);
    static const COMMAND_PT1_CHAR_UUID = Ble.longToUuid(0xb1b2c3d4e5f67890l, 0xabcdef1234567895l);
    static const COMMAND_PT2_CHAR_UUID = Ble.longToUuid(0xb1b2c3d4e5f67890l, 0xabcdef1234567896l);

    static const CCCD_UUID = Ble.cccdUuid();

    // API-v2 command types and fixed security binding (must match ESPHome).
    static const CMD_AUTH_ONLY = 0x01;
    static const CMD_PRESS     = 0x02;

    static function getProfileDef() {
        return {
            :uuid => SERVICE_UUID,
            :characteristics => [
                {
                    :uuid => CHALLENGE_CHAR_UUID
                },
                {
                    :uuid => COMMAND_CHAR_UUID
                },
                {
                    :uuid => COMMAND_PT1_CHAR_UUID
                },
                {
                    :uuid => COMMAND_PT2_CHAR_UUID
                },
                {
                    :uuid => STATUS_CHAR_UUID
                }
            ]
        };
    }
}

