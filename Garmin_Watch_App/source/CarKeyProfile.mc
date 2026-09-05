using Toybox.BluetoothLowEnergy as Ble;
using Toybox.Cryptography;
using Toybox.System;
using Toybox.Application;
using Toybox.WatchUi;
using Toybox.Lang;
using Toybox.Timer;

// UUIDs matching the ESP32 firmware
class CarKeyProfile {
    static const READ_STATUS = false;
    static const DEVICE_NAME = "BLE-Device";
    static const BINDING = "car-main";
    static const SERVICE_UUID         = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567890l);
    static const CHALLENGE_CHAR_UUID  = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567891l);
    static const COMMAND_CHAR_UUID    = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567892l);
    static const STATUS_CHAR_UUID     = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567893l);
    static const COMMAND_PT1_CHAR_UUID = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567895l);
    static const COMMAND_PT2_CHAR_UUID = Ble.longToUuid(0xa1b2c3d4e5f67890l, 0xabcdef1234567896l);

    static const CCCD_UUID = Ble.cccdUuid();

    // Command types (must match ESP32 firmware)
    static const CMD_AUTH_ONLY = 0x01;
    static const CMD_PRESS     = 0x02;

    static function getProfileDef() {
        return {
            :uuid => SERVICE_UUID,
            :characteristics => [
                {
                    :uuid => CHALLENGE_CHAR_UUID,
                    :descriptors => [CCCD_UUID]
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
                    :uuid => STATUS_CHAR_UUID,
                    :descriptors => [CCCD_UUID]
                }
            ]
        };
    }
}

