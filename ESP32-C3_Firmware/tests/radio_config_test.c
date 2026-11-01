#include <assert.h>
#include "radio_config.h"

int main(void) {
    radio_config_t defaults = RADIO_DEFAULTS, decoded;
    uint8_t data[10];
    radio_config_encode(data, &defaults);
    const uint8_t expected[] = {80, 0, 160, 0, 64, 1, 128, 2, 60, 0};
    assert(memcmp(expected, data, sizeof(data)) == 0);
    assert(radio_config_decode(&decoded, data));
    assert(decoded.fast_min == 80 && decoded.slow_max == 640 && decoded.idle_seconds == 60);
    radio_config_t bounds = {32, 32, 3200, 3200, 5, 3, 3};
    assert(radio_config_valid(&bounds));
    bounds.idle_seconds = 3600; assert(radio_config_valid(&bounds));
    bounds.idle_seconds = 3601; assert(!radio_config_valid(&bounds));
    bounds = defaults; bounds.fast_min = 31; assert(!radio_config_valid(&bounds));
    bounds = defaults; bounds.fast_max = 79; assert(!radio_config_valid(&bounds));
    bounds = defaults; bounds.slow_min = 79; assert(!radio_config_valid(&bounds));
    bounds = defaults; bounds.slow_min = 641; assert(!radio_config_valid(&bounds));
    bounds = defaults; bounds.slow_max = 3201; assert(!radio_config_valid(&bounds));
    bounds = defaults; bounds.idle_seconds = 4; assert(!radio_config_valid(&bounds));
    uint8_t nonce[16], transcript[RADIO_TRANSCRIPT_SIZE];
    for (unsigned i = 0; i < sizeof(nonce); i++) nonce[i] = i;
    radio_transcript(transcript, nonce, data);
    assert(sizeof(transcript) == 49);
    assert(memcmp(transcript, "BLEKEY-RADIO1\0car-main\0", 23) == 0);
    assert(memcmp(transcript + 23, nonce, 16) == 0);
    assert(memcmp(transcript + 39, expected, 10) == 0);
    uint8_t data2[RADIO_CONFIG2_SIZE], transcript2[RADIO_TRANSCRIPT2_SIZE];
    for (int power = -128; power <= 127; ++power) {
        bounds = defaults; bounds.tx_power_dbm = power; bounds.idle_tx_power_dbm = power;
        bool valid = power >= -12 && power <= 9 && power % 3 == 0;
        assert(radio_config_valid(&bounds) == valid);
        radio_config2_encode(data2, &bounds);
        assert(radio_config2_decode(&decoded, data2) == valid);
        if (valid) assert(decoded.tx_power_dbm == power);
    }
    bounds = defaults; bounds.tx_power_dbm = -12;
    radio_config2_encode(data2, &bounds);
    radio_transcript2(transcript2, nonce, data2);
    assert(sizeof(transcript2) == 50);
    assert(memcmp(transcript2, "BLEKEY-RADIO2\0car-main\0", 23) == 0);
    assert(memcmp(transcript2 + 23, nonce, 16) == 0);
    assert(memcmp(transcript2 + 39, data2, 11) == 0);
    assert(data2[10] == 244);
    // A legacy settings write preserves its original wire encoding.
    radio_config_encode(data, &bounds);
    assert(memcmp(expected, data, sizeof(data)) == 0);
    uint8_t data3[RADIO_CONFIG3_SIZE], transcript3[RADIO_TRANSCRIPT3_SIZE];
    for (int recent = -15; recent <= 12; ++recent) {
        for (int idle = -15; idle <= 12; ++idle) {
            bounds = defaults; bounds.tx_power_dbm = recent; bounds.idle_tx_power_dbm = idle;
            bool valid = radio_tx_valid(recent) && radio_tx_valid(idle) && idle <= recent;
            assert(radio_config_valid(&bounds) == valid);
            radio_config3_encode(data3, &bounds);
            assert(radio_config3_decode(&decoded, data3) == valid);
            if (valid) assert(decoded.tx_power_dbm == recent && decoded.idle_tx_power_dbm == idle);
        }
    }
    bounds = defaults; bounds.tx_power_dbm = 9; bounds.idle_tx_power_dbm = -12;
    radio_config3_encode(data3, &bounds);
    radio_transcript3(transcript3, nonce, data3);
    assert(sizeof(transcript3) == 51);
    assert(memcmp(transcript3, "BLEKEY-RADIO3\0car-main\0", 23) == 0);
    assert(memcmp(transcript3 + 39, data3, 12) == 0);
    assert(data3[10] == 9 && data3[11] == 244);
    assert(radio_power_target(&bounds, 999, 1000, false) == 9);
    assert(radio_power_target(&bounds, 1000, 1000, false) == -12);
    assert(radio_power_target(&bounds, 5000, 1000, true) == 9);
    // Old fixed-power writes map to equal recent/inactive levels.
    radio_config2_encode(data2, &bounds);
    assert(radio_config2_decode(&decoded, data2));
    assert(decoded.tx_power_dbm == 9 && decoded.idle_tx_power_dbm == 9);
    return 0;
}
