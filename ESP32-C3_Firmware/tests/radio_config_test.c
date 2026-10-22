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
    radio_config_t bounds = {32, 32, 3200, 3200, 5, 3};
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
        bounds = defaults; bounds.tx_power_dbm = power;
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
    return 0;
}
