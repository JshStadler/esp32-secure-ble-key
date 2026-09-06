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
    radio_config_t bounds = {32, 32, 3200, 3200, 5};
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
    return 0;
}
