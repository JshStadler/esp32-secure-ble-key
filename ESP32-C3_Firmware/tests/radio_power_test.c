#include <assert.h>
#include "radio_power.h"

static const uint16_t handles[] = {123, 513, 8};
static esp_power_level_t levels[5];
static int calls, fail_call, saves;
static bool save_ok = true, fail_restore, bad_readback;
static int set(unsigned index, esp_power_level_t power) {
    if (++calls == fail_call || (fail_restore && power == ESP_PWR_LVL_P3)) return 1;
    levels[index] = power; return 0;
}
int esp_ble_tx_power_set(esp_ble_power_type_t type, esp_power_level_t power) { return set(type, power); }
esp_power_level_t esp_ble_tx_power_get(esp_ble_power_type_t type) {
    return bad_readback && levels[type] == ESP_PWR_LVL_P9 ? ESP_PWR_LVL_INVALID : levels[type];
}
static unsigned connection(esp_ble_enhanced_power_type_t type, uint16_t handle) {
    assert(type == ESP_BLE_ENHANCED_PWR_TYPE_CONN);
    for (unsigned i = 0; i < 3; ++i) if (handle == handles[i]) return i + 2;
    assert(false); return 0;
}
int esp_ble_tx_power_set_enhanced(esp_ble_enhanced_power_type_t type, uint16_t handle, esp_power_level_t power) {
    return set(connection(type, handle), power);
}
esp_power_level_t esp_ble_tx_power_get_enhanced(esp_ble_enhanced_power_type_t type, uint16_t handle) {
    return levels[connection(type, handle)];
}
static bool save(const radio_config_t *config) {
    assert(config->tx_power_dbm == 9); saves++; return save_ok;
}
static void reset(void) {
    calls = fail_call = saves = 0; save_ok = true; fail_restore = bad_readback = false;
    for (unsigned i = 0; i < 5; ++i) levels[i] = ESP_PWR_LVL_P3;
}
static void split(esp_power_level_t link, esp_power_level_t advertising) {
    assert(levels[ESP_BLE_PWR_TYPE_DEFAULT] == link);
    assert(levels[ESP_BLE_PWR_TYPE_ADV] == advertising);
    for (unsigned i = 2; i < 5; ++i) assert(levels[i] == link);
}
static void all(esp_power_level_t level) {
    for (unsigned i = 0; i < 5; ++i) assert(levels[i] == level);
}
int main(void) {
    const radio_config_t previous = RADIO_DEFAULTS;
    radio_config_t requested = previous; requested.tx_power_dbm = 9;
    reset();
    assert(radio_power_update(&requested, &previous, previous.tx_power_dbm, handles, 3, save) == RADIO_UPDATE_OK);
    assert(saves == 1); all(ESP_PWR_LVL_P9);
    for (int failure = 1; failure <= 5; ++failure) {
        reset(); fail_call = failure;
        assert(radio_power_update(&requested, &previous, previous.tx_power_dbm, handles, 3, save) == RADIO_UPDATE_APPLY);
        assert(saves == 0); all(ESP_PWR_LVL_P3);
    }
    reset(); save_ok = false;
    assert(radio_power_update(&requested, &previous, previous.tx_power_dbm, handles, 3, save) == RADIO_UPDATE_SAVE);
    assert(saves == 1); all(ESP_PWR_LVL_P3);
    reset(); bad_readback = true;
    assert(radio_power_update(&requested, &previous, previous.tx_power_dbm, handles, 3, save) == RADIO_UPDATE_APPLY);
    assert(saves == 0); all(ESP_PWR_LVL_P3);
    reset(); save_ok = false; fail_restore = true;
    assert(radio_power_update(&requested, &previous, previous.tx_power_dbm, handles, 3, save) == RADIO_UPDATE_RESTORE);
    reset(); requested.tx_power_dbm = 10;
    assert(radio_power_update(&requested, &previous, previous.tx_power_dbm, handles, 3, save) == RADIO_UPDATE_APPLY);
    assert(calls == 0 && saves == 0);
    for (int dbm = -12; dbm <= 9; dbm += 3) {
        reset(); assert(radio_power_apply(dbm, handles, 3));
        assert(radio_power_dbm(levels[0]) == dbm);
        assert(radio_power_dbm(levels[4]) == dbm);
    }
    assert(radio_power_dbm(ESP_PWR_LVL_INVALID) == 127);
    // Shared deadline switches only advertising; every connected link stays high.
    radio_config_t dual = previous; dual.tx_power_dbm = 9; dual.idle_tx_power_dbm = 3;
    radio_power_state_t state = RADIO_POWER_STATE_INITIAL;
    reset();
    assert(radio_power_sync(&state, &dual, 0, 60000, false, handles, 3, false));
    all(ESP_PWR_LVL_P9); assert(calls == 5);
    assert(!radio_power_sync(&state, &dual, 59999, 60000, false, handles, 3, false));
    assert(calls == 5);
    assert(radio_power_sync(&state, &dual, 60000, 60000, false, handles, 3, false));
    split(ESP_PWR_LVL_P9, ESP_PWR_LVL_P3);
    // Activity extends deadline; a callback for the old deadline cannot lower it.
    assert(radio_power_sync(&state, &dual, 60001, 120001, false, handles, 3, false));
    assert(!radio_power_sync(&state, &dual, 60002, 120001, false, handles, 3, false));
    all(ESP_PWR_LVL_P9);
    // A newly allocated controller handle still needs applying in the same phase.
    levels[4] = ESP_PWR_LVL_P3;
    assert(radio_power_sync(&state, &dual, 60002, 120001, false, handles, 3, true));
    all(ESP_PWR_LVL_P9);
    // OTA holds advertising high; finishing releases only advertising.
    assert(!radio_power_sync(&state, &dual, 120002, 120001, true, handles, 3, false));
    all(ESP_PWR_LVL_P9);
    assert(radio_power_sync(&state, &dual, 120003, 120001, false, handles, 3, false));
    split(ESP_PWR_LVL_P9, ESP_PWR_LVL_P3);
    // Failed idle transition restores every link to recent power; bounded retry.
    state = (radio_power_state_t)RADIO_POWER_STATE_INITIAL;
    reset(); fail_call = 3;
    assert(!radio_power_sync(&state, &dual, 100, 100, false, handles, 3, false));
    all(ESP_PWR_LVL_P9); assert(state.retry_after_ms == 5100);
    int before = calls;
    assert(!radio_power_sync(&state, &dual, 5099, 100, false, handles, 3, false));
    assert(calls == before);
    assert(radio_power_sync(&state, &dual, 5100, 100, false, handles, 3, false));
    split(ESP_PWR_LVL_P9, ESP_PWR_LVL_P3);
    reset(); fail_call = 1; bad_readback = true;
    state = (radio_power_state_t)RADIO_POWER_STATE_INITIAL;
    assert(!radio_power_sync(&state, &dual, 100, 100, false, handles, 3, false));
    assert(state.applied_dbm == 127 && state.retry_after_ms == 5100);
    // Saving during inactive advertising restores independent link/ADV levels.
    reset(); save_ok = false;
    assert(radio_power_update(&dual, &previous, 0, handles, 3, save) == RADIO_UPDATE_SAVE);
    split(ESP_PWR_LVL_P3, ESP_PWR_LVL_N0);
    // One or all connected devices stay at high TX after any idle duration.
    for (unsigned count = 0; count <= 3; ++count) {
        reset(); state = (radio_power_state_t)RADIO_POWER_STATE_INITIAL;
        assert(radio_power_sync(&state, &dual, 1000000, 0, false, handles, count, false));
        assert(levels[ESP_BLE_PWR_TYPE_DEFAULT] == ESP_PWR_LVL_P9);
        assert(levels[ESP_BLE_PWR_TYPE_ADV] == ESP_PWR_LVL_P3);
        for (unsigned i = 0; i < count; ++i) assert(levels[i + 2] == ESP_PWR_LVL_P9);
    }
    return 0;
}
