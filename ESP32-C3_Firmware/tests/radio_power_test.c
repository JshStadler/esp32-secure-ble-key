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
static void all(esp_power_level_t level) {
    for (unsigned i = 0; i < 5; ++i) assert(levels[i] == level);
}
int main(void) {
    const radio_config_t previous = RADIO_DEFAULTS;
    radio_config_t requested = previous; requested.tx_power_dbm = 9;
    reset();
    assert(radio_power_update(&requested, &previous, handles, 3, save) == RADIO_UPDATE_OK);
    assert(saves == 1); all(ESP_PWR_LVL_P9);
    for (int failure = 1; failure <= 5; ++failure) {
        reset(); fail_call = failure;
        assert(radio_power_update(&requested, &previous, handles, 3, save) == RADIO_UPDATE_APPLY);
        assert(saves == 0); all(ESP_PWR_LVL_P3);
    }
    reset(); save_ok = false;
    assert(radio_power_update(&requested, &previous, handles, 3, save) == RADIO_UPDATE_SAVE);
    assert(saves == 1); all(ESP_PWR_LVL_P3);
    reset(); bad_readback = true;
    assert(radio_power_update(&requested, &previous, handles, 3, save) == RADIO_UPDATE_APPLY);
    assert(saves == 0); all(ESP_PWR_LVL_P3);
    reset(); save_ok = false; fail_restore = true;
    assert(radio_power_update(&requested, &previous, handles, 3, save) == RADIO_UPDATE_RESTORE);
    reset(); requested.tx_power_dbm = 10;
    assert(radio_power_update(&requested, &previous, handles, 3, save) == RADIO_UPDATE_APPLY);
    assert(calls == 0 && saves == 0);
    for (int dbm = -12; dbm <= 9; dbm += 3) {
        reset(); assert(radio_power_apply(dbm, handles, 3));
        assert(radio_power_dbm(levels[0]) == dbm);
        assert(radio_power_dbm(levels[4]) == dbm);
    }
    assert(radio_power_dbm(ESP_PWR_LVL_INVALID) == 127);
    return 0;
}
