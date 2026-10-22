#pragma once
#include "radio_config.h"
#include "esp_bt.h"

typedef enum { RADIO_UPDATE_OK, RADIO_UPDATE_APPLY, RADIO_UPDATE_SAVE, RADIO_UPDATE_RESTORE } radio_update_result_t;

static inline esp_power_level_t radio_power_level(int dbm) {
    switch (dbm) {
        case -12: return ESP_PWR_LVL_N12;
        case -9: return ESP_PWR_LVL_N9;
        case -6: return ESP_PWR_LVL_N6;
        case -3: return ESP_PWR_LVL_N3;
        case 0: return ESP_PWR_LVL_N0;
        case 3: return ESP_PWR_LVL_P3;
        case 6: return ESP_PWR_LVL_P6;
        case 9: return ESP_PWR_LVL_P9;
        default: return ESP_PWR_LVL_INVALID;
    }
}

/* Return the controller's selected level, not an estimate from RSSI.
 * 127 denotes unavailable, and is never formatted as a dBm reading. */
static inline int radio_power_dbm(esp_power_level_t level) {
    switch (level) {
        case ESP_PWR_LVL_N24: return -24;
        case ESP_PWR_LVL_N21: return -21;
        case ESP_PWR_LVL_N18: return -18;
        case ESP_PWR_LVL_N15: return -15;
        case ESP_PWR_LVL_N12: return -12;
        case ESP_PWR_LVL_N9: return -9;
        case ESP_PWR_LVL_N6: return -6;
        case ESP_PWR_LVL_N3: return -3;
        case ESP_PWR_LVL_N0: return 0;
        case ESP_PWR_LVL_P3: return 3;
        case ESP_PWR_LVL_P6: return 6;
        case ESP_PWR_LVL_P9: return 9;
        case ESP_PWR_LVL_P12: return 12;
        case ESP_PWR_LVL_P15: return 15;
        case ESP_PWR_LVL_P18: return 18;
        case ESP_PWR_LVL_P20: return 20;
        default: return 127;
    }
}

static inline bool radio_power_connection(uint16_t handle, int dbm) {
    esp_power_level_t level = radio_power_level(dbm);
    return level != ESP_PWR_LVL_INVALID &&
        esp_ble_tx_power_set_enhanced(ESP_BLE_ENHANCED_PWR_TYPE_CONN, handle, level) == ESP_OK &&
        esp_ble_tx_power_get_enhanced(ESP_BLE_ENHANCED_PWR_TYPE_CONN, handle) == level;
}

static inline bool radio_power_apply(int dbm, const uint16_t *handles, unsigned count) {
    esp_power_level_t level = radio_power_level(dbm);
    if (level == ESP_PWR_LVL_INVALID) return false;
    bool ok = esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, level) == ESP_OK;
    if (esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, level) != ESP_OK) ok = false;
    if (esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_DEFAULT) != level ||
        esp_ble_tx_power_get(ESP_BLE_PWR_TYPE_ADV) != level) ok = false;
    for (unsigned i = 0; i < count; ++i)
        if (!radio_power_connection(handles[i], dbm)) ok = false;
    return ok;
}

/* Never persist a power setting the controller rejected. Restore all links on
 * partial failure; callers explicitly report if that restoration also fails. */
static inline radio_update_result_t radio_power_update(const radio_config_t *requested,
        const radio_config_t *previous, const uint16_t *handles, unsigned count,
        bool (*save)(const radio_config_t *)) {
    if (!radio_config_valid(requested)) return RADIO_UPDATE_APPLY;
    bool applied = radio_power_apply(requested->tx_power_dbm, handles, count);
    if (applied && save(requested)) return RADIO_UPDATE_OK;
    if (!radio_power_apply(previous->tx_power_dbm, handles, count)) return RADIO_UPDATE_RESTORE;
    return applied ? RADIO_UPDATE_SAVE : RADIO_UPDATE_APPLY;
}
