#pragma once
#include <stdint.h>
#define ESP_OK 0
typedef enum {
    ESP_PWR_LVL_N24, ESP_PWR_LVL_N21, ESP_PWR_LVL_N18, ESP_PWR_LVL_N15,
    ESP_PWR_LVL_N12, ESP_PWR_LVL_N9, ESP_PWR_LVL_N6, ESP_PWR_LVL_N3,
    ESP_PWR_LVL_N0, ESP_PWR_LVL_P3, ESP_PWR_LVL_P6, ESP_PWR_LVL_P9,
    ESP_PWR_LVL_P12, ESP_PWR_LVL_P15, ESP_PWR_LVL_P18, ESP_PWR_LVL_P20,
    ESP_PWR_LVL_INVALID = 255,
} esp_power_level_t;
typedef enum { ESP_BLE_PWR_TYPE_DEFAULT, ESP_BLE_PWR_TYPE_ADV } esp_ble_power_type_t;
typedef enum { ESP_BLE_ENHANCED_PWR_TYPE_CONN } esp_ble_enhanced_power_type_t;
int esp_ble_tx_power_set(esp_ble_power_type_t, esp_power_level_t);
esp_power_level_t esp_ble_tx_power_get(esp_ble_power_type_t);
int esp_ble_tx_power_set_enhanced(esp_ble_enhanced_power_type_t, uint16_t, esp_power_level_t);
esp_power_level_t esp_ble_tx_power_get_enhanced(esp_ble_enhanced_power_type_t, uint16_t);
