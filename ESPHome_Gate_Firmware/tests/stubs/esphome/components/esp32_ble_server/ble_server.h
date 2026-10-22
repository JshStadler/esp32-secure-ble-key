#pragma once
#include <cstdint>
using esp_gatt_if_t = uint8_t;
constexpr int ESP_OK = 0, ESP_BT_STATUS_SUCCESS = 0;
enum esp_gatts_cb_event_t { ESP_GATTS_CONNECT_EVT, ESP_GATTS_DISCONNECT_EVT };
enum esp_gap_ble_cb_event_t { ESP_GAP_BLE_READ_RSSI_COMPLETE_EVT, OTHER_GAP_EVENT };
struct esp_ble_gatts_cb_param_t {
  struct { uint16_t conn_id; uint8_t remote_bda[6]; } connect{};
  struct { uint16_t conn_id; } disconnect{};
};
struct esp_ble_gap_cb_param_t {
  struct { int status; int8_t rssi; uint8_t remote_addr[6]; } read_rssi_cmpl{};
};
extern int test_requests, test_enqueue_result;
inline int esp_ble_gap_read_rssi(uint8_t *) { ++test_requests; return test_enqueue_result; }
namespace esphome::esp32_ble_server {
class BLEServer { public: esp_gatt_if_t get_gatts_if() { return 1; } };
}
