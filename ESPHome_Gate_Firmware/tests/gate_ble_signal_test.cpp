#include <cassert>
#include "gate_ble_signal.h"

uint32_t esphome::test_now = 0;
int test_requests = 0, test_enqueue_result = ESP_OK;
using esphome::gate_ble_signal::GateBLESignal;
const std::vector<uint8_t> REQUEST{1, 2, 3, 4, 5, 6, 7, 8};

static void connect(GateBLESignal &signal, uint16_t conn, uint8_t address) {
  esp_ble_gatts_cb_param_t param{};
  param.connect.conn_id = conn;
  param.connect.remote_bda[0] = address;
  signal.gatts_event_handler(ESP_GATTS_CONNECT_EVT, 1, &param);
}
static void disconnect(GateBLESignal &signal, uint16_t conn) {
  esp_ble_gatts_cb_param_t param{};
  param.disconnect.conn_id = conn;
  signal.gatts_event_handler(ESP_GATTS_DISCONNECT_EVT, 1, &param);
}
static void complete(GateBLESignal &signal, uint8_t address, int8_t rssi, int status = 0) {
  esp_ble_gap_cb_param_t param{};
  param.read_rssi_cmpl.remote_addr[0] = address;
  param.read_rssi_cmpl.rssi = rssi;
  param.read_rssi_cmpl.status = status;
  signal.gap_event_handler(ESP_GAP_BLE_READ_RSSI_COMPLETE_EVT, &param);
}

int main() {
  esphome::esp32_ble_server::BLEServer server;
  GateBLESignal signal;
  signal.set_server(&server);
  for (uint16_t i = 0; i < 5; ++i) connect(signal, i, i + 10);
  assert(test_requests == 0);  // Connection setup must never poll RSSI.
  assert(signal.read(50).empty());
  signal.request(0, REQUEST);
  assert(test_requests == 1 && signal.read(0)[0] == 0);
  complete(signal, 11, -40);  // Another client's result must not satisfy it.
  assert(signal.read(0)[0] == 0);
  complete(signal, 10, -84);
  const auto result = signal.read(0);
  assert(result.size() == 10 && result[0] == 1 && int8_t(result[9]) == -84);
  assert(std::equal(REQUEST.begin(), REQUEST.end(), result.begin() + 1));
  assert(signal.read(1)[0] == 2);

  // A reconnect at exactly the same address and connection ID must not claim
  // the old request. Wait for its callback to drain before submitting another.
  signal.request(0, REQUEST);
  disconnect(signal, 0);
  connect(signal, 0, 10);
  const std::vector<uint8_t> next{8, 7, 6, 5, 4, 3, 2, 1};
  signal.request(0, next);
  assert(signal.read(0)[0] == 2);
  complete(signal, 10, -20);
  assert(signal.read(0)[0] == 2);
  signal.request(0, next);
  complete(signal, 10, -70);
  assert(signal.read(0)[0] == 1 && int8_t(signal.read(0)[9]) == -70);

  // Timeout across millis wrap, late result, invalid RSSI, API failure, reset.
  esphome::test_now = 0xffffff00U;
  signal.request(1, REQUEST);
  esphome::test_now += 2100;
  assert(signal.read(1)[0] == 2);
  complete(signal, 11, -50);
  assert(signal.read(1)[0] == 2);
  signal.request(2, REQUEST);
  complete(signal, 12, 127);
  assert(signal.read(2)[0] == 2);
  signal.request(2, REQUEST);
  complete(signal, 12, -60, 1);
  assert(signal.read(2)[0] == 2);
  test_enqueue_result = 1;
  signal.request(3, REQUEST);
  assert(signal.read(3)[0] == 2);
  test_enqueue_result = 0;
  signal.request(4, REQUEST);
  signal.ble_before_disabled_event_handler();
  complete(signal, 14, -10);
  assert(signal.read(4).empty());
  connect(signal, 4, 14);
  signal.request(4, REQUEST);
  complete(signal, 14, -90);
  assert(signal.read(4)[0] == 1);
  signal.request(4, {});
  assert(signal.read(4)[0] == 2);
}
