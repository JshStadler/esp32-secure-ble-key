#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#include "esphome/core/component.h"
#include "esphome/components/esp32_ble_server/ble_server.h"

namespace esphome::gate_ble_signal {

// Diagnostic only: YAML checks application authentication before request/read.
// No scanning, timer or periodic polling. BLE callbacks run on ESPHome's loop.
class GateBLESignal : public Component {
 public:
  void set_server(esp32_ble_server::BLEServer *server) { server_ = server; }

  void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t iface,
                           esp_ble_gatts_cb_param_t *param) {
    if (server_ == nullptr || iface != server_->get_gatts_if()) return;
    if (event == ESP_GATTS_CONNECT_EVT) {
      for (auto &session : sessions_) {
        if (session.conn != NO_CONNECTION) continue;
        session = Session{};
        session.conn = param->connect.conn_id;
        session.generation = ++generation_;
        memcpy(session.address.data(), param->connect.remote_bda, 6);
        return;
      }
    } else if (event == ESP_GATTS_DISCONNECT_EVT) {
      auto *session = find_(param->disconnect.conn_id);
      if (session != nullptr) *session = Session{};
      // Retain an outstanding controller request until its callback arrives.
      // A new session, even at the same address/connection ID, cannot claim it.
    }
  }

  void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    if (event != ESP_GAP_BLE_READ_RSSI_COMPLETE_EVT || !pending_ ||
        memcmp(pending_address_.data(), param->read_rssi_cmpl.remote_addr, 6) != 0) return;
    pending_ = false;
    auto *session = find_(pending_conn_);
    if (session == nullptr || session->generation != pending_generation_ ||
        session->request != pending_request_ || session->state != WAITING) return;
    const auto &result = param->read_rssi_cmpl;
    const bool valid = result.status == ESP_BT_STATUS_SUCCESS && result.rssi >= -127 && result.rssi <= 20;
    session->state = valid ? READY : UNAVAILABLE;
    session->rssi = valid ? result.rssi : 127;
  }

  void ble_before_disabled_event_handler() {
    sessions_ = {};
    pending_ = false;
  }

  void request(uint16_t conn, const std::vector<uint8_t> &request) {
    auto *session = find_(conn);
    if (session == nullptr) return;
    session->state = UNAVAILABLE;
    session->rssi = 127;
    session->request.fill(0);
    if (request.size() != session->request.size()) return;
    std::copy(request.begin(), request.end(), session->request.begin());
    if (pending_) return;  // Optional diagnostic must never obstruct key use.
    pending_ = true;
    pending_conn_ = conn;
    pending_generation_ = session->generation;
    pending_request_ = session->request;
    pending_address_ = session->address;
    session->started = millis();
    session->state = WAITING;
    if (esp_ble_gap_read_rssi(session->address.data()) != ESP_OK) {
      pending_ = false;
      session->state = UNAVAILABLE;
    }
  }

  std::vector<uint8_t> read(uint16_t conn) {
    auto *session = find_(conn);
    if (session == nullptr) return {};
    if (session->state == WAITING && uint32_t(millis() - session->started) >= 2000)
      session->state = UNAVAILABLE;
    std::vector<uint8_t> value{session->state};
    value.insert(value.end(), session->request.begin(), session->request.end());
    value.push_back(static_cast<uint8_t>(session->state == READY ? session->rssi : 127));
    return value;
  }

 private:
  static constexpr uint16_t NO_CONNECTION = 65535;
  static constexpr uint8_t WAITING = 0, READY = 1, UNAVAILABLE = 2;
  struct Session {
    uint16_t conn{NO_CONNECTION};
    uint32_t generation{0}, started{0};
    std::array<uint8_t, 6> address{};
    std::array<uint8_t, 8> request{};
    uint8_t state{UNAVAILABLE};
    int8_t rssi{127};
  };
  Session *find_(uint16_t conn) {
    for (auto &session : sessions_) if (session.conn == conn && conn != NO_CONNECTION) return &session;
    return nullptr;
  }
  esp32_ble_server::BLEServer *server_{nullptr};
  std::array<Session, 5> sessions_{};
  uint32_t generation_{0}, pending_generation_{0};
  uint16_t pending_conn_{NO_CONNECTION};
  std::array<uint8_t, 6> pending_address_{};
  std::array<uint8_t, 8> pending_request_{};
  bool pending_{false};
};
}  // namespace esphome::gate_ble_signal
