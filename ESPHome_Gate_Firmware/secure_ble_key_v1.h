#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "esp_random.h"
#include "esp_timer.h"
#include "psa/crypto.h"

namespace secure_ble_key_v1 {

constexpr size_t NONCE_LENGTH = 16;
constexpr size_t HMAC_LENGTH = 32;
constexpr uint8_t COMMAND_AUTH_ONLY = 0x01;
constexpr uint8_t COMMAND_PRESS = 0x02;
constexpr int64_t SPLIT_TIMEOUT_MS = 5000;
constexpr int64_t PRESS_COOLDOWN_MS = 1000;

enum class CommandResult : uint8_t {
  AUTHENTICATED,
  PRESS,
  AUTH_ERROR,
  BUSY,
  UNKNOWN_COMMAND,
  BAD_LENGTH,
  CRYPTO_ERROR,
  SPLIT_STORED,
  SPLIT_MISSING,
  SPLIT_CLIENT_MISMATCH,
  SPLIT_TIMEOUT,
};

class Protocol {
 public:
  bool begin(const std::string &psk) {
    psk_ = psk;
    initialized_ = !psk_.empty() && psa_crypto_init() == PSA_SUCCESS;
    rotate_nonce();
    clear_split();
    return initialized_;
  }

  void on_connect(uint16_t client_id) {
    active_client_id_ = client_id;
    rotate_nonce();
    clear_split();
  }

  void on_disconnect(uint16_t client_id) {
    if (active_client_id_ == client_id) {
      active_client_id_ = 0xFFFF;
      clear_split();
    }
  }

  std::vector<uint8_t> challenge() const {
    return std::vector<uint8_t>(nonce_.begin(), nonce_.end());
  }

  CommandResult process_full(const std::vector<uint8_t> &data) {
    if (data.size() != 1 + HMAC_LENGTH) {
      rotate_nonce();
      return CommandResult::BAD_LENGTH;
    }
    return verify(data[0], data.data() + 1, HMAC_LENGTH);
  }

  CommandResult store_split_part1(const std::vector<uint8_t> &data, uint16_t client_id) {
    if (data.size() != 17) {
      clear_split();
      return CommandResult::BAD_LENGTH;
    }

    split_command_ = data[0];
    std::copy_n(data.begin() + 1, split_hmac_part1_.size(), split_hmac_part1_.begin());
    split_client_id_ = client_id;
    split_started_ms_ = now_ms();
    split_pending_ = true;
    return CommandResult::SPLIT_STORED;
  }

  CommandResult process_split_part2(const std::vector<uint8_t> &data, uint16_t client_id) {
    if (data.size() != 16) {
      clear_split();
      return CommandResult::BAD_LENGTH;
    }
    if (!split_pending_) {
      return CommandResult::SPLIT_MISSING;
    }
    if (split_client_id_ != client_id) {
      clear_split();
      return CommandResult::SPLIT_CLIENT_MISMATCH;
    }
    if (now_ms() - split_started_ms_ > SPLIT_TIMEOUT_MS) {
      clear_split();
      return CommandResult::SPLIT_TIMEOUT;
    }

    std::array<uint8_t, HMAC_LENGTH> hmac{};
    std::copy(split_hmac_part1_.begin(), split_hmac_part1_.end(), hmac.begin());
    std::copy(data.begin(), data.end(), hmac.begin() + split_hmac_part1_.size());
    const uint8_t command = split_command_;
    clear_split();
    return verify(command, hmac.data(), hmac.size());
  }

 private:
  static int64_t now_ms() { return esp_timer_get_time() / 1000; }

  void rotate_nonce() { esp_fill_random(nonce_.data(), nonce_.size()); }

  void clear_split() {
    split_pending_ = false;
    split_command_ = 0;
    split_client_id_ = 0xFFFF;
    split_started_ms_ = 0;
    split_hmac_part1_.fill(0);
  }

  bool compute_hmac(std::array<uint8_t, HMAC_LENGTH> &output) const {
    if (!initialized_) return false;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, psk_.size() * 8);

    psa_key_id_t key_id = 0;
    psa_status_t status = psa_import_key(
        &attributes, reinterpret_cast<const uint8_t *>(psk_.data()), psk_.size(), &key_id);
    psa_reset_key_attributes(&attributes);

    size_t output_length = 0;
    if (status == PSA_SUCCESS) {
      status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), nonce_.data(), nonce_.size(),
                               output.data(), output.size(), &output_length);
    }
    if (key_id != 0) psa_destroy_key(key_id);
    return status == PSA_SUCCESS && output_length == output.size();
  }

  CommandResult verify(uint8_t command, const uint8_t *received_hmac, size_t hmac_length) {
    if (command != COMMAND_AUTH_ONLY && command != COMMAND_PRESS) {
      return CommandResult::UNKNOWN_COMMAND;
    }
    if (hmac_length != HMAC_LENGTH) {
      rotate_nonce();
      return CommandResult::BAD_LENGTH;
    }

    std::array<uint8_t, HMAC_LENGTH> expected{};
    const bool computed = compute_hmac(expected);

    uint8_t difference = 0;
    if (computed) {
      for (size_t i = 0; i < expected.size(); ++i) {
        difference |= expected[i] ^ received_hmac[i];
      }
    }
    expected.fill(0);

    // Rotate after every verification attempt, successful or not, to prevent replay.
    rotate_nonce();
    if (!computed) return CommandResult::CRYPTO_ERROR;
    if (difference != 0) return CommandResult::AUTH_ERROR;
    if (command == COMMAND_AUTH_ONLY) return CommandResult::AUTHENTICATED;

    const int64_t current_ms = now_ms();
    if (has_pressed_ && current_ms - last_press_ms_ < PRESS_COOLDOWN_MS) {
      return CommandResult::BUSY;
    }
    has_pressed_ = true;
    last_press_ms_ = current_ms;
    return CommandResult::PRESS;
  }

  std::string psk_;
  bool initialized_{false};
  std::array<uint8_t, NONCE_LENGTH> nonce_{};
  uint16_t active_client_id_{0xFFFF};

  bool split_pending_{false};
  uint8_t split_command_{0};
  uint16_t split_client_id_{0xFFFF};
  int64_t split_started_ms_{0};
  std::array<uint8_t, 16> split_hmac_part1_{};

  bool has_pressed_{false};
  int64_t last_press_ms_{0};
};

inline Protocol gate_protocol;

}  // namespace secure_ble_key_v1
