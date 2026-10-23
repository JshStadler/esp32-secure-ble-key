#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

#define id(value) value
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
static std::vector<uint16_t> gate_ble_conn_ids{10, 20, 65535};
static std::vector<bool> gate_ble_closing{false, false, false};
static int accepted;
#include "gate_session_under_test.inc"

int main() {
  for (auto handler : {gate_ble_command, gate_ble_command_part1, gate_ble_command_part2}) {
    accepted = 0;
    handler(10);
    assert(accepted == 1);
    // Timeout/auth-failure starts an asynchronous close; packets can still
    // arrive before the disconnection callback frees this connection slot.
    gate_ble_closing[0] = true;
    handler(10);
    assert(accepted == 1);
    handler(20);
    assert(accepted == 2);  // Another client's live session remains usable.
    handler(99);
    assert(accepted == 2);
    // Once disconnected and reused, the new session may accept commands.
    gate_ble_conn_ids[0] = 30;
    gate_ble_closing[0] = false;
    handler(10);
    assert(accepted == 2);
    handler(30);
    assert(accepted == 3);
    gate_ble_conn_ids[0] = 10;
  }
  puts("gate closing-session guards: passed");
}
