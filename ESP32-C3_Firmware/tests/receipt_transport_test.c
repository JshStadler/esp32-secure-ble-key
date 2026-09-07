#include <assert.h>
#include <stdio.h>
#include <mbedtls/md.h>
#include "press_receipt.h"
#define MAX_AUTH_FAILURES 5
#define BLE_GATT_ACCESS_OP_READ_CHR 0
#define BLE_GATT_ACCESS_OP_WRITE_CHR 1
#define BLE_ATT_ERR_UNLIKELY 1
#define BLE_ATT_ERR_INSUFFICIENT_RES 2
#define BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN 3
#define BLE_ATT_ERR_INSUFFICIENT_AUTHEN 4
#define BLE_ERR_CONN_TERM_LOCAL 5
struct os_mbuf { uint8_t bytes[128]; uint16_t len; };
struct ble_gatt_access_ctxt { int op; struct os_mbuf *om; };
#define OS_MBUF_PKTLEN(om) ((om)->len)
typedef struct {
    uint8_t receipt_id[16], receipt_mac[16], receipt_op, receipt_reply[19], nonce[16], auth_failures;
    bool receipt_context, receipt_part, receipt_valid, closing;
    int64_t receipt_started;
} client_state_t;
static client_state_t clients[3];
static press_receipt_t press_receipts[RECEIPT_SLOTS];
static int receipt_button_slot = -1;
static bool button_busy;
static char current_psk[] = "synthetic-review-key";
static int64_t fake_now;
static int pulse_count;
static int ensure_client_slot(uint16_t handle) { return handle < 3 && !clients[handle].closing ? handle : -1; }
static int os_mbuf_append(struct os_mbuf *om, const void *p, size_t n) { memcpy(om->bytes + om->len, p, n); om->len += n; return 0; }
static int os_mbuf_copydata(struct os_mbuf *om, int offset, size_t n, void *p) { memcpy(p, om->bytes + offset, n); return 0; }
static int64_t now_ms(void) { return fake_now; }
static bool compute_hmac(const uint8_t *p, size_t n, const char *key, uint8_t out[32]) {
    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)key, strlen(key), p, n, out) == 0;
}
static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0; for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i]; return diff == 0;
}
static void generate_nonce_for_slot(int slot, bool notify) { (void)notify; clients[slot].nonce[0]++; }
static void ble_gap_terminate(uint16_t handle, int reason) { (void)handle; (void)reason; }
static void mark_authenticated(uint16_t handle) { clients[handle].auth_failures = 0; }
static void mark_ble_activity(void) {}
static void schedule_receipt_expiry(void) {}
static bool press_remote_button(void) { pulse_count++; button_busy = true; return true; }
#include "receipt_under_test.inc"

static int fragment(int handle, const uint8_t *packet, size_t n) {
    struct os_mbuf om = { .len = (uint16_t)n }; memcpy(om.bytes, packet, n);
    struct ble_gatt_access_ctxt ctxt = {BLE_GATT_ACCESS_OP_WRITE_CHR, &om};
    return chr_access_receipt(handle, 0, &ctxt, NULL);
}
static int exchange(int handle, uint8_t op, const uint8_t id[16], bool tamper) {
    uint8_t nonce[16], transcript[64], mac[32], packet[18];
    memcpy(nonce, clients[handle].nonce, 16);
    size_t n = receipt_transcript(transcript, false, op, id, nonce, 0);
    assert(compute_hmac(transcript, n, current_psk, mac));
    packet[0] = 0xf0; memcpy(packet + 1, id, 16); assert(fragment(handle, packet, 17) == 0);
    packet[0] = 0xf1; packet[1] = op; memcpy(packet + 2, mac, 16); assert(fragment(handle, packet, 18) == 0);
    packet[0] = 0xf2; memcpy(packet + 1, mac + 16, 16); if (tamper) packet[1] ^= 1;
    int rc = fragment(handle, packet, 17);
    if (tamper) { assert(rc == BLE_ATT_ERR_INSUFFICIENT_AUTHEN); return -1; }
    assert(rc == 0);
    struct os_mbuf om = {0};
    struct ble_gatt_access_ctxt ctxt = {BLE_GATT_ACCESS_OP_READ_CHR, &om};
    assert(chr_access_receipt(handle, 0, &ctxt, NULL) == 0 && om.len == 19);
    n = receipt_transcript(transcript, true, op, id, nonce, om.bytes[2]);
    assert(compute_hmac(transcript, n, current_psk, mac));
    assert(om.bytes[0] == 0xb1 && om.bytes[1] == op && !memcmp(om.bytes + 3, mac, 16));
    return om.bytes[2];
}
int main(void) {
    uint8_t id[16] = {1}, other[16] = {2};
    assert(exchange(0, RECEIPT_PROVE, id, false) == RECEIPT_PROVED && pulse_count == 0);
    exchange(0, RECEIPT_PRESS, id, true); assert(pulse_count == 0);
    assert(exchange(0, RECEIPT_PRESS, id, false) == RECEIPT_PENDING && pulse_count == 1);
    assert(exchange(1, RECEIPT_PRESS, id, false) == RECEIPT_PENDING && pulse_count == 1);
    assert(exchange(1, RECEIPT_PRESS, other, false) == RECEIPT_BUSY && pulse_count == 1);
    /* Complete pulse, lose the response, then reconnect with independent session state. */
    press_receipts[receipt_button_slot].result = RECEIPT_PRESSED; receipt_button_slot = -1; button_busy = false;
    memset(&clients[0], 0, sizeof(clients[0])); fake_now = 1000;
    assert(exchange(0, RECEIPT_QUERY, id, false) == RECEIPT_PRESSED && pulse_count == 1);
    assert(exchange(0, RECEIPT_ACK, id, false) == RECEIPT_ACKED);
    assert(exchange(0, RECEIPT_PRESS, id, false) == RECEIPT_ACKED && pulse_count == 1);
    fake_now = 29999; assert(exchange(0, RECEIPT_QUERY, id, false) == RECEIPT_ACKED);
    fake_now = 30000; assert(exchange(0, RECEIPT_QUERY, id, false) == RECEIPT_UNKNOWN && pulse_count == 1);
    uint8_t partial[17] = {0xf0}; assert(fragment(0, partial, 17) == 0);
    fake_now += 5001; partial[0] = 0xf2; assert(fragment(0, partial, 17) != 0);
    for (int i = 0; i < 5; ++i) exchange(2, RECEIPT_PROVE, id, true);
    assert(clients[2].closing);
    puts("Real GATT handler: authentication, lost response/reconnect, duplicate/ACK, busy, expiry and fragment faults passed");
}
