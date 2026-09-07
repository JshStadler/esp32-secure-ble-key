#include <assert.h>
#include <stdio.h>
#include "press_receipt.h"

int main(void) {
    press_receipt_t cache[RECEIPT_SLOTS] = {0};
    uint8_t id[16] = {1};
    int slot = receipt_reserve(cache, id, 1000);
    assert(slot >= 0 && cache[slot].result == RECEIPT_PENDING);
    assert(receipt_reserve(cache, id, 1001) == slot); /* duplicate cannot allocate a second action */
    receipt_ack(&cache[slot]);
    assert(cache[slot].result == RECEIPT_PENDING); /* cannot acknowledge an unfinished pulse */
    cache[slot].result = RECEIPT_PRESSED;
    assert(receipt_find(cache, id, 1200) == slot); /* disconnect does not remove result */
    assert(receipt_waiting(cache));
    receipt_ack(&cache[slot]);
    assert(cache[slot].result == RECEIPT_ACKED && !receipt_waiting(cache));
    assert(receipt_reserve(cache, id, 30999) == slot); /* ACK tombstone blocks duplicate */
    assert(receipt_find(cache, id, 31000) == -1); /* exact original 30-second boundary */
    assert(!receipt_waiting(cache));
    for (int i = 0; i < RECEIPT_SLOTS; ++i) {
        id[0] = (uint8_t)i;
        assert(receipt_reserve(cache, id, 40000) >= 0);
    }
    id[0] = 100;
    assert(receipt_reserve(cache, id, 40001) == -1); /* backpressure, never evict live IDs */
    assert(receipt_reserve(cache, id, 70000) >= 0);
    memset(cache, 0, sizeof(cache)); /* reboot = unknown, never infer not pressed */
    assert(receipt_find(cache, id, 0) == -1);
    uint8_t transcript[64], nonce[16] = {0};
    size_t n = receipt_transcript(transcript, false, 2, id, nonce, 0);
    assert(n == 54 && memcmp(transcript, "BLEKEY-RCP1\0car-main\0", 21) == 0);
    n = receipt_transcript(transcript, true, 3, id, nonce, RECEIPT_PRESSED);
    assert(n == 59 && transcript[n - 1] == RECEIPT_PRESSED);
    puts("Receipt lifetime, ACK, duplicate, capacity, reboot and transcript tests passed");
}
