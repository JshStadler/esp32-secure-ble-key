#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* RAM only. Neither queries nor acknowledgment extend the original lifetime. */
#define RECEIPT_TTL_MS 30000
#define RECEIPT_SLOTS 32
#define RECEIPT_UNKNOWN 0
#define RECEIPT_PENDING 1
#define RECEIPT_PRESSED 2
#define RECEIPT_BUSY 3
#define RECEIPT_ACKED 4
#define RECEIPT_FULL 5
#define RECEIPT_PROVED 6
#define RECEIPT_PROVE 1
#define RECEIPT_PRESS 2
#define RECEIPT_QUERY 3
#define RECEIPT_ACK 4

typedef struct {
    uint8_t id[16];
    uint8_t result;
    int64_t created_ms;
} press_receipt_t;

static inline void receipt_expire(press_receipt_t *cache, int64_t now) {
    for (int i = 0; i < RECEIPT_SLOTS; ++i)
        if (cache[i].result && now - cache[i].created_ms >= RECEIPT_TTL_MS)
            memset(&cache[i], 0, sizeof(cache[i]));
}

static inline int receipt_find(press_receipt_t *cache, const uint8_t id[16], int64_t now) {
    receipt_expire(cache, now);
    for (int i = 0; i < RECEIPT_SLOTS; ++i)
        if (cache[i].result && memcmp(cache[i].id, id, 16) == 0) return i;
    return -1;
}

/* Never evict a live entry to make room: that would remove duplicate protection. */
static inline int receipt_reserve(press_receipt_t *cache, const uint8_t id[16], int64_t now) {
    int found = receipt_find(cache, id, now);
    if (found >= 0) return found;
    for (int i = 0; i < RECEIPT_SLOTS; ++i) {
        if (!cache[i].result) {
            memcpy(cache[i].id, id, 16);
            cache[i].created_ms = now;
            cache[i].result = RECEIPT_PENDING;
            return i;
        }
    }
    return -1;
}

static inline void receipt_ack(press_receipt_t *entry) {
    if (entry->result == RECEIPT_PRESSED || entry->result == RECEIPT_BUSY)
        entry->result = RECEIPT_ACKED; /* discard outcome, retain only ID tombstone */
}

static inline bool receipt_waiting(const press_receipt_t *cache) {
    for (int i = 0; i < RECEIPT_SLOTS; ++i)
        if (cache[i].result == RECEIPT_PENDING || cache[i].result == RECEIPT_PRESSED ||
            cache[i].result == RECEIPT_BUSY) return true;
    return false;
}

/* Both domains include NUL; fixed binding ends with NUL. */
static inline size_t receipt_transcript(uint8_t *out, bool reply, uint8_t op,
                                        const uint8_t id[16], const uint8_t nonce[16], uint8_t result) {
    const char *domain = reply ? "BLEKEY-RCP1-ACK" : "BLEKEY-RCP1";
    size_t n = strlen(domain) + 1;
    memcpy(out, domain, n);
    memcpy(out + n, "car-main", 9); n += 9;
    out[n++] = op;
    memcpy(out + n, id, 16); n += 16;
    memcpy(out + n, nonce, 16); n += 16;
    if (reply) out[n++] = result;
    return n;
}
