#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Match Android's PskKeyPolicy. This rejects obvious weaknesses, not all
 * guessable keys; provision cryptographically generated keys whenever possible. */
static inline bool psk_valid_new_key(const uint8_t *key, size_t length) {
    if (!key || length < 32 || length > 128) return false;
    bool seen[256] = {false};
    unsigned distinct = 0;
    for (size_t i = 0; i < length; ++i) {
        if (!key[i]) return false;
        if (!seen[key[i]]) { seen[key[i]] = true; ++distinct; }
    }
    if (distinct < 8) return false;
    for (size_t period = 1; period <= 16; ++period) {
        bool repeats = true;
        for (size_t i = period; i < length; ++i) {
            if (key[i] != key[i % period]) { repeats = false; break; }
        }
        if (repeats) return false;
    }
    return true;
}
