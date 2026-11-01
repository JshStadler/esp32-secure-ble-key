#include "psk_key_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool valid(const char *key) {
    return psk_valid_new_key((const uint8_t *)key, strlen(key));
}

int main(void) {
    const char *strong = "5e90b1c274a83d6f0a519fbe842c73d6";
    assert(valid(strong));
    assert(!valid("replacement-key"));
    assert(!valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"));
    assert(!valid("passwordpasswordpasswordpassword"));
    assert(!psk_valid_new_key(NULL, 32));
    char key[130];
    memcpy(key, strong, 32);
    assert(!psk_valid_new_key((uint8_t *)key, 31));
    for (int i = 1; i < 4; ++i) memcpy(key + i * 32, strong, 32);
    assert(psk_valid_new_key((uint8_t *)key, 127));
    assert(psk_valid_new_key((uint8_t *)key, 128));
    key[128] = 'a';
    assert(!psk_valid_new_key((uint8_t *)key, 129));
    key[10] = 0;
    assert(!psk_valid_new_key((uint8_t *)key, 128));
    memset(key, 'x', 128);
    assert(!psk_valid_new_key((uint8_t *)key, 128));
    for (int i = 0; i < 128; ++i) key[i] = "0123456789abcdef"[i % 16];
    assert(!psk_valid_new_key((uint8_t *)key, 127));
    puts("New PSK policy boundaries, diversity and repetition tests passed");
}
