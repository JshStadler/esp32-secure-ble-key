#include "psk_update.h"
#include "psa/crypto.h"
#include "psk2_vectors.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    assert(psa_crypto_init() == PSA_SUCCESS);
    unsigned char nonce[16], ack[32];
    for (int i = 0; i < 16; i++) nonce[i] = i;
    char replacement[129], receipt[80];
    const char *key = "synthetic-current-key";
    assert(psk2_decrypt(key, "car-main", nonce, packet0, sizeof(packet0), replacement, ack));
    assert(!strcmp(replacement, "5e90b1c274a83d6f0a519fbe842c73d6"));
    assert(psk2_receipt(ack, packet0, sizeof(packet0), true, receipt));
    assert(!strcmp(receipt, RECEIPT_OK));
    assert(psk2_receipt(ack, packet0, sizeof(packet0), false, receipt));
    assert(!strcmp(receipt, RECEIPT_FAIL));
    for (size_t i = 0; i < sizeof(packet0); i++) {
        unsigned char altered[sizeof(packet0)];
        memcpy(altered, packet0, sizeof(altered)); altered[i] ^= 1;
        assert(!psk2_decrypt(key, "car-main", nonce, altered, sizeof(altered), replacement, ack));
        for (int j = 0; j < 129; j++) assert(replacement[j] == 0);
        for (int j = 0; j < 32; j++) assert(ack[j] == 0);
    }
    assert(!psk2_decrypt("wrong", "car-main", nonce, packet0, sizeof(packet0), replacement, ack));
    assert(!psk2_decrypt(key, "gate-main", nonce, packet0, sizeof(packet0), replacement, ack));
    nonce[0] ^= 1;
    assert(!psk2_decrypt(key, "car-main", nonce, packet0, sizeof(packet0), replacement, ack));
    nonce[0] ^= 1;
    assert(psk2_decrypt(key, "car-main", nonce, packet1, sizeof(packet1), replacement, ack));
    assert(strlen(replacement) == 127);
    assert(psk2_decrypt(key, "car-main", nonce, packet2, sizeof(packet2), replacement, ack));
    assert(strlen(replacement) == 128);
    assert(!psk2_decrypt(key, "car-main", nonce, packet3, sizeof(packet3), replacement, ack));
    assert(!psk2_decrypt(key, "car-main", nonce, packet4, sizeof(packet4), replacement, ack));
    /* These requests have valid GCM tags under a supported old key, but the
     * replacement key policy must still reject them and clear the plaintext. */
    const unsigned char *weak[] = {packet5, packet6, packet7, packet8, packet10, packet11};
    const size_t weak_sizes[] = {sizeof(packet5), sizeof(packet6), sizeof(packet7),
                               sizeof(packet8), sizeof(packet10), sizeof(packet11)};
    for (size_t i = 0; i < sizeof(weak) / sizeof(weak[0]); ++i) {
        memset(replacement, 0x55, sizeof(replacement)); memset(ack, 0x55, sizeof(ack));
        assert(!psk2_decrypt(key, "car-main", nonce, weak[i], weak_sizes[i], replacement, ack));
        for (size_t j = 0; j < sizeof(replacement); ++j) assert(replacement[j] == 0);
        for (size_t j = 0; j < sizeof(ack); ++j) assert(ack[j] == 0);
    }
    assert(psk2_decrypt(key, "car-main", nonce, packet9, sizeof(packet9), replacement, ack));
    assert(strlen(replacement) == 128);
    assert(!psk2_decrypt("", "car-main", nonce, packet0, sizeof(packet0), replacement, ack));
    puts("PSK2 firmware interoperability and tamper tests passed");
}
