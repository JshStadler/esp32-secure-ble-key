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
    assert(!strcmp(replacement, "replacement-key"));
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
    assert(!psk2_decrypt("", "car-main", nonce, packet0, sizeof(packet0), replacement, ack));
    puts("PSK2 firmware interoperability and tamper tests passed");
}
