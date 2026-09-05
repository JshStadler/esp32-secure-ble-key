#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PSK2_MAX_KEY 128
#define PSK2_MAX_PACKET (1 + 12 + PSK2_MAX_KEY + 16)
#define PSK2_RECEIPT_SIZE 80
bool psk2_decrypt(const char *key, const char *binding, const uint8_t nonce[16],
                  const uint8_t *packet, size_t length, char replacement[PSK2_MAX_KEY + 1],
                  uint8_t receipt_key[32]);
bool psk2_receipt(const uint8_t receipt_key[32], const uint8_t *packet, size_t length,
                  bool persisted, char output[PSK2_RECEIPT_SIZE]);
void psk2_zero(void *data, size_t length);
