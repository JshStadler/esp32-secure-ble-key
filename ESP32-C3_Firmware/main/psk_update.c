#include "psk_update.h"
#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>

void psk2_zero(void *data, size_t length) {
    volatile uint8_t *p = data;
    while (length--) *p++ = 0;
}

static bool mac(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t out[32]) {
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0;
    size_t written = 0;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_status_t rc = psa_import_key(&attributes, key, key_len, &id);
    if (rc == PSA_SUCCESS) {
        rc = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, len, out, 32, &written);
        psa_destroy_key(id);
    }
    psa_reset_key_attributes(&attributes);
    return rc == PSA_SUCCESS && written == 32;
}

static size_t context(const char *domain, const char *binding, const uint8_t nonce[16], uint8_t out[96]) {
    const size_t d = strlen(domain), b = strlen(binding);
    if (d + b + 18 > 96) return 0;
    memcpy(out, domain, d + 1);
    memcpy(out + d + 1, binding, b + 1);
    memcpy(out + d + b + 2, nonce, 16);
    return d + b + 18;
}

bool psk2_decrypt(const char *key, const char *binding, const uint8_t nonce[16],
                  const uint8_t *packet, size_t length, char replacement[PSK2_MAX_KEY + 1],
                  uint8_t receipt_key[32]) {
    psk2_zero(replacement, PSK2_MAX_KEY + 1);
    psk2_zero(receipt_key, 32);
    if (length < 30 || length > PSK2_MAX_PACKET || packet[0] != 0xa2 || !key[0]) return false;
    uint8_t transcript[96], encryption_key[32];
    size_t n = context("BLEKEY-PSK2-ENC", binding, nonce, transcript);
    if (!n || !mac((const uint8_t *)key, strlen(key), transcript, n, encryption_key)) return false;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_status_t rc = psa_import_key(&attributes, encryption_key, sizeof(encryption_key), &id);
    psk2_zero(encryption_key, sizeof(encryption_key));
    size_t plaintext_len = 0;
    n = context("BLEKEY-PSK2", binding, nonce, transcript);
    if (rc == PSA_SUCCESS) {
        rc = psa_aead_decrypt(id, PSA_ALG_GCM, packet + 1, 12, transcript, n,
                              packet + 13, length - 13, (uint8_t *)replacement,
                              PSK2_MAX_KEY, &plaintext_len);
        psa_destroy_key(id);
    }
    psa_reset_key_attributes(&attributes);
    bool valid = rc == PSA_SUCCESS && plaintext_len > 0 && plaintext_len <= PSK2_MAX_KEY &&
                 memchr(replacement, 0, plaintext_len) == NULL;
    if (valid) {
        replacement[plaintext_len] = 0;
        n = context("BLEKEY-PSK2-ACK", binding, nonce, transcript);
        valid = mac((const uint8_t *)key, strlen(key), transcript, n, receipt_key);
    }
    if (!valid) { psk2_zero(replacement, PSK2_MAX_KEY + 1); psk2_zero(receipt_key, 32); }
    return valid;
}

bool psk2_receipt(const uint8_t receipt_key[32], const uint8_t *packet, size_t length,
                  bool persisted, char output[PSK2_RECEIPT_SIZE]) {
    uint8_t transcript[33] = {persisted ? 1 : 0}, tag[32];
    size_t digest_len = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, packet, length, transcript + 1, 32, &digest_len) != PSA_SUCCESS ||
        digest_len != 32 || !mac(receipt_key, 32, transcript, sizeof(transcript), tag)) return false;
    int offset = snprintf(output, PSK2_RECEIPT_SIZE, "PSK2:%s:", persisted ? "OK" : "FAIL");
    for (size_t i = 0; i < sizeof(tag); ++i) snprintf(output + offset + i * 2, 3, "%02x", tag[i]);
    psk2_zero(tag, sizeof(tag));
    return true;
}
