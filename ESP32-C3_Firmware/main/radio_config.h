#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define RADIO_CONFIG_SIZE 10
#define RADIO_PACKET_SIZE (1 + RADIO_CONFIG_SIZE + 32)
#define RADIO_CONFIG2_SIZE 11
#define RADIO_PACKET2_SIZE (1 + RADIO_CONFIG2_SIZE + 32)
#define RADIO_DOMAIN2 "BLEKEY-RADIO2\0car-main"
#define RADIO_TRANSCRIPT2_SIZE (sizeof(RADIO_DOMAIN2) + 16 + RADIO_CONFIG2_SIZE)
#define RADIO_DOMAIN "BLEKEY-RADIO1\0car-main"
#define RADIO_TRANSCRIPT_SIZE (sizeof(RADIO_DOMAIN) + 16 + RADIO_CONFIG_SIZE)

typedef struct {
    uint16_t fast_min, fast_max, slow_min, slow_max, idle_seconds;
    int8_t tx_power_dbm;
} radio_config_t;

#define RADIO_DEFAULTS {80, 160, 320, 640, 60, 3}

static inline bool radio_tx_valid(int dbm) {
    return dbm >= -12 && dbm <= 9 && dbm % 3 == 0;
}

static inline bool radio_config_valid(const radio_config_t *c) {
    /* 20-2000ms. Bound discovery latency for the phone/watch scan windows. */
    return c->fast_min >= 32 && c->fast_max <= 3200 && c->fast_min <= c->fast_max &&
        c->slow_min >= c->fast_min && c->slow_min <= c->slow_max &&
        c->slow_max >= c->fast_max && c->slow_max <= 3200 &&
        c->idle_seconds >= 5 && c->idle_seconds <= 3600 && radio_tx_valid(c->tx_power_dbm);
}

static inline void radio_config_encode(uint8_t out[RADIO_CONFIG_SIZE], const radio_config_t *c) {
    uint16_t values[] = {c->fast_min, c->fast_max, c->slow_min, c->slow_max, c->idle_seconds};
    for (unsigned i = 0; i < 5; i++) { out[i * 2] = values[i]; out[i * 2 + 1] = values[i] >> 8; }
}

static inline bool radio_config_decode(radio_config_t *c, const uint8_t in[RADIO_CONFIG_SIZE]) {
    uint16_t v[5];
    for (unsigned i = 0; i < 5; i++) v[i] = in[i * 2] | ((uint16_t)in[i * 2 + 1] << 8);
    *c = (radio_config_t){v[0], v[1], v[2], v[3], v[4], 3};
    return radio_config_valid(c);
}

static inline void radio_transcript(uint8_t out[RADIO_TRANSCRIPT_SIZE],
                                     const uint8_t nonce[16], const uint8_t config[RADIO_CONFIG_SIZE]) {
    memcpy(out, RADIO_DOMAIN, sizeof(RADIO_DOMAIN));
    memcpy(out + sizeof(RADIO_DOMAIN), nonce, 16);
    memcpy(out + sizeof(RADIO_DOMAIN) + 16, config, RADIO_CONFIG_SIZE);
}

static inline void radio_config2_encode(uint8_t out[RADIO_CONFIG2_SIZE], const radio_config_t *c) {
    radio_config_encode(out, c);
    out[RADIO_CONFIG_SIZE] = (uint8_t)c->tx_power_dbm;
}

static inline bool radio_config2_decode(radio_config_t *c, const uint8_t in[RADIO_CONFIG2_SIZE]) {
    if (!radio_config_decode(c, in)) return false;
    c->tx_power_dbm = in[RADIO_CONFIG_SIZE] <= 127 ? in[RADIO_CONFIG_SIZE] : (int)in[RADIO_CONFIG_SIZE] - 256;
    return radio_config_valid(c);
}

static inline void radio_transcript2(uint8_t out[RADIO_TRANSCRIPT2_SIZE],
                                    const uint8_t nonce[16], const uint8_t config[RADIO_CONFIG2_SIZE]) {
    memcpy(out, RADIO_DOMAIN2, sizeof(RADIO_DOMAIN2));
    memcpy(out + sizeof(RADIO_DOMAIN2), nonce, 16);
    memcpy(out + sizeof(RADIO_DOMAIN2) + 16, config, RADIO_CONFIG2_SIZE);
}
