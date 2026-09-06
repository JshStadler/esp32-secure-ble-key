#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "radio_config.h"

#define CAR_IDENTITY "blekey|2|car-main|car|press,ota1,psk2,health1,radio1"

typedef struct {
    const char *version, *build, *idf, *reset, *ota;
    uint64_t uptime_s;
    uint32_t free_heap, min_heap, connections, adv_recoveries, ghost_reaps;
    radio_config_t radio;
    const char *adv_mode;
} device_health_t;

/* Extend the existing capability list so old clients and cached GATT handles
 * remain compatible. Before authentication this is only the static identity.
 * A post-authentication read is the explicit health request. */
static inline int device_health_format(char *out, size_t size,
                                       const device_health_t *h) {
    if (!h) return snprintf(out, size, "%s", CAR_IDENTITY);
    return snprintf(out, size, CAR_IDENTITY
        ",fw=%s,build=%s,idf=%s,up=%" PRIu64 ",reset=%s,ota=%s"
        ",heap=%" PRIu32 ",minheap=%" PRIu32 ",links=%" PRIu32
        ",advrec=%" PRIu32 ",ghost=%" PRIu32
        ",fastmin=%u,fastmax=%u,slowmin=%u,slowmax=%u,idlesec=%u,advmode=%s",
        h->version, h->build, h->idf, h->uptime_s, h->reset, h->ota,
        h->free_heap, h->min_heap, h->connections, h->adv_recoveries, h->ghost_reaps,
        (unsigned)h->radio.fast_min, (unsigned)h->radio.fast_max,
        (unsigned)h->radio.slow_min, (unsigned)h->radio.slow_max,
        (unsigned)h->radio.idle_seconds, h->adv_mode);
}
