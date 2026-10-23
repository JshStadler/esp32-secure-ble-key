#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include "radio_config.h"

#define CAR_IDENTITY "blekey|2|car-main|car|press,ota1,psk2,health1,radio1,rcp1,auth2,radio2,radio3"

typedef struct {
    const char *version, *build, *idf, *reset, *ota;
    uint64_t uptime_s;
    uint32_t free_heap, min_heap, connections, adv_recoveries, ghost_reaps;
    radio_config_t radio;
    const char *adv_mode;
    bool rssi_valid;
    int rssi;
    int tx_adv, tx_conn;
    const char *power_mode;
} device_health_t;

/* Extend the existing capability list so old clients and cached GATT handles
 * remain compatible. Before authentication this is only the static identity.
 * A post-authentication read is the explicit health request. */
static inline int device_health_format(char *out, size_t size,
                                       const device_health_t *h) {
    if (!h) return snprintf(out, size, "%s", CAR_IDENTITY);
    char rssi[16] = "";
    if (h->rssi_valid && h->rssi >= -127 && h->rssi <= 20)
        snprintf(rssi, sizeof(rssi), ",rssi=%d", h->rssi);
    char power[64] = "", adv[16] = "", conn[16] = "";
    if (h->tx_adv >= -24 && h->tx_adv <= 20) snprintf(adv, sizeof(adv), ",txadv=%d", h->tx_adv);
    if (h->tx_conn >= -24 && h->tx_conn <= 20) snprintf(conn, sizeof(conn), ",txconn=%d", h->tx_conn);
    snprintf(power, sizeof(power), ",txdbm=%d,txidle=%d,txmode=%s",
        h->radio.tx_power_dbm, h->radio.idle_tx_power_dbm, h->power_mode);
    return snprintf(out, size, CAR_IDENTITY
        ",fw=%s,build=%s,idf=%s,up=%" PRIu64 ",reset=%s,ota=%s"
        ",heap=%" PRIu32 ",minheap=%" PRIu32 ",links=%" PRIu32
        ",advrec=%" PRIu32 ",ghost=%" PRIu32
        ",fastmin=%u,fastmax=%u,slowmin=%u,slowmax=%u,idlesec=%u,advmode=%s%s%s%s%s",
        h->version, h->build, h->idf, h->uptime_s, h->reset, h->ota,
        h->free_heap, h->min_heap, h->connections, h->adv_recoveries, h->ghost_reaps,
        (unsigned)h->radio.fast_min, (unsigned)h->radio.fast_max,
        (unsigned)h->radio.slow_min, (unsigned)h->radio.slow_max,
        (unsigned)h->radio.idle_seconds, h->adv_mode, rssi, power, adv, conn);
}
