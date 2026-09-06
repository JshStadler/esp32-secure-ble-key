#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    int64_t healthy_since_ms;
    unsigned healthy_checks;
} ota_health_t;

typedef enum { OTA_HEALTH_WAIT, OTA_HEALTH_CONFIRM, OTA_HEALTH_ROLLBACK } ota_health_result_t;

/* Called by the host's maintenance event, never by a timer that can progress
 * while the BLE host is stuck. Require a continuous healthy minute, with at
 * least six separate checks. A stalled host is also caught by its watchdog. */
static inline ota_health_result_t ota_health_check(ota_health_t *health,
                                                  int64_t uptime_ms, bool healthy) {
    if (!healthy) {
        health->healthy_checks = 0;
    } else {
        if (health->healthy_checks == 0) health->healthy_since_ms = uptime_ms;
        if (health->healthy_checks < 6) health->healthy_checks++;
        if (health->healthy_checks >= 6 && uptime_ms - health->healthy_since_ms >= 60000)
            return OTA_HEALTH_CONFIRM;
    }
    return uptime_ms >= 120000 ? OTA_HEALTH_ROLLBACK : OTA_HEALTH_WAIT;
}
