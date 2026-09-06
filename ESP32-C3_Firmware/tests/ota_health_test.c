#include <assert.h>
#include "ota_health.h"

int main(void) {
    ota_health_t h = {0};
    for (int t = 0; t < 60000; t += 10000)
        assert(ota_health_check(&h, t, true) == OTA_HEALTH_WAIT);
    assert(ota_health_check(&h, 60000, true) == OTA_HEALTH_CONFIRM);

    h = (ota_health_t){0};
    assert(ota_health_check(&h, 0, true) == OTA_HEALTH_WAIT);
    /* Elapsed time alone cannot prove that the host kept progressing. */
    assert(ota_health_check(&h, 60000, true) == OTA_HEALTH_WAIT);
    assert(ota_health_check(&h, 120000, true) == OTA_HEALTH_ROLLBACK);

    h = (ota_health_t){0};
    for (int t = 0; t < 50000; t += 10000)
        assert(ota_health_check(&h, t, true) == OTA_HEALTH_WAIT);
    assert(ota_health_check(&h, 50000, false) == OTA_HEALTH_WAIT);
    for (int t = 60000; t < 120000; t += 10000)
        assert(ota_health_check(&h, t, true) == OTA_HEALTH_WAIT);
    assert(ota_health_check(&h, 120000, true) == OTA_HEALTH_CONFIRM);

    h = (ota_health_t){0};
    assert(ota_health_check(&h, 119999, false) == OTA_HEALTH_WAIT);
    assert(ota_health_check(&h, 120000, false) == OTA_HEALTH_ROLLBACK);
    return 0;
}
