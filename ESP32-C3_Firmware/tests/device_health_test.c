#include <assert.h>
#include <string.h>
#include "device_health.h"

int main(void) {
    char out[512];
    assert(device_health_format(out, sizeof(out), NULL) == (int)strlen(CAR_IDENTITY));
    assert(strcmp(out, CAR_IDENTITY) == 0);
    assert(strstr(out, "fw=") == NULL);
    device_health_t h = {"2.7.0", "012345abcdef", "v6.0.1", "brownout", "valid",
        UINT64_MAX, UINT32_MAX, UINT32_MAX, 3, UINT32_MAX, UINT32_MAX,
        RADIO_DEFAULTS, "recent", true, -67, 3, 6, "recent"};
    int n = device_health_format(out, sizeof(out), &h);
    assert(n > 0 && n < (int)sizeof(out));
    assert(strstr(out, "press,ota1,psk2,health1,radio1,rcp1,auth2,radio2,radio3,fw=2.7.0") != NULL);
    assert(strstr(out, ",rssi=-67") != NULL);
    assert(strstr(out, "up=18446744073709551615,reset=brownout,ota=valid") != NULL);
    assert(strstr(out, "minheap=4294967295,links=3") != NULL);
    assert(strstr(out, ",txdbm=3,txidle=3,txmode=recent,txadv=3,txconn=6") != NULL);
    char short_out[8];
    assert(device_health_format(short_out, sizeof(short_out), &h) == n);
    assert(short_out[7] == '\0');
    h.tx_adv = 127; h.tx_conn = 127;
    device_health_format(out, sizeof(out), &h);
    assert(strstr(out, ",txadv=") == NULL && strstr(out, ",txconn=") == NULL);
    h.rssi_valid = false;
    device_health_format(out, sizeof(out), &h);
    assert(strstr(out, ",rssi=") == NULL);
    h.rssi_valid = true; h.rssi = 127;
    device_health_format(out, sizeof(out), &h);
    assert(strstr(out, ",rssi=") == NULL);
    return 0;
}
