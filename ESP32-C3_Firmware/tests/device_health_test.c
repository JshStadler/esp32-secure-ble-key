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
        RADIO_DEFAULTS, "recent"};
    int n = device_health_format(out, sizeof(out), &h);
    assert(n > 0 && n < (int)sizeof(out));
    assert(strstr(out, "press,ota1,psk2,health1,radio1,fw=2.7.0") != NULL);
    assert(strstr(out, "up=18446744073709551615,reset=brownout,ota=valid") != NULL);
    assert(strstr(out, "minheap=4294967295,links=3") != NULL);
    char short_out[8];
    assert(device_health_format(short_out, sizeof(short_out), &h) == n);
    assert(short_out[7] == '\0');
    return 0;
}
