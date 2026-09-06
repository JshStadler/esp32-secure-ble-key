#include <assert.h>
#include <stddef.h>
#include "radio_config.h"

typedef int nvs_handle_t;
typedef int esp_err_t;
#define ESP_OK 0
#define NVS_READONLY 0
#define NVS_READWRITE 1
static radio_config_t radio_config = RADIO_DEFAULTS;
static bool radio_config_persisted;
static uint8_t stored[11], pending[11];
static size_t stored_size = 11;
static int open_error, get_error, set_error, commit_error, writes;
static int nvs_open(const char *name, int mode, nvs_handle_t *h) { (void)name; (void)mode; *h = 1; return open_error; }
static void nvs_close(nvs_handle_t h) { (void)h; }
static int nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *size) {
    (void)h; assert(!strcmp(key, "radio1"));
    if (get_error) return get_error;
    if (*size < stored_size) return 9;
    memcpy(out, stored, stored_size); *size = stored_size; return 0;
}
static int nvs_set_blob(nvs_handle_t h, const char *key, const void *data, size_t size) {
    (void)h; assert(!strcmp(key, "radio1")); assert(size == 11);
    writes++; memcpy(pending, data, size); return set_error;
}
static int nvs_commit(nvs_handle_t h) { (void)h; if (!commit_error) memcpy(stored, pending, 11); return commit_error; }
#include "radio_nvs_under_test.inc"

int main(void) {
    const radio_config_t defaults = RADIO_DEFAULTS;
    radio_config_t requested = {160, 160, 1600, 3200, 10};
    stored[0] = 1; radio_config_encode(stored + 1, &requested);
    load_radio_config(); assert(radio_config.idle_seconds == 10);
    assert(save_radio_config(&requested)); assert(writes == 0);
    radio_config = defaults;
    for (size_t size = 0; size < 11; size++) {
        stored_size = size; load_radio_config(); assert(radio_config.idle_seconds == 60);
    }
    stored_size = 11;
    stored[0] = 2; load_radio_config(); assert(radio_config.idle_seconds == 60);
    stored[0] = 1; stored[1] = 0; stored[2] = 0;
    load_radio_config(); assert(radio_config.idle_seconds == 60);
    radio_config_encode(stored + 1, &requested);
    get_error = 4; load_radio_config(); assert(radio_config.idle_seconds == 60); get_error = 0;
    open_error = 4; load_radio_config(); assert(radio_config.idle_seconds == 60);
    assert(!save_radio_config(&requested)); open_error = 0;
    set_error = 4; assert(!save_radio_config(&requested)); set_error = 0;
    assert(radio_config.idle_seconds == 60);
    commit_error = 4; assert(!save_radio_config(&requested)); commit_error = 0;
    assert(radio_config.idle_seconds == 60);
    assert(save_radio_config(&requested)); assert(radio_config.idle_seconds == 10);
    radio_config = defaults; load_radio_config(); assert(radio_config.idle_seconds == 10);
    requested.idle_seconds = 0; assert(!save_radio_config(&requested));
    /* A failed load must not make Save Defaults silently skip persistence. */
    radio_config = defaults; radio_config_persisted = false;
    assert(save_radio_config(&defaults));
    radio_config = (radio_config_t){160, 160, 320, 640, 10};
    load_radio_config(); assert(radio_config.idle_seconds == 60);
    return 0;
}
