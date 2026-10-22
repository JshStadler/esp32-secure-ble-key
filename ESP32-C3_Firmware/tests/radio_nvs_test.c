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
static uint8_t stored[12], legacy[11], pending[12];
static size_t stored_size = 12;
static bool have_new, have_legacy;
static int open_error, get_error, set_error, commit_error, writes;
static int nvs_open(const char *name, int mode, nvs_handle_t *h) { (void)name; (void)mode; *h = 1; return open_error; }
static void nvs_close(nvs_handle_t h) { (void)h; }
static int nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *size) {
    (void)h;
    if (get_error) return get_error;
    bool v2 = !strcmp(key, "radio2");
    assert(v2 || !strcmp(key, "radio1"));
    if (v2 ? !have_new : !have_legacy) return 8;
    size_t count = v2 ? stored_size : sizeof(legacy);
    if (*size < count) return 9;
    memcpy(out, v2 ? stored : legacy, count); *size = count; return 0;
}
static int nvs_set_blob(nvs_handle_t h, const char *key, const void *data, size_t size) {
    (void)h; assert(!strcmp(key, "radio2")); assert(size == 12);
    writes++; memcpy(pending, data, size); return set_error;
}
static int nvs_commit(nvs_handle_t h) {
    (void)h;
    if (!commit_error) { memcpy(stored, pending, 12); stored_size = 12; have_new = true; }
    return commit_error;
}
#include "radio_nvs_under_test.inc"

int main(void) {
    const radio_config_t defaults = RADIO_DEFAULTS;
    radio_config_t requested = {160, 160, 1600, 3200, 10, 9};
    legacy[0] = 1; radio_config_encode(legacy + 1, &requested); have_legacy = true;
    load_radio_config();
    assert(radio_config.idle_seconds == 10 && radio_config.tx_power_dbm == 3);
    assert(!radio_config_persisted); // Must migrate on next save.
    assert(save_radio_config(&requested)); assert(writes == 1);
    assert(legacy[0] == 1); // Keep rollback record untouched.
    load_radio_config(); assert(radio_config.tx_power_dbm == 9);
    assert(save_radio_config(&requested)); assert(writes == 1);
    have_legacy = false;
    for (size_t size = 0; size < 12; size++) {
        radio_config = defaults; stored_size = size;
        load_radio_config(); assert(radio_config.idle_seconds == 60 && !radio_config_persisted);
    }
    stored_size = 12; radio_config = defaults;
    stored[0] = 1; load_radio_config(); assert(!radio_config_persisted);
    stored[0] = 2; stored[11] = 10; load_radio_config(); assert(!radio_config_persisted);
    // Corrupt new record falls back to valid legacy record, with default power.
    have_legacy = true; load_radio_config();
    assert(radio_config.idle_seconds == 10 && radio_config.tx_power_dbm == 3);
    have_legacy = false; radio_config = defaults;
    radio_config2_encode(stored + 1, &requested);
    get_error = 4; load_radio_config(); assert(radio_config.idle_seconds == 60); get_error = 0;
    open_error = 4; load_radio_config(); assert(!save_radio_config(&requested)); open_error = 0;
    set_error = 4; assert(!save_radio_config(&requested)); set_error = 0;
    assert(radio_config.idle_seconds == 60 && radio_config.tx_power_dbm == 3);
    commit_error = 4; assert(!save_radio_config(&requested)); commit_error = 0;
    assert(radio_config.idle_seconds == 60 && radio_config.tx_power_dbm == 3);
    assert(save_radio_config(&requested)); assert(radio_config.tx_power_dbm == 9);
    radio_config = defaults; load_radio_config(); assert(radio_config.tx_power_dbm == 9);
    requested.tx_power_dbm = 10; assert(!save_radio_config(&requested));
    radio_config = defaults; radio_config_persisted = false;
    assert(save_radio_config(&defaults));
    radio_config = requested; load_radio_config(); assert(radio_config.tx_power_dbm == 3);
    return 0;
}
