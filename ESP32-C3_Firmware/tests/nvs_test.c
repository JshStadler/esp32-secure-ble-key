#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef int nvs_handle_t;
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 1
#define NVS_READONLY 0
#define NVS_READWRITE 1
#define MAX_PSK_LEN 128
#define DEFAULT_PSK "CHANGE_ME_before_flashing_32chars!"
#define LOG_I(...) ((void)0)
#define LOG_E(...) ((void)0)
static char current_psk[129], stored[129], pending[129];
static int open_result, get_result, set_result, commit_result;
static int nvs_open(const char *ns, int mode, nvs_handle_t *h) { (void)ns; (void)mode; *h = 1; return open_result; }
static void nvs_close(nvs_handle_t h) { (void)h; }
static int nvs_get_str(nvs_handle_t h, const char *name, char *out, size_t *length) {
    (void)h; (void)name;
    if (get_result) return get_result;
    size_t needed = strlen(stored) + 1;
    if (*length < needed) return 2;
    memcpy(out, stored, needed); *length = needed; return 0;
}
static int nvs_set_str(nvs_handle_t h, const char *name, const char *value) {
    (void)h; (void)name; strcpy(pending, value); return set_result;
}
static int nvs_commit(nvs_handle_t h) { (void)h; if (!commit_result) strcpy(stored, pending); return commit_result; }
#include "nvs_under_test.inc"
int main(void) {
    for (int n = 1; n <= 128; n++) {
        memset(stored, 'k', n); stored[n] = 0;
        load_psk(); assert(strlen(current_psk) == (size_t)n); assert(!strcmp(current_psk, stored));
    }
    for (int error = 1; error <= 4; error++) {
        get_result = error; load_psk(); assert(current_psk[0] == 0);
    }
    get_result = 0; stored[0] = 0; load_psk(); assert(current_psk[0] == 0);
    for (int error = 1; error <= 4; error++) {
        open_result = error; load_psk(); assert(current_psk[0] == 0);
    }
    open_result = 0; strcpy(current_psk, "old"); strcpy(stored, "old");
    set_result = 3; assert(!save_psk("new")); assert(!strcmp(current_psk, "old"));
    set_result = 0; commit_result = 4; assert(!save_psk("new")); assert(!strcmp(current_psk, "old"));
    assert(!strcmp(stored, "old"));
    commit_result = 0; assert(save_psk("new")); assert(!strcmp(current_psk, "new"));
    load_psk(); assert(!strcmp(current_psk, "new"));
    puts("NVS key lengths, fail-closed loading and atomic save tests passed");
}
