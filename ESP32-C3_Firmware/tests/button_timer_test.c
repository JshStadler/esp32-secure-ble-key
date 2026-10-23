#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "press_receipt.h"

#define BUTTON_GPIO 1
#define DEBUG_LED_GPIO 2
#define DEBUG_LED_ENABLED
#define BUTTON_ACTIVE_HIGH 1
#define BUTTON_PULSE_MS 500
#define GPIO_MODE_INPUT 0
#define GPIO_MODE_OUTPUT 1
#define ESP_OK 0
#define TAG "test"
#define LOG_E(...) ((void)0)
typedef int esp_err_t;
struct ble_npl_event { int unused; };
static struct ble_npl_event receipt_button_event;
static bool button_busy, event_queued;
static int receipt_button_slot = -1;
static press_receipt_t press_receipts[RECEIPT_SLOTS];
static int button_timer, timer_result, timer_starts, direction, led;
static void gpio_set_direction(int pin, int mode) { assert(pin == BUTTON_GPIO); direction = mode; }
static void gpio_set_level(int pin, int value) { if (pin == DEBUG_LED_GPIO) led = value; }
static esp_err_t esp_timer_start_once(int timer, uint64_t duration) {
    (void)timer; assert(duration == BUTTON_PULSE_MS * 1000); timer_starts++; return timer_result;
}
static void *nimble_port_get_dflt_eventq(void) { return NULL; }
static void ble_npl_eventq_put(void *queue, struct ble_npl_event *event) {
    (void)queue; assert(event == &receipt_button_event); assert(!event_queued); event_queued = true;
}
#include "button_under_test.inc"

static void dispatch_completion(void) {
    assert(event_queued); event_queued = false; receipt_button_complete(&receipt_button_event);
}

int main(void) {
    // A timer can preempt the host immediately after starting the pulse, even
    // before the caller associates its receipt. It must not read that slot.
    assert(press_remote_button());
    button_timer_callback(NULL);
    assert(direction == GPIO_MODE_INPUT && led == 0);
    assert(button_busy && !press_remote_button() && timer_starts == 1);
    receipt_button_slot = 4;
    press_receipts[4].result = RECEIPT_PENDING;
    dispatch_completion();
    assert(!button_busy && receipt_button_slot == -1);
    assert(press_receipts[4].result == RECEIPT_PRESSED);

    // A normal command can be followed by a receipt command only after its
    // completion event. It must not inherit the old pulse's completion.
    assert(press_remote_button());
    button_timer_callback(NULL);
    assert(!press_remote_button());
    dispatch_completion();
    assert(press_remote_button());
    receipt_button_slot = 5; press_receipts[5].result = RECEIPT_PENDING;
    assert(press_receipts[5].result != RECEIPT_PRESSED);
    button_timer_callback(NULL); dispatch_completion();
    assert(press_receipts[5].result == RECEIPT_PRESSED);

    // Failure to arm the release timer must restore both hardware outputs.
    timer_result = 1;
    assert(!press_remote_button());
    assert(direction == GPIO_MODE_INPUT && led == 0 && !button_busy && !event_queued);
    puts("button timer interleavings: passed");
    return 0;
}
