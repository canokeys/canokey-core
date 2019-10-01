#include "common.h"
#include <ccid.h>
#include <ctaphid.h>
#include <device.h>

volatile static uint8_t touch_result;

__weak void device_delay(int ms) {}

__weak uint32_t device_get_tick(void) { return 0; }

uint8_t wait_for_user_presence(void) {
  while (!touch_result) {
    CCID_Loop();
    if (CTAPHID_Loop(1) == LOOP_CANCEL) return USER_PRESENCE_CANCEL;
  }
  return USER_PRESENCE_OK;
}

void device_loop(void) {
  while (1) {
    CCID_Loop();
    CTAPHID_Loop(0);
  }
}

uint8_t get_touch_result(void) { return touch_result; }

void set_touch_result(uint8_t result) { touch_result = result; }

uint8_t is_nfc(void) { return 0; }
