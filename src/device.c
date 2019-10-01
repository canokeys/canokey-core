#include "common.h"
#include <ccid.h>
#include <ctaphid.h>
#include <device.h>

volatile static uint8_t touch_result;

__weak void device_delay(int ms) {}

__weak uint32_t device_get_tick(void) { return 0; }

uint8_t wait_for_user_presence(void) {
#ifndef TEST
  uint32_t start = device_get_tick();
  uint32_t last = start;
  DBG_MSG("start %u\n", start);
  while (!touch_result) {
    CCID_Loop();
    if (CTAPHID_Loop(1) == LOOP_CANCEL) return USER_PRESENCE_CANCEL;
    uint32_t now = device_get_tick();
    if (now - start >= 30000) {
      DBG_MSG("timeout at %u\n", now);
      return USER_PRESENCE_TIMEOUT;
    }
    if (now - last >= 300) {
      last = now;
      CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_UPNEEDED);
    }
  }
#endif
  return USER_PRESENCE_OK;
}

void device_loop(void) {
#ifndef TEST
  while (1) {
    CCID_Loop();
    CTAPHID_Loop(0);
  }
#endif
}

uint8_t get_touch_result(void) { return touch_result; }

void set_touch_result(uint8_t result) { touch_result = result; }

uint8_t is_nfc(void) {
#ifdef TEST
  return 1;
#else
  return 0;
#endif
}
