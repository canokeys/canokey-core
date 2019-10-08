#include "common.h"
#include <ccid.h>
#include <ctaphid.h>
#include <device.h>
#include <webusb.h>

#ifndef TEST

volatile static uint8_t touch_result;
static uint8_t is_inf_blinking;
static uint32_t last_blink = UINT32_MAX;

__weak void device_delay(int ms) {}

__weak uint32_t device_get_tick(void) { return 0; }

__weak void device_start_blinking(uint8_t sec) {}

__weak void device_stop_blinking(void) {}

__weak uint8_t is_nfc(void) {
  return 0;
}

uint8_t wait_for_user_presence(void) {
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
  return USER_PRESENCE_OK;
}

void device_loop(void) {
  CCID_Loop();
  CTAPHID_Loop(0);
  WebUSB_Loop();
}

uint8_t get_touch_result(void) { return touch_result; }

void set_touch_result(uint8_t result) { touch_result = result; }

void start_blinking(uint8_t sec) {
  if (sec == 0) {
    if (is_inf_blinking) return;
    is_inf_blinking = 1;
  } else {
    uint32_t now = device_get_tick();
    if (now > last_blink && now - last_blink < 1000) return;
    last_blink = now;
  }
  device_start_blinking(sec);
}

void stop_blinking(void) {
  is_inf_blinking = 0;
  device_stop_blinking();
}

#endif
