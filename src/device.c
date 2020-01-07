#include "common.h"
#include <admin.h>
#include <ccid.h>
#include <ctaphid.h>
#include <device.h>
#include <kbdhid.h>
#include <webusb.h>

#ifndef TEST

volatile static uint8_t touch_result;
static uint8_t has_rf, is_blinking;
static uint32_t last_blink = UINT32_MAX, blink_timeout, blink_interval;
static enum { ON, OFF } led_status;

uint8_t wait_for_user_presence(void) {
  uint32_t start = device_get_tick();
  uint32_t last = start;
  DBG_MSG("start %u\n", start);
  while (touch_result == TOUCH_NO) {
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
  touch_result = TOUCH_NO;
  return USER_PRESENCE_OK;
}

uint8_t get_touch_result(void) { return touch_result; }

void set_touch_result(uint8_t result) { touch_result = result; }

void set_nfc_state(uint8_t val) { has_rf = val; }

uint8_t is_nfc(void) { return has_rf; }

static void toggle_led(void) {
  if (led_status == ON) {
    led_off();
    led_status = OFF;
  } else {
    led_on();
    led_status = ON;
  }
}

static void update_led(void) {
  uint32_t now = device_get_tick();
  if (now > blink_timeout) stop_blinking();
  if (now >= last_blink && now - last_blink >= blink_interval) {
    last_blink = now;
    toggle_led();
  }
}

void start_blinking(uint8_t sec) {
  if (is_blinking) return;
  last_blink = device_get_tick();
  if (sec == 0) {
    blink_timeout = UINT32_MAX;
    blink_interval = 1000;
  } else {
    blink_timeout = last_blink + sec * 1000;
    blink_interval = sec * 500;
  }
  toggle_led();
}

void stop_blinking(void) {
  is_blinking = 0;
  last_blink = UINT32_MAX;
  if (cfg_is_led_normally_on()) {
    led_on();
    led_status = ON;
  } else {
    led_off();
    led_status = OFF;
  }
}

void device_loop(void) {
  static uint8_t cnt = 1;
  CCID_Loop();
  CTAPHID_Loop(0);
  WebUSB_Loop();
  KBDHID_Loop();
  if (++cnt == 0) update_led();
}

#else

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking) {
  // Not really working, for test only
  while (*lock) {
    if (!blocking) return -1;
  }
  *lock = 1;
  return 0;
}
void device_spinlock_unlock(volatile uint32_t *lock) { *lock = 0; }

#endif
