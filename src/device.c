// SPDX-License-Identifier: Apache-2.0
#include "common.h"
#include <admin.h>
#include <ccid.h>
#include <ctaphid.h>
#include <device.h>
#include <kbdhid.h>
#include <webusb.h>

volatile static uint8_t touch_result;
static uint8_t has_rf;
static uint32_t last_blink, blink_timeout, blink_interval;
static enum { ON, OFF } led_status;
typedef enum { WAIT_NONE = 1, WAIT_CCID, WAIT_CTAPHID, WAIT_DEEP, WAIT_DEEP_TOUCHED, WAIT_DEEP_CANCEL } wait_status_t;
volatile static wait_status_t wait_status = WAIT_NONE; // WAIT_NONE is not 0, hence inited

uint8_t device_is_blinking(void) { return blink_timeout != 0; }

void device_loop(void) {
  CCID_Loop();
  CTAPHID_Loop(0);
  WebUSB_Loop();
  KBDHID_Loop();
}

bool device_allow_kbd_touch(void) {
  uint32_t now = device_get_tick();
  if (!device_is_blinking() &&      // applets are not waiting for touch
      now > 2000   &&               // ignore touch for the first 2 seconds
      now - 1000 > last_blink &&
      get_touch_result() != TOUCH_NO
  ) {
    DBG_MSG("now=%lu last_blink=%lu\n", now, last_blink);
    return true;
  }
  return false;
}

uint8_t get_touch_result(void) {
#ifdef TEST // emulate user interaction in test mode
  testmode_emulate_user_presence();
#endif
  return touch_result;
}

void set_touch_result(uint8_t result) { touch_result = result; }

uint8_t wait_for_user_presence(uint8_t entry) {
  start_blinking(0);
  uint32_t start = device_get_tick();
  uint32_t last = start;
  DBG_MSG("start %u\n", start);

  wait_status_t shallow = wait_status;
  if (wait_status == WAIT_NONE) {
    switch (entry) {
    case WAIT_ENTRY_CCID:
      wait_status = WAIT_CCID;
      break;
    case WAIT_ENTRY_CTAPHID:
      wait_status = WAIT_CTAPHID;
      break;
    }
  } else
    wait_status = WAIT_DEEP;
  while (get_touch_result() == TOUCH_NO) {
    if (wait_status == WAIT_DEEP_TOUCHED || wait_status == WAIT_DEEP_CANCEL) break;
    if (wait_status == WAIT_CTAPHID) CCID_Loop();
    if (CTAPHID_Loop(wait_status != WAIT_CCID) == LOOP_CANCEL) {
      DBG_MSG("Cancelled by host\n");
      if (wait_status != WAIT_DEEP) {
        stop_blinking();
        wait_status = WAIT_NONE; // namely shallow
      } else
        wait_status = WAIT_DEEP_CANCEL;
      return USER_PRESENCE_CANCEL;
    }
    uint32_t now = device_get_tick();
    if (now - start >= 30000) {
      DBG_MSG("timeout at %u\n", now);
      if (wait_status != WAIT_DEEP) stop_blinking();
      wait_status = shallow;
      return USER_PRESENCE_TIMEOUT;
    }
    if (now - last >= 100) {
      last = now;
      if (wait_status != WAIT_CCID) CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_UPNEEDED);
    }
  }
  set_touch_result(TOUCH_NO);
  if (wait_status != WAIT_DEEP) stop_blinking();
  if (wait_status == WAIT_DEEP)
    wait_status = WAIT_DEEP_TOUCHED;
  else if (wait_status == WAIT_DEEP_CANCEL) {
    wait_status = WAIT_NONE;
    return USER_PRESENCE_TIMEOUT;
  } else
    wait_status = WAIT_NONE;
  return USER_PRESENCE_OK;
}

int send_keepalive_during_processing(uint8_t entry) {
  if (entry == WAIT_ENTRY_CTAPHID) CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_PROCESSING);
  DBG_MSG("KEEPALIVE\n");
  return 0;
}

__attribute__((weak)) int strong_user_presence_test(void) {
  for (int i = 0; i < 5; i++) {
    const uint8_t wait_sec = 2;
    start_blinking_interval(wait_sec, (i & 1) ? 200 : 50);
    uint32_t now, begin = device_get_tick();
    bool user_presence = false;
    do {
      if (get_touch_result() == TOUCH_SHORT) {
        user_presence = true;
        set_touch_result(TOUCH_NO);
        stop_blinking();
        // wait for some time before next user-precense test
        begin = device_get_tick();
      }
      now = device_get_tick();
    } while (now - begin < 1000 * wait_sec);
    if (!user_presence) {
      return -1;
    }
  }
  return 0;
}

void set_nfc_state(uint8_t val) { has_rf = val; }

uint8_t is_nfc(void) {
#ifdef TEST // read NFC emulation config from a file
  testmode_get_is_nfc_mode();
#endif
  return has_rf;
}

static void toggle_led(void) {
  if (led_status == ON) {
    led_off();
    led_status = OFF;
  } else {
    led_on();
    led_status = ON;
  }
}

void device_update_led(void) {
  uint32_t now = device_get_tick();
  if (now > blink_timeout) stop_blinking();
  if (device_is_blinking() && now >= last_blink && now - last_blink >= blink_interval) {
    last_blink = now;
    toggle_led();
  }
}

void start_blinking_interval(uint8_t sec, uint32_t interval) {
  if (device_is_blinking()) return;
  last_blink = device_get_tick();
  blink_interval = interval;
  if (sec == 0) {
    blink_timeout = UINT32_MAX;
  } else {
    blink_timeout = last_blink + sec * 1000;
  }
  toggle_led();
}

void stop_blinking(void) {
  blink_timeout = 0;
  if (cfg_is_led_normally_on()) {
    led_on();
    led_status = ON;
  } else {
    led_off();
    led_status = OFF;
  }
}
