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
static uint32_t last_blink = UINT32_MAX, blink_timeout, blink_interval;
static enum { ON, OFF } led_status;
typedef enum { WAIT_NONE = 1, WAIT_CCID, WAIT_CTAPHID, WAIT_DEEP, WAIT_DEEP_TOUCHED, WAIT_DEEP_CANCEL } wait_status_t;
volatile static wait_status_t wait_status = WAIT_NONE; // WAIT_NONE is not 0, hence inited

#define IS_BLINKING (last_blink != UINT32_MAX)

void device_loop(uint8_t has_touch) {
  CCID_Loop();
  CTAPHID_Loop(0);
  WebUSB_Loop();
  if (has_touch &&                  // hardware features the touch pad
      !IS_BLINKING &&               // applets are not waiting for touch
      cfg_is_kbd_interface_enable() // keyboard emulation enabled
  )
    KBDHID_Loop();
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
    if (now - last >= 300) {
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
  if (now >= last_blink && now - last_blink >= blink_interval) {
    last_blink = now;
    toggle_led();
  }
}

void start_blinking_interval(uint8_t sec, uint32_t interval) {
  if (IS_BLINKING) return;
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
  last_blink = UINT32_MAX;
  if (cfg_is_led_normally_on()) {
    led_on();
    led_status = ON;
  } else {
    led_off();
    led_status = OFF;
  }
}

#ifdef TEST
#include <stdio.h>
int testmode_emulate_user_presence(void) {
  if (!IS_BLINKING) return; // user only touches while blinking

  int counter = 0;
  FILE *f_cnt = fopen("/tmp/canokey-test-up", "r");
  if (f_cnt != NULL) {
    fscanf(f_cnt, "%d", &counter);
    fclose(f_cnt);
  } else {
    ERR_MSG("Failed to open canokey-test-up for reading\n");
  }
  counter++;
  DBG_MSG("counter=%d\n", counter);
  f_cnt = fopen("/tmp/canokey-test-up", "w");
  if (f_cnt != NULL) {
    fprintf(f_cnt, "%d", counter);
    fclose(f_cnt);
  } else {
    ERR_MSG("Failed to open canokey-test-up for writing\n");
  }

  set_touch_result(TOUCH_SHORT);
  return 0;
}

int testmode_get_is_nfc_mode(void) {
  uint32_t nfc_mode = 0;
  FILE *f_cfg = fopen("/tmp/canokey-test-nfc", "r");
  if (f_cfg == NULL) return -1;
  if (fscanf(f_cfg, "%u", &nfc_mode) < 1) return -1;
  fclose(f_cfg);
  set_nfc_state((uint8_t)nfc_mode);
  return 0;
}

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update) {
  if (*var == expect) {
    *var = update;
    return 0;
  } else {
    return -1;
  }
}

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking) {
  // Not really working, for test only
  while (*lock) {
    if (!blocking) return -1;
  }
  *lock = 1;
  return 0;
}
void device_spinlock_unlock(volatile uint32_t *lock) { *lock = 0; }

void led_on(void) {}
void led_off(void) {}

#endif
