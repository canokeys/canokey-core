// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <common.h>
#include <device.h>
#include <kbdhid.h>
#include <oath.h>
#include <usb_device.h>
#include <usbd_kbdhid.h>

static enum {
  KBDHID_Idle,
  KBDHID_Typing,
  KBDHID_KeyDown,
  KBDHID_KeyUp,
} state;
static char key_sequence[8 + 2];
static uint8_t key_seq_position;
static keyboard_report_t report;
static uint32_t last_sent;

static uint8_t ascii2keycode(char ch) {
  if ('1' <= ch && ch <= '9')
    return 30 + ch - '1';
  else if ('0' == ch)
    return 30 + 9;
  else if ('\r' == ch)
    return 40;
  else if ('a' <= ch && ch <= 'z')
    return 4 + ch - 'a';
  else if ('-' == ch)
    return 0x2d;
  else
    return 0; // do not support non-digits for now
}

static void KBDHID_UserTouchHandle(void) {
  int ret, len;
  memset(key_sequence, 0, sizeof(key_sequence));
  ret = oath_process_one_touch(key_sequence, sizeof(key_sequence));
  if (ret < 0) {
    ERR_MSG("Failed to get the OTP code: %d\n", ret);
    if (ret == -2) {
      memcpy(key_sequence, "not-set", 7);
      len = 7;
    } else {
      memcpy(key_sequence, "error", 5);
      len = 5;
    }
  } else {
    for (int i = 0; i < sizeof(key_sequence) - 1; i++) {
      if (key_sequence[i] == '\0') {
        len = i;
        break;
      }
    }
  }
  if (cfg_is_kbd_with_return_enable()) key_sequence[len] = '\r';
  key_seq_position = 0;
  state = KBDHID_Typing;
  DBG_MSG("Start typing %s", key_sequence);
}

static void KBDHID_TypeKeySeq(void) {
  switch (state) {
  case KBDHID_Idle:
    break;
  case KBDHID_Typing:
  case KBDHID_KeyUp:
    if (key_sequence[key_seq_position] == '\0') {
      DBG_MSG("Key typing ended\n");
      state = KBDHID_Idle;
    } else if (USBD_KBDHID_IsIdle()) {
      report.keycode[0] = ascii2keycode(key_sequence[key_seq_position]);
      // Emulate the key press
      USBD_KBDHID_SendReport(&usb_device, (uint8_t *)&report, sizeof(report));
      state = KBDHID_KeyDown;
    }
    break;

  case KBDHID_KeyDown:
    if (USBD_KBDHID_IsIdle()) {
      report.keycode[0] = 0;
      // Emulate the key release
      USBD_KBDHID_SendReport(&usb_device, (uint8_t *)&report, sizeof(report));
      key_seq_position++;
      state = KBDHID_KeyUp;
      break;
    }
  }
}

uint8_t KBDHID_Init() {
  last_sent = 0;
  memset(&report, 0, sizeof(report));
  state = KBDHID_Idle;
  return 0;
}

uint8_t KBDHID_Loop(void) {
  if (get_touch_result() == TOUCH_SHORT && state == KBDHID_Idle && device_get_tick() - last_sent > 1000) {
    KBDHID_UserTouchHandle();
    last_sent = device_get_tick();
    set_touch_result(TOUCH_NO);
  }
  if (state != KBDHID_Idle) KBDHID_TypeKeySeq();
  return 0;
}
