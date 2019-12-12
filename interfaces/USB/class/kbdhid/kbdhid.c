#include <common.h>
#include <device.h>
#include <kbdhid.h>
#include <usb_device.h>
#include <usbd_kbdhid.h>

static enum {
  KBDHID_Idle,
  KBDHID_Typing,
  KBDHID_KeyDown,
  KBDHID_KeyUp,
} state;
static char key_sequence[10];
static uint8_t key_seq_position;
static keyboard_report_t report;

static uint8_t ascii2keycode(char ch) {
  if ('1' <= ch && ch <= '9')
    return 30 + ch - '1';
  else if ('0' == ch)
    return 30 + 9;
  else
    return 0; // do not support non-digits for now
}

static void KBDHID_UserTouchHandle(void) {
  // TODO: call something
  strcpy(key_sequence, "123456");
  key_seq_position = 0;
  state = KBDHID_Typing;
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
  state = KBDHID_Idle;
  return 0;
}

uint8_t KBDHID_Loop(void) {
  static uint8_t active;
  if (!active) {
    if (get_touch_result() == TOUCH_SHORT) {
      active = 1;
      if (state == KBDHID_Idle) {
        KBDHID_UserTouchHandle();
      }
    }
  } else {
    if (get_touch_result() == TOUCH_NO) {
      active = 0;
    }
  }
  if (state != KBDHID_Idle) KBDHID_TypeKeySeq();
  return 0;
}
