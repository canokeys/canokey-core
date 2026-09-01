// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <device.h>
#include <kbdhid.h>
#include <pass.h>
#include <usb_device.h>
#include <usbd_kbdhid.h>

#define EJECT_KEY 0x03

static enum {
  KBDHID_Idle,
  KBDHID_Typing,
  KBDHID_KeyDown,
  KBDHID_KeyUp,
} state;
static char key_sequence[PASS_MAX_PASSWORD_LENGTH + 2]; // one for enter and one for '\0'
static uint8_t key_seq_position;
static keyboard_report_t report;

static bool ascii2key_report(char ch, uint8_t *modifier, uint8_t *usage) {
  // Platforms can provide a layout-specific map. If they do, the returned HID
  // report is authoritative; the built-in table is only the QWERTY fallback.
  if (kbdhid_platform_translate_ascii((uint8_t)ch, modifier, usage)) return true;

  const uint8_t shift = 0x80; // Shift key flag
  uint8_t keycode;

  // digits and lowercase letters
  if ('1' <= ch && ch <= '9') {
    keycode = 30 + ch - '1';
    goto done;
  }
  if ('0' == ch) {
    keycode = 39;
    goto done;
  }
  if ('a' <= ch && ch <= 'z') {
    keycode = 4 + ch - 'a';
    goto done;
  }

  // uppercase letters
  if ('A' <= ch && ch <= 'Z') {
    keycode = (4 + ch - 'A') | shift;
    goto done;
  }

  // symbols and special characters
  switch (ch) {
  case 13:
    keycode = 0x28; // \r
    break;
  case 32:
    keycode = 0x2C; // space
    break;
  case 33:
    keycode = 0x1E | shift; // !
    break;
  case 34:
    keycode = 0x34 | shift; // "
    break;
  case 35:
    keycode = 0x20 | shift; // #
    break;
  case 36:
    keycode = 0x21 | shift; // $
    break;
  case 37:
    keycode = 0x22 | shift; // %
    break;
  case 38:
    keycode = 0x24 | shift; // &
    break;
  case 39:
    keycode = 0x34; // '
    break;
  case 40:
    keycode = 0x26 | shift; // (
    break;
  case 41:
    keycode = 0x27 | shift; // )
    break;
  case 42:
    keycode = 0x25 | shift; // *
    break;
  case 43:
    keycode = 0x2E | shift; // +
    break;
  case 44:
    keycode = 0x36; // ,
    break;
  case 45:
    keycode = 0x2D; // -
    break;
  case 46:
    keycode = 0x37; // .
    break;
  case 47:
    keycode = 0x38; // /
    break;
  case 58:
    keycode = 0x33 | shift; // :
    break;
  case 59:
    keycode = 0x33; // ;
    break;
  case 60:
    keycode = 0x36 | shift; // <
    break;
  case 61:
    keycode = 0x2E; // =
    break;
  case 62:
    keycode = 0x37 | shift; // >
    break;
  case 63:
    keycode = 0x38 | shift; // ?
    break;
  case 64:
    keycode = 0x1F | shift; // @
    break;
  case 91:
    keycode = 0x2F; // [
    break;
  case 92:
    keycode = 0x31; // "\"
    break;
  case 93:
    keycode = 0x30; // ]
    break;
  case 94:
    keycode = 0x23 | shift; // ^
    break;
  case 95:
    keycode = 0x2D | shift; // _
    break;
  case 96:
    keycode = 0x35; // `
    break;
  case 123:
    keycode = 0x2F | shift; // {
    break;
  case 124:
    keycode = 0x31 | shift; // |
    break;
  case 125:
    keycode = 0x30 | shift; // }
    break;
  case 126:
    keycode = 0x35 | shift; // ~
    break;
  default:
    return false; // undefined
  }

done:
  if (keycode & shift) {
    *modifier = 0x02; // Shift key
    keycode &= ~shift;
  } else {
    *modifier = 0;
  }
  *usage = keycode;
  return true;
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
      if (key_sequence[key_seq_position] == EJECT_KEY) {
        report.id = 2;
        report.modifier = 0xB8;
        // Emulate the key press
        USBD_KBDHID_SendReport(&usb_device, (uint8_t *)&report, 2);
      } else {
        if (!ascii2key_report(key_sequence[key_seq_position], &report.modifier, &report.keycode[0])) {
          key_seq_position++;
          state = KBDHID_KeyUp;
          break;
        }
        if (report.keycode[0] == 0) {
          key_seq_position++;
          state = KBDHID_KeyUp;
          break;
        }
        report.id = 1;
        // Emulate the key press
        USBD_KBDHID_SendReport(&usb_device, (uint8_t *)&report, sizeof(report));
      }
      state = KBDHID_KeyDown;
    }
    break;

  case KBDHID_KeyDown:
    if (USBD_KBDHID_IsIdle()) {
      memset(&report, 0, sizeof(report)); // Clear the report
      if (key_sequence[key_seq_position] == EJECT_KEY) {
        report.id = 2;
        // Emulate the key release
        USBD_KBDHID_SendReport(&usb_device, (uint8_t *)&report, 2);
      } else {
        report.id = 1;
        // Emulate the key release
        USBD_KBDHID_SendReport(&usb_device, (uint8_t *)&report, sizeof(report));
      }
      key_seq_position++;
      state = KBDHID_KeyUp;
      break;
    }
  }
}

void KBDHID_Eject() {
  key_sequence[0] = EJECT_KEY;
  key_sequence[1] = 0;
  key_seq_position = 0;
  state = KBDHID_Typing;
}

uint8_t KBDHID_Init() {
  memset(&report, 0, sizeof(report));
  state = KBDHID_Idle;
  return 0;
}

uint8_t KBDHID_Loop(void) {
  if (state == KBDHID_Idle && device_allow_kbd_touch()) {
    const uint8_t touch = get_touch_result();
    if (touch != TOUCH_NO) {
      const int len = pass_handle_touch(touch, key_sequence);
      set_touch_result(TOUCH_NO);
      if (len <= 0) {
        DBG_MSG("Do nothing\n");
        return 0;
      }
      key_sequence[len] = 0;
      key_seq_position = 0;
      state = KBDHID_Typing;
      DBG_MSG("Start typing %s\n", key_sequence);
    }
  } else {
    KBDHID_TypeKeySeq();
  }
  return 0;
}
