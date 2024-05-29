// SPDX-License-Identifier: Apache-2.0
#include <tusb.h>

#include <admin.h>
#include <common.h>
#include <device.h>
#include <pass.h>

#include <kbdhid.h>
#include <usb_descriptors.h>

#define EJECT_KEY 0x03

static enum {
  KBDHID_Idle,
  KBDHID_Typing,
  KBDHID_KeyDown,
  KBDHID_KeyUp,
} state;
static char key_sequence[PASS_MAX_PASSWORD_LENGTH + 2]; // one for enter and one for '\0'
static uint8_t key_seq_position;

static uint8_t ascii2keycode(char ch) {
  const uint8_t shift = 0x80; // Shift key flag

  // digits and lowercase letters
  if ('1' <= ch && ch <= '9')
    return 30 + ch - '1';
  if ('0' == ch)
    return 39;
  if ('a' <= ch && ch <= 'z')
    return 4 + ch - 'a';

  // uppercase letters
  if ('A' <= ch && ch <= 'Z')
    return (4 + ch - 'A') | shift;

  // symbols and special characters
  switch(ch) {
  case 13: return 0x28; // \r
  case 32: return 0x2C; // space
  case 33: return 0x1E | shift; // !
  case 34: return 0x34 | shift; // "
  case 35: return 0x20 | shift; // #
  case 36: return 0x21 | shift; // $
  case 37: return 0x22 | shift; // %
  case 38: return 0x24 | shift; // &
  case 39: return 0x34; // '
  case 40: return 0x26 | shift; // (
  case 41: return 0x27 | shift; // )
  case 42: return 0x25 | shift; // *
  case 43: return 0x2E | shift; // +
  case 44: return 0x36; // ,
  case 45: return 0x2D; // -
  case 46: return 0x37; // .
  case 47: return 0x38; // /
  case 58: return 0x33 | shift; // :
  case 59: return 0x33; // ;
  case 60: return 0x36 | shift; // <
  case 61: return 0x2E; // =
  case 62: return 0x37 | shift; // >
  case 63: return 0x38 | shift; // ?
  case 64: return 0x1F | shift; // @
  case 91: return 0x2F; // [
  case 92: return 0x31; // "\"
  case 93: return 0x30; // ]
  case 94: return 0x23 | shift; // ^
  case 95: return 0x2D | shift; // _
  case 96: return 0x35; // `
  case 123: return 0x2F | shift; // {
  case 124: return 0x31 | shift; // |
  case 125: return 0x30 | shift; // }
  case 126: return 0x35 | shift; // ~
  default: return 0; // undefined
  }
}

static void KBDHID_TypeKeySeq(void) {
  static uint8_t modifier, keycode[6];
  switch (state) {
  case KBDHID_Idle:
    break;

  case KBDHID_Typing:
  case KBDHID_KeyUp:
    if (key_sequence[key_seq_position] == '\0') {
      DBG_MSG("Key typing ended\n");
      state = KBDHID_Idle;
    } else if (tud_hid_n_ready(HID_ITF_KBD)) {
      uint8_t report_id = 1;
      if (key_sequence[key_seq_position] == EJECT_KEY) {
        report_id = 2;
        keycode[0] = 0;
        modifier = 0xB8;
      } else {
        // Emulate key down
        keycode[0] = ascii2keycode(key_sequence[key_seq_position]);
        if (keycode[0] & 0x80) { // Check for shift flag
          modifier = 0x02; // Shift key
          keycode[0] &= 0x7F; // Clear shift flag
        } else {
          modifier = 0; // No modifier key
        }
      }
      tud_hid_n_keyboard_report(HID_ITF_KBD, report_id, modifier, keycode);

      state = KBDHID_KeyDown;
    }
    break;

  case KBDHID_KeyDown:
    if (tud_hid_n_ready(HID_ITF_KBD)) {
      // Emulate key release
      modifier = 0;
      keycode[0] = 0;
      if (key_sequence[key_seq_position] == EJECT_KEY) {
        // Emulate the key release
        tud_hid_n_keyboard_report(HID_ITF_KBD, 2, modifier, keycode);
      } else {
        // Emulate the key release
        tud_hid_n_keyboard_report(HID_ITF_KBD, 1, modifier, keycode);
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

void kbd_hid_init(void) {
  state = KBDHID_Idle;

  key_seq_position = 0;
}

void kbd_hid_loop(void) {
  if (state == KBDHID_Idle) {
    const uint8_t touch = get_touch_result();
    if (touch != TOUCH_NO) {
      const int len = pass_handle_touch(touch, key_sequence);
      if (len <= 0) {
        DBG_MSG("Do nothing\n");
        return;
      }
      key_sequence[len] = 0;
      key_seq_position = 0;
      state = KBDHID_Typing;
      DBG_MSG("Start typing %s", key_sequence);
    }
    set_touch_result(TOUCH_NO);
  } else {
    KBDHID_TypeKeySeq();
  }

}

//--------------------------------------------------------------------+
// TinyUSB callbacks
//--------------------------------------------------------------------+

// Invoked when sent REPORT successfully to host
void kbd_hid_report_complete_cb(uint8_t const *report, uint8_t len) {
  // There is nothing to do...

  (void)len;
}

// Invoked when received GET_REPORT control request
uint16_t kbd_hid_get_report_cb(uint8_t report_id, hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen) {
  // not implemented, stall the request
  (void)report_id;
  (void)report_type;
  (void)buffer;
  (void)reqlen;

  return 0;
}

// Invoked when received SET_REPORT control request or
// received data on OUT endpoint ( Report ID = 0, Type = 0 )
void kbd_hid_set_report_cb(uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
  // There is nothing to do...
}
