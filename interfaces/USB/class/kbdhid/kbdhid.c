#include <tusb.h>

#include <common.h>
#include <device.h>
#include <oath.h>

#include <kbdhid.h>
#include <usb_descriptors.h>

static enum {
  KBDHID_Idle,
  KBDHID_Typing,
  KBDHID_KeyDown,
  KBDHID_KeyUp,
} state;

static const uint8_t ascii_to_keycode[128][2] = {HID_ASCII_TO_KEYCODE};
static char key_sequence[8 + 2];
static uint8_t keycode[6];
static uint8_t modifier;

static uint8_t key_seq_position;
static uint32_t last_sent;

//--------------------------------------------------------------------+
// User class code
//--------------------------------------------------------------------+

static void KBDHID_UserTouchHandle(void) {
  int ret;
  memset(key_sequence, 0, sizeof(key_sequence));
  ret = oath_process_one_touch(key_sequence, sizeof(key_sequence));
  if (ret < 0) {
    ERR_MSG("Failed to get the OTP code: %d\r\n", ret);
    if (ret == -2)
      memcpy(key_sequence, "not-set\r", 8);
    else
      memcpy(key_sequence, "error\r", 6);
  } else {
    for (size_t i = 0; i < sizeof(key_sequence) - 1; i++) {
      if (key_sequence[i] == '\0') {
        key_sequence[i] = '\r';
        break;
      }
    }
  }

  key_seq_position = 0;
  state = KBDHID_Typing;
  DBG_MSG("Start typing %s\r\n", key_sequence);
}

static void KBDHID_TypeKeySeq() {
  switch (state) {
  case KBDHID_Idle:
    break;

  case KBDHID_Typing:
  case KBDHID_KeyUp:
    if (key_sequence[key_seq_position] == '\0') {
      DBG_MSG("Key typing ended\r\n");
      state = KBDHID_Idle;
    } else if (tud_hid_n_ready(HID_ITF_KBD)) {
      // Emulate key down
      uint8_t chr = (uint8_t)key_sequence[key_seq_position];
      modifier = (ascii_to_keycode[chr][0]) ? KEYBOARD_MODIFIER_LEFTSHIFT : 0;
      keycode[0] = ascii_to_keycode[chr][1];
      tud_hid_n_keyboard_report(HID_ITF_KBD, 0, modifier, keycode);

      state = KBDHID_KeyDown;
    }
    break;

  case KBDHID_KeyDown:
    if (tud_hid_n_ready(HID_ITF_KBD)) {
      // Emulate key release
      modifier = 0;
      keycode[0] = 0;
      tud_hid_n_keyboard_report(HID_ITF_KBD, 0, modifier, keycode);

      key_seq_position++;
      state = KBDHID_KeyUp;
      break;
    }
  }
}

void kbd_hid_init(void) {
  state = KBDHID_Idle;

  key_seq_position = 0;
  last_sent = 0;

  memset(keycode, 0, sizeof(keycode));
  modifier = 0;
}

void kbd_hid_loop(void) {
  if (get_touch_result() == TOUCH_SHORT && state == KBDHID_Idle && device_get_tick() - last_sent > 1000) {
    DBG_MSG("Short touch detected\r\n");

    KBDHID_UserTouchHandle();
    last_sent = device_get_tick();
    set_touch_result(TOUCH_NO);
  }

  if (state != KBDHID_Idle) KBDHID_TypeKeySeq();
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
