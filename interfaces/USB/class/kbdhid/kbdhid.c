// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <common.h>
#include <crc.h>
#include <device.h>
#include <kbdhid.h>
#include <memzero.h>
#include <pass.h>
#include <usb_device.h>
#include <usbd_kbdhid.h>

#define EJECT_KEY 0x03
#define KBDHID_FEATURE_REPORT_SIZE 8

// Compatibility subset of the YubiKey OTP HID challenge-response protocol.
// A host writes ten 8-byte feature reports: seven frame bytes plus a sequence
// byte. The assembled frame is 64 bytes of challenge, one command byte, a
// little-endian CRC over the challenge, and three unused bytes.
#define YK_SLOT_DATA_SIZE 64

#define YK_SLOT_CHAL_HMAC1 0x30
#define YK_SLOT_CHAL_HMAC2 0x38

#define YK_RESP_PENDING_FLAG 0x40
#define YK_SLOT_WRITE_FLAG 0x80
#define YK_DUMMY_REPORT_WRITE 0x8f

static enum {
  KBDHID_Idle,
  KBDHID_Typing,
  KBDHID_KeyDown,
  KBDHID_KeyUp,
} state;
static char key_sequence[PASS_MAX_PASSWORD_LENGTH + 2]; // one for enter and one for '\0'
static uint8_t key_seq_position;
static keyboard_report_t report;

typedef struct {
  uint8_t payload[YK_SLOT_DATA_SIZE];
  uint8_t slot;
  uint8_t crc[2];
  uint8_t filler[3];
} __packed yk_frame_t;

static yk_frame_t feature_frame;
static uint8_t feature_status[KBDHID_FEATURE_REPORT_SIZE];
static uint8_t feature_response[5 * KBDHID_FEATURE_REPORT_SIZE];
static uint8_t feature_response_len;
static uint8_t feature_response_offset;

static void KBDHID_ResetFeatureFrame(void) { memzero(&feature_frame, sizeof(feature_frame)); }

static uint8_t pass_slot_from_yk_cmd(uint8_t cmd, uint8_t *slot) {
  switch (cmd) {
  case YK_SLOT_CHAL_HMAC1:
    *slot = 0;
    return 1;
  case YK_SLOT_CHAL_HMAC2:
    *slot = 1;
    return 1;
  default:
    return 0;
  }
}

static void KBDHID_SetStatus(uint8_t flags) {
  memset(feature_status, 0, sizeof(feature_status));
  feature_status[1] = 0x02;
  feature_status[2] = 0x02;
  feature_status[3] = 0x03;
  feature_status[4] = 0x03;
  feature_status[5] = 0x03;
  feature_status[6] = flags;
}

static void KBDHID_ClearFeatureResponse(void) {
  memzero(feature_response, sizeof(feature_response));
  feature_response_len = 0;
  feature_response_offset = 0;
}

static void KBDHID_BuildHmacResponse(uint8_t slot_index) {
  uint8_t hmac[PASS_HMAC_RESPONSE_LENGTH];
  uint8_t payload[28];
  memzero(feature_response, sizeof(feature_response));
  if (pass_hmacsha1(slot_index, feature_frame.payload, hmac) != PASS_HMAC_RESPONSE_LENGTH) {
    KBDHID_ClearFeatureResponse();
    KBDHID_SetStatus(0);
    return;
  }

  memzero(payload, sizeof(payload));
  memcpy(payload, hmac, sizeof(hmac));
  const uint16_t crc = crc16_ibm_sdlc(hmac, sizeof(hmac));
  payload[sizeof(hmac)] = LO(crc);
  payload[sizeof(hmac) + 1] = HI(crc);

  // The response is read as five 8-byte reports. The first four reports carry
  // seven payload bytes plus a pending/sequence marker; the last report only
  // clears the pending state after the host has consumed the payload.
  for (uint8_t i = 0; i < 4; i++) {
    memcpy(feature_response + i * KBDHID_FEATURE_REPORT_SIZE, payload + i * (KBDHID_FEATURE_REPORT_SIZE - 1),
           KBDHID_FEATURE_REPORT_SIZE - 1);
    feature_response[i * KBDHID_FEATURE_REPORT_SIZE + KBDHID_FEATURE_REPORT_SIZE - 1] = YK_RESP_PENDING_FLAG | (i + 1);
  }
  feature_response[4 * KBDHID_FEATURE_REPORT_SIZE + KBDHID_FEATURE_REPORT_SIZE - 1] = YK_RESP_PENDING_FLAG;
  feature_response_len = sizeof(feature_response);
  feature_response_offset = 0;
  KBDHID_SetStatus(YK_RESP_PENDING_FLAG | 1);
}

static void KBDHID_ProcessFeatureFrame(void) {
  uint8_t slot_index;
  const uint16_t expected_crc = crc16_ibm_sdlc(feature_frame.payload, YK_SLOT_DATA_SIZE);
  const uint16_t frame_crc = (uint16_t)feature_frame.crc[0] | ((uint16_t)feature_frame.crc[1] << 8);
  // Invalid CRCs and unsupported YK commands are reported as idle status with
  // no response bytes, matching the legacy challenge-response flow.
  if (frame_crc != expected_crc || !pass_slot_from_yk_cmd(feature_frame.slot, &slot_index)) {
    KBDHID_ClearFeatureResponse();
    KBDHID_SetStatus(0);
    return;
  }

  KBDHID_BuildHmacResponse(slot_index);
}

static void KBDHID_FeatureInit(void) {
  KBDHID_ResetFeatureFrame();
  KBDHID_ClearFeatureResponse();
  KBDHID_SetStatus(0);
}

static uint8_t ascii2keycode(char ch) {
  const uint8_t shift = 0x80; // Shift key flag

  // digits and lowercase letters
  if ('1' <= ch && ch <= '9') return 30 + ch - '1';
  if ('0' == ch) return 39;
  if ('a' <= ch && ch <= 'z') return 4 + ch - 'a';

  // uppercase letters
  if ('A' <= ch && ch <= 'Z') return (4 + ch - 'A') | shift;

  // symbols and special characters
  switch (ch) {
  case 13:
    return 0x28; // \r
  case 32:
    return 0x2C; // space
  case 33:
    return 0x1E | shift; // !
  case 34:
    return 0x34 | shift; // "
  case 35:
    return 0x20 | shift; // #
  case 36:
    return 0x21 | shift; // $
  case 37:
    return 0x22 | shift; // %
  case 38:
    return 0x24 | shift; // &
  case 39:
    return 0x34; // '
  case 40:
    return 0x26 | shift; // (
  case 41:
    return 0x27 | shift; // )
  case 42:
    return 0x25 | shift; // *
  case 43:
    return 0x2E | shift; // +
  case 44:
    return 0x36; // ,
  case 45:
    return 0x2D; // -
  case 46:
    return 0x37; // .
  case 47:
    return 0x38; // /
  case 58:
    return 0x33 | shift; // :
  case 59:
    return 0x33; // ;
  case 60:
    return 0x36 | shift; // <
  case 61:
    return 0x2E; // =
  case 62:
    return 0x37 | shift; // >
  case 63:
    return 0x38 | shift; // ?
  case 64:
    return 0x1F | shift; // @
  case 91:
    return 0x2F; // [
  case 92:
    return 0x31; // "\"
  case 93:
    return 0x30; // ]
  case 94:
    return 0x23 | shift; // ^
  case 95:
    return 0x2D | shift; // _
  case 96:
    return 0x35; // `
  case 123:
    return 0x2F | shift; // {
  case 124:
    return 0x31 | shift; // |
  case 125:
    return 0x30 | shift; // }
  case 126:
    return 0x35 | shift; // ~
  default:
    return 0; // undefined
  }
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
        uint8_t keycode = ascii2keycode(key_sequence[key_seq_position]);
        if (keycode & 0x80) {     // Check for shift flag
          report.modifier = 0x02; // Shift key
          keycode &= 0x7F;        // Clear shift flag
        } else {
          report.modifier = 0; // No modifier key
        }
        report.keycode[0] = keycode;
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
  KBDHID_FeatureInit();
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

uint8_t KBDHID_SetFeatureReport(const uint8_t *in_report, uint16_t len) {
  if (len != KBDHID_FEATURE_REPORT_SIZE) return 0;

  const uint8_t seq = in_report[KBDHID_FEATURE_REPORT_SIZE - 1];
  if (seq == YK_DUMMY_REPORT_WRITE) {
    KBDHID_FeatureInit();
    return 1;
  }
  if ((seq & YK_SLOT_WRITE_FLAG) == 0) return 0;

  const uint8_t frame_seq = seq & ~YK_SLOT_WRITE_FLAG;
  if (frame_seq >= 10) return 0;

  // Each SET_REPORT contributes seven bytes; processing starts only after the
  // tenth fragment completes the 70-byte compatibility frame.
  memcpy(((uint8_t *)&feature_frame) + frame_seq * 7, in_report, KBDHID_FEATURE_REPORT_SIZE - 1);
  KBDHID_SetStatus(0);
  if (frame_seq == 9) KBDHID_ProcessFeatureFrame();

  return 1;
}

uint8_t KBDHID_GetFeatureReport(uint8_t *out_report, uint16_t len) {
  if (len == 0) return 0;

  const uint16_t out_len = MIN(len, KBDHID_FEATURE_REPORT_SIZE);
  memset(out_report, 0, len);

  if (feature_response_offset < feature_response_len) {
    memcpy(out_report, feature_response + feature_response_offset, out_len);
    feature_response_offset += KBDHID_FEATURE_REPORT_SIZE;
    if (feature_response_offset >= feature_response_len) {
      // Keep status pending until the final chunk is served, then forget the
      // challenge so a repeated GET_REPORT cannot replay the previous HMAC.
      KBDHID_ResetFeatureFrame();
      KBDHID_SetStatus(0);
    }
  } else {
    memcpy(out_report, feature_status, out_len);
  }

  return 1;
}
