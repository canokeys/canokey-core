#include "key.h"
#include <common.h>
#include <pin.h>
#include <piv.h>

#define MAX_BUFFER_SIZE 2000
#define KEY_PIV_AUTH_PATH "piv-pau"
#define KEY_CARD_ADMIN_PATH "piv-adm"
#define KEY_SIG_PATH "piv-sig"
#define KEY_MANAGEMENT_PATH "piv-mnt"
#define KEY_CARD_AUTH_PATH "piv-cau"
#define STATE_NORMAL 0
#define STATE_LONG_RESPONSE 1
#define STATE_CHAINING 2

static const uint8_t rid[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t pix[] = {0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
static const uint8_t pin_policy[] = {0x00, 0x00};
static uint8_t *buffer;
static uint16_t buffer_pos, buffer_len, buffer_cap;
static uint8_t state, state_ins, state_p1, state_p2;

static pin_t pin = {
    .min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-pin"};
static pin_t puk = {
    .min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-puk"};

int piv_install() {
  // PIN data
  if (pin_create(&pin, "123456\xFF\xFF", 8, 3) < 0)
    return -1;
  if (pin_create(&puk, "12345678", 8, 3) < 0)
    return -1;

  // Keys and certs
  if (key_create(KEY_PIV_AUTH_PATH) < 0)
    return -1;
  if (key_create(KEY_CARD_ADMIN_PATH) < 0)
    return -1;
  if (key_create(KEY_SIG_PATH) < 0)
    return -1;
  if (key_create(KEY_MANAGEMENT_PATH) < 0)
    return -1;
  if (key_create(KEY_CARD_AUTH_PATH) < 0)
    return -1;

  return 0;
}

static const char *get_key_path_by_tag(uint8_t tag) {
  switch (tag) {
  case 0x05: // X.509 Certificate for PIV Authentication
    return KEY_PIV_AUTH_PATH;
  case 0x01: // X.509 Certificate for Card Authentication
    return KEY_CARD_AUTH_PATH;
  case 0x0A: // X.509 Certificate for Digital Signature
    return KEY_SIG_PATH;
  case 0x0B: // X.509 Certificate for Key Management
    return KEY_MANAGEMENT_PATH;
  default:
    return NULL;
  }
}

static void send_response(RAPDU *rapdu, uint16_t le) {
  uint32_t to_send = buffer_len - buffer_pos;
  if (to_send > le)
    to_send = le;
  memcpy(RDATA, buffer + buffer_pos, to_send);
  buffer_pos += to_send;
  LL = to_send;
  if (buffer_pos < buffer_len) {
    state = STATE_LONG_RESPONSE;
    if (buffer_len - buffer_pos > 0xFF)
      SW = 0x61FF;
    else
      SW = 0x6100 + (buffer_len - buffer_pos);
  }
}

int piv_deselect() { return 0; }

int piv_select(const CAPDU *capdu, RAPDU *rapdu) {
  // This implementation is compatible with Yubikey 5, which is different from
  // NIST SP 800-73-4
  (void)capdu;
  buffer[0] = 0x61;
  buffer[1] = 6 + sizeof(pix) + sizeof(rid);
  buffer[2] = 0x4F;
  buffer[3] = sizeof(pix);
  memcpy(buffer + 4, pix, sizeof(pix));
  buffer[4 + sizeof(pix)] = 0x79;
  buffer[5 + sizeof(pix)] = 2 + sizeof(rid);
  buffer[6 + sizeof(pix)] = 0x4F;
  buffer[7 + sizeof(pix)] = sizeof(rid);
  memcpy(buffer + 8 + sizeof(pix), rid, sizeof(rid));
  buffer_len = 8 + sizeof(pix) + sizeof(rid);
  send_response(rapdu, LE);
  return 0;
}

/*
 * Command Data:
 * ---------------------------------------------
 *   Name     Tag    Value
 * ---------------------------------------------
 * Tag List   5C     Tag to read
 *                   0x7E for Discovery Object
 *                   0x7F61 for BIT, ignore
 *                   0x5FC1xx for others
 * ---------------------------------------------
 */
int piv_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x3F || P2 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (DATA[0] != 0x5C)
    EXCEPT(SW_WRONG_DATA);
  if (DATA[1] + 2 != LC)
    EXCEPT(SW_WRONG_LENGTH);
  if (DATA[1] == 1) {
    if (DATA[2] != 0x7E)
      EXCEPT(SW_FILE_NOT_FOUND);
    // For the Discovery Object, the 0x7E template nests two data elements:
    // 1) tag 0x4F contains the AID of the PIV Card Application and
    // 2) tag 0x5F2F lists the PIN Usage Policy.
    buffer[0] = 0x7E;
    buffer[1] = 5 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
    buffer[2] = 0x4F;
    buffer[3] = sizeof(rid) + sizeof(pix);
    memcpy(buffer + 4, rid, sizeof(rid));
    memcpy(buffer + 4 + sizeof(rid), pix, sizeof(pix));
    buffer[4 + sizeof(rid) + sizeof(pix)] = 0x5F;
    buffer[5 + sizeof(rid) + sizeof(pix)] = 0x2F;
    buffer[6 + sizeof(rid) + sizeof(pix)] = sizeof(pin_policy);
    memcpy(buffer + 7 + sizeof(rid) + sizeof(pix), pin_policy,
           sizeof(pin_policy));
    buffer_len = 7 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
    send_response(rapdu, LE);
  } else if (DATA[1] == 3) {
    if (LC != 5 || DATA[2] != 0x5F || DATA[3] != 0xC1)
      EXCEPT(SW_FILE_NOT_FOUND);
    // We only process certificate data objects
    const char *key_path = get_key_path_by_tag(DATA[4]);
    if (key_path == NULL)
      EXCEPT(SW_FILE_NOT_FOUND);
    buffer[0] = 0x5C;
    buffer[1] = 0x82;
    int len = key_read_cert(key_path, buffer + 4);
    if (len < 0)
      return -1;
    if (len == 0)
      EXCEPT(SW_FILE_NOT_FOUND);
    buffer[2] = HI(len);
    buffer[3] = LO(len);
    buffer_len = len + 4;
    send_response(rapdu, LE);
  } else
    EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

int piv_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 && P1 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (P1 == 0xFF) {
    if (LC != 0)
      EXCEPT(SW_WRONG_LENGTH);
    pin.is_validated = 0;
    return 0;
  }
  if (LC == 0) {
    if (pin.is_validated)
      return 0;
    EXCEPT(0x63C0 + pin_get_retries(&pin));
  }
  if (LC != 8)
    EXCEPT(SW_WRONG_LENGTH);
  int err = pin_verify(&pin, DATA, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_AUTH_FAIL)
    EXCEPT(0x63C0 + err);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  return 0;
}

int piv_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16)
    EXCEPT(SW_WRONG_LENGTH);
  int err = pin_verify(&puk, DATA, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_AUTH_FAIL)
    EXCEPT(0x63C0 + err);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  err = pin_update(&pin, DATA + 8, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

int piv_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  pin_t *p;
  if (P2 == 0x80)
    p = &pin;
  else if (P2 == 0x81)
    p = &puk;
  else
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16)
    EXCEPT(SW_WRONG_LENGTH);
  int err = pin_verify(p, DATA, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_AUTH_FAIL)
    EXCEPT(0x63C0 + err);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  err = pin_update(p, DATA + 8, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

int piv_general_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  const char *key_path;
  switch (P2) {
  case 0x9A:
    key_path = KEY_PIV_AUTH_PATH;
    break;
  case 0x9B:
    key_path = KEY_CARD_ADMIN_PATH;
    break;
  case 0x9C:
    key_path = KEY_SIG_PATH;
    break;
  case 0x9D:
    key_path = KEY_MANAGEMENT_PATH;
    break;
  case 0x9E:
    key_path = KEY_CARD_AUTH_PATH;
    break;
  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  return 0;
}

int piv_put_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x3F || P2 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (buffer[0] != 0x5C)
    EXCEPT(SW_WRONG_DATA);
  if (buffer[1] != 3 || buffer[2] != 0x5F || buffer[3] != 0xC1)
    EXCEPT(SW_FILE_NOT_FOUND);
  // We only process certificate data objects
  const char *key_path = get_key_path_by_tag(buffer[4]);
  if (key_path == NULL)
    EXCEPT(SW_FILE_NOT_FOUND);
  if (write_file(key_path, buffer + 5, buffer_len - 5) < 0)
    return -1;
  return 0;
}

int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  uint8_t is_chaining = CLA & 0x10u;
restart:
  if (state == STATE_NORMAL) {
    buffer_len = 0;
    buffer_pos = 0;
    if (is_chaining) {
      state_ins = INS;
      state_p1 = P1;
      state_p2 = P2;
      state = STATE_CHAINING;
    } else {
      memcpy(buffer, DATA, LC);
      buffer_len = LC;
    }
  }
  if (state == STATE_CHAINING) {
    if (state_ins != INS || state_p1 != P1 || state_p2 != P2) {
      state = STATE_NORMAL;
      goto restart;
    }
    if (buffer_len + LC > buffer_cap)
      EXCEPT(SW_WRONG_DATA);
    memcpy(buffer + buffer_len, DATA, LC);
    buffer_len += LC;
    if (is_chaining)
      return 0;
    state = STATE_NORMAL;
  }
  if (state == STATE_LONG_RESPONSE && INS != PIV_GET_RESPONSE) {
    state = STATE_NORMAL;
    goto restart;
  }
  int ret = 0;
  switch (INS) {
  case PIV_GET_RESPONSE:
    if (state != STATE_LONG_RESPONSE)
      EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    send_response(rapdu, LE);
    break;
  case PIV_INS_SELECT:
    ret = piv_select(capdu, rapdu);
    break;
  case PIV_INS_GET_DATA:
    ret = piv_get_data(capdu, rapdu);
    break;
  case PIV_INS_VERIFY:
    ret = piv_verify(capdu, rapdu);
    break;
  case PIV_INS_CHANGE_REFERENCE_DATA:
    ret = piv_change_reference_data(capdu, rapdu);
    break;
  case PIV_INS_RESET_RETRY_COUNTER:
    ret = piv_reset_retry_counter(capdu, rapdu);
    break;
  case PIV_GENERAL_AUTHENTICATE:
    ret = piv_general_authenticate(capdu, rapdu);
    break;
  case PIV_INS_PUT_DATA:
    ret = piv_put_data(capdu, rapdu);
    break;
  case PIV_GENERATE_ASYMMETRIC_KEY_PAIR:
    ret = piv_generate_asymmetric_key_pair(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}

int piv_config(uint8_t *buf, uint16_t buffer_size) {
  if (buffer_size < MAX_BUFFER_SIZE)
    return -1;
  buffer = buf;
  buffer_cap = buffer_size;
  state = STATE_NORMAL;
  return 0;
}
