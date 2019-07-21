#include "openpgp.h"
#include "key.h"
#include <fs.h>
#include <string.h>

#define DATA_PATH "pgp-data"
#define KEY_SIG_PATH "pgp-sig"
#define KEY_DEC_PATH "pgp-dec"
#define KEY_AUT_PATH "pgp-aut"

#define MAX_CHALLENGE_LENGTH 16
#define MAX_LOGIN_LENGTH 254
#define MAX_URL_LENGTH 254
#define MAX_NAME_LENGTH 39
#define MAX_LANG_LENGTH 8
#define MAX_SEX_LENGTH 1
#define MAX_PIN_LENGTH 64
#define MAX_CERT_LENGTH 0x4C0
#define ALGO_ATTRIBUTES_LENGTH 6
#define DIGITAL_SIG_COUNTER_LENGTH 3

#define ATTR_CA1_FP 0xFF
#define ATTR_CA2_FP 0xFE
#define ATTR_CA3_FP 0xFD

static const uint8_t default_lang[] = {0x65, 0x6E}; // English
static const uint8_t default_sex = 0x39;
static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static const uint8_t historical_bytes[] = {0x00, 0x73, 0x00, 0x00,
                                           0x80, 0x05, 0x90, 0x00}; // TODO
static const uint8_t extended_capabilites[] = {
    0x00, // Support nothing currently
    0x00, // SM algorithm
    0x00, MAX_CHALLENGE_LENGTH,
    0x04, 0xC0, // Maximum length of Cardholder Certificate
    0x08, 0x00, // Maximum length of command data
    0x08, 0x00, // Maximum length of response data
};
static const uint8_t pw_status[] = {
    0x00, // PW1 only valid for one command
    MAX_PIN_LENGTH, MAX_PIN_LENGTH, MAX_PIN_LENGTH, 0x00, 0x00, 0x00};
static uint8_t pw1_mode;
pin_t pw1 = {.min_length = 6,
             .max_length = MAX_PIN_LENGTH,
             .is_validated = 0,
             .path = "pgp-pw1"};
pin_t pw3 = {.min_length = 8,
             .max_length = MAX_PIN_LENGTH,
             .is_validated = 0,
             .path = "pgp-pw3"};
pin_t rc = {.min_length = 0,
            .max_length = MAX_PIN_LENGTH,
            .is_validated = 0,
            .path = "pgp-rc"};

#define EXCEPT(sw_code)                                                        \
  do {                                                                         \
    SW = sw_code;                                                              \
    return 0;                                                                  \
  } while (0)

#define PW1_MODE81_ON() pw1_mode |= 1u
#define PW1_MODE81_OFF() pw1_mode &= 0XFEu
#define PW1_MODE82_ON() pw1_mode |= 2u
#define PW1_MODE82_OFF() pw1_mode &= 0XFDu
#define PW_RETRY_COUNTER_DEFAULT 3

#define LO(x) ((uint8_t)((x)&0xFFu))
#define HI(x) ((uint8_t)(((x) >> 8u) & 0xFFu))

#define ASSERT_ADMIN()                                                         \
  do {                                                                         \
    if (pw3.is_validated == 0) {                                               \
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);                                \
    }                                                                          \
  } while (0)

int openpgp_initialize() {
  // PIN data
  if (pin_create(&pw1, "123456", 6, PW_RETRY_COUNTER_DEFAULT) < 0)
    return -1;
  if (pin_create(&pw3, "12345678", 8, PW_RETRY_COUNTER_DEFAULT) < 0)
    return -1;
  if (pin_create(&rc, NULL, 0, PW_RETRY_COUNTER_DEFAULT) < 0)
    return -1;

  // Cardholder Data
  if (write_file(DATA_PATH, NULL, 0) < 0)
    return -1;
  if (write_attr(DATA_PATH, TAG_LOGIN, NULL, 0))
    return -1;
  if (write_attr(DATA_PATH, LO(TAG_URL), NULL, 0))
    return -1;
  if (write_attr(DATA_PATH, TAG_NAME, NULL, 0))
    return -1;
  if (write_attr(DATA_PATH, LO(TAG_LANG), default_lang, sizeof(default_lang)))
    return -1;
  if (write_attr(DATA_PATH, LO(TAG_SEX), &default_sex, sizeof(default_sex)))
    return -1;

  // Key data
  uint8_t buf[20];
  memset(buf, 0, sizeof(buf));
  if (write_file(KEY_SIG_PATH, NULL, 0) < 0)
    return -1;
  if (openpgp_key_set_fingerprint(KEY_SIG_PATH, buf) < 0)
    return -1;
  if (openpgp_key_set_datetime(KEY_SIG_PATH, buf) < 0)
    return -1;
  if (write_file(KEY_DEC_PATH, NULL, 0) < 0)
    return -1;
  if (openpgp_key_set_fingerprint(KEY_DEC_PATH, buf) < 0)
    return -1;
  if (openpgp_key_set_datetime(KEY_SIG_PATH, buf) < 0)
    return -1;
  if (write_file(KEY_AUT_PATH, NULL, 0) < 0)
    return -1;
  if (openpgp_key_set_fingerprint(KEY_AUT_PATH, buf) < 0)
    return -1;
  if (openpgp_key_set_datetime(KEY_SIG_PATH, buf) < 0)
    return -1;
  if (write_attr(DATA_PATH, ATTR_CA1_FP, buf, FINGERPRINT_LENGTH) < 0)
    return -1;
  if (write_attr(DATA_PATH, ATTR_CA2_FP, buf, FINGERPRINT_LENGTH) < 0)
    return -1;
  if (write_attr(DATA_PATH, ATTR_CA3_FP, buf, FINGERPRINT_LENGTH) < 0)
    return -1;

  // Digital Sig Counter
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, buf,
                 DIGITAL_SIG_COUNTER_LENGTH) < 0)
    return -1;

  // Cert
  if (write_attr(DATA_PATH, LO(TAG_CARDHOLDER_CERTIFICATE), buf, 0) < 0)
    return -1;

  return 0;
}

int openpgp_select(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;
  (void)rapdu;

  pw1_mode = 0;
  pw1.is_validated = 0;
  pw3.is_validated = 0;

  return 0;
}

int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0)
    EXCEPT(SW_WRONG_LENGTH);

  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  uint8_t off = 0;
  int len, retries;

  switch (tag) {
  case TAG_AID:
    memcpy(RDATA, aid, sizeof(aid));
    LL = sizeof(aid);
    break;

  case TAG_LOGIN:
    len = read_attr(DATA_PATH, TAG_LOGIN, RDATA, MAX_LOGIN_LENGTH);
    if (len < 0)
      return -1;
    LL = len;
    break;

  case TAG_URL:
    len = read_attr(DATA_PATH, LO(TAG_URL), RDATA, MAX_URL_LENGTH);
    if (len < 0)
      return -1;
    LL = len;
    break;

  case TAG_HISTORICAL_BYTES:
    memcpy(RDATA, historical_bytes, sizeof(historical_bytes));
    LL = sizeof(historical_bytes);
    break;

  case TAG_CARDHOLDER_RELATED_DATA:
    RDATA[off++] = TAG_NAME;
    len = read_attr(DATA_PATH, TAG_NAME, RDATA + off + 1, MAX_NAME_LENGTH);
    if (len < 0)
      return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = HI(TAG_LANG);
    RDATA[off++] = LO(TAG_LANG);
    len = read_attr(DATA_PATH, LO(TAG_LANG), RDATA + off + 1, MAX_LANG_LENGTH);
    if (len < 0)
      return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = HI(TAG_SEX);
    RDATA[off++] = LO(TAG_SEX);
    len = read_attr(DATA_PATH, LO(TAG_SEX), RDATA + off + 1, MAX_SEX_LENGTH);
    if (len < 0)
      return -1;
    RDATA[off++] = len;
    off += len;
    LL = off;
    break;

  case TAG_APPLICATION_RELATED_DATA:
    RDATA[off++] = TAG_AID;
    RDATA[off++] = sizeof(aid);
    memcpy(RDATA + off, aid, sizeof(aid));
    off += sizeof(aid);

    RDATA[off++] = HI(TAG_HISTORICAL_BYTES);
    RDATA[off++] = LO(TAG_HISTORICAL_BYTES);
    RDATA[off++] = sizeof(historical_bytes);
    memcpy(RDATA + off, historical_bytes, sizeof(historical_bytes));
    off += sizeof(historical_bytes);

    RDATA[off++] = TAG_DISCRETIONARY_DATA_OBJECTS;
    uint8_t length_pos = off + 1;
    RDATA[off++] = 0x81;
    RDATA[off++] = 0; // for length

    RDATA[off++] = TAG_EXTENDED_CAPABILITIES;
    RDATA[off++] = sizeof(extended_capabilites);
    memcpy(RDATA + off, extended_capabilites, sizeof(extended_capabilites));
    off += sizeof(extended_capabilites);

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_SIG;
    RDATA[off++] = ALGO_ATTRIBUTES_LENGTH;
    openpgp_key_get_attributes(RDATA + off);
    off += ALGO_ATTRIBUTES_LENGTH;

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_DEC;
    RDATA[off++] = ALGO_ATTRIBUTES_LENGTH;
    openpgp_key_get_attributes(RDATA + off);
    off += ALGO_ATTRIBUTES_LENGTH;

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_AUT;
    RDATA[off++] = ALGO_ATTRIBUTES_LENGTH;
    openpgp_key_get_attributes(RDATA + off);
    off += ALGO_ATTRIBUTES_LENGTH;

    RDATA[off++] = TAG_PW_STATUS;
    RDATA[off++] = sizeof(pw_status);
    memcpy(RDATA + off, pw_status, sizeof(pw_status));
    retries = pin_get_retries(&pw1);
    if (retries < 0)
      return -1;
    RDATA[off + 4] = retries;
    retries = pin_get_retries(&rc);
    if (retries < 0)
      return -1;
    RDATA[off + 5] = retries;
    retries = pin_get_retries(&pw3);
    if (retries < 0)
      return -1;
    RDATA[off + 6] = retries;
    off += sizeof(pw_status);

    RDATA[off++] = TAG_KEY_FINGERPRINTS;
    RDATA[off++] = FINGERPRINT_LENGTH * 3;
    len = openpgp_key_get_fingerprint(KEY_SIG_PATH, RDATA + off);
    if (len < 0)
      return -1;
    off += len;
    len = openpgp_key_get_fingerprint(KEY_DEC_PATH, RDATA + off);
    if (len < 0)
      return -1;
    off += len;
    len = openpgp_key_get_fingerprint(KEY_AUT_PATH, RDATA + off);
    if (len < 0)
      return -1;
    off += len;

    RDATA[off++] = TAG_CA_FINGERPRINTS;
    RDATA[off++] = FINGERPRINT_LENGTH * 3;
    len = read_attr(DATA_PATH, ATTR_CA1_FP, RDATA + off, FINGERPRINT_LENGTH);
    if (len < 0)
      return -1;
    off += len;
    len = read_attr(DATA_PATH, ATTR_CA2_FP, RDATA + off, FINGERPRINT_LENGTH);
    if (len < 0)
      return -1;
    off += len;
    len = read_attr(DATA_PATH, ATTR_CA3_FP, RDATA + off, FINGERPRINT_LENGTH);
    if (len < 0)
      return -1;
    off += len;

    RDATA[off++] = TAG_KEY_GENERATION_DATES;
    RDATA[off++] = DATETIME_LENGTH * 3;
    len = openpgp_key_get_datetime(KEY_SIG_PATH, RDATA + off);
    if (len < 0)
      return -1;
    off += len;
    len = openpgp_key_get_datetime(KEY_DEC_PATH, RDATA + off);
    if (len < 0)
      return -1;
    off += len;
    len = openpgp_key_get_datetime(KEY_AUT_PATH, RDATA + off);
    if (len < 0)
      return -1;
    off += len;

    LL = off;
    RDATA[length_pos] = off - length_pos - 1;
    break;

  case TAG_SECURITY_SUPPORT_TEMPLATE:
    RDATA[off++] = TAG_DIGITAL_SIG_COUNTER;
    RDATA[off++] = DIGITAL_SIG_COUNTER_LENGTH;
    len = read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, RDATA + off,
                    DIGITAL_SIG_COUNTER_LENGTH);
    if (len < 0)
      return -1;
    off += len;
    LL = off;
    break;

  case TAG_CARDHOLDER_CERTIFICATE:
    len = read_attr(DATA_PATH, LO(TAG_CARDHOLDER_CERTIFICATE), RDATA,
                    MAX_CERT_LENGTH);
    if (len < 0)
      return -1;
    LL = len;
    break;

  case TAG_PW_STATUS:
    memcpy(RDATA + off, pw_status, sizeof(pw_status));
    retries = pin_get_retries(&pw1);
    if (retries < 0)
      return -1;
    RDATA[4] = retries;
    retries = pin_get_retries(&rc);
    if (retries < 0)
      return -1;
    RDATA[5] = retries;
    retries = pin_get_retries(&pw3);
    if (retries < 0)
      return -1;
    RDATA[6] = retries;
    LL = sizeof(pw_status);
    break;

  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  return 0;
}

int openpgp_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  pin_t *pw;
  if (P2 == 0x81) {
    pw = &pw1;
    PW1_MODE81_OFF();
  } else if (P2 == 0x82) {
    pw = &pw1;
    PW1_MODE82_OFF();
  } else if (P2 == 0x83)
    pw = &pw3;
  else
    EXCEPT(SW_WRONG_P1P2);
  int err = pin_verify(pw, DATA, LC);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  if (err == PIN_AUTH_FAIL)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (P2 == 0x81)
    PW1_MODE81_ON();
  else if (P2 == 0x82)
    PW1_MODE82_ON();
  return 0;
}

int openpgp_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  pin_t *pw;
  if (P2 == 0x81) {
    pw = &pw1;
    pw1_mode = 0;
  } else if (P2 == 0x83)
    pw = &pw3;
  else
    EXCEPT(SW_WRONG_P1P2);
  int pw_length = pin_get_size(pw);
  int err = pin_verify(pw, DATA, pw_length);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_AUTH_FAIL)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  err = pin_update(pw, DATA + pw_length, LC - pw_length);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

int openpgp_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if ((P1 != 0x00 && P1 != 0x02) || P2 != 0x81)
    EXCEPT(SW_WRONG_P1P2);
  int offset, err;
  if (P1 == 0x00) {
    offset = pin_get_size(&rc);
    if (offset == 0)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    err = pin_verify(&rc, DATA, offset);
    if (err == PIN_IO_FAIL)
      return -1;
    if (err == PIN_AUTH_FAIL)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (err == 0)
      EXCEPT(SW_AUTHENTICATION_BLOCKED);
  } else {
    ASSERT_ADMIN();
    offset = 0;
  }
  err = pin_update(&pw1, DATA + offset, LC - offset);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

int openpgp_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_compute_digital_signature(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_internal_authentication(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_terminate_df(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_activate_file(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  int ret;
  switch (INS) {
  case OPENPGP_INS_SELECT:
    ret = openpgp_select(capdu, rapdu);
    break;
  case OPENPGP_INS_GET_DATA:
    ret = openpgp_get_data(capdu, rapdu);
    break;
  case OPENPGP_INS_VERIFY:
    ret = openpgp_verify(capdu, rapdu);
    break;
  case OPENPGP_INS_CHANGE_REFERENCE_DATA:
    ret = openpgp_change_reference_data(capdu, rapdu);
    break;
  case OPENPGP_INS_RESET_RETRY_COUNTER:
    ret = openpgp_reset_retry_counter(capdu, rapdu);
    break;
    // TODO: DADB
  case 0x47:
    ret = openpgp_generate_asymmetric_key_pair(capdu, rapdu);
    break;
  case 0x2A:
    if (P1 == 0x9E && P2 == 0x9A) {
      ret = openpgp_compute_digital_signature(capdu, rapdu);
      break;
    }
    if (P1 == 0x80 && P2 == 0x86) {
      ret = openpgp_decipher(capdu, rapdu);
      break;
    }
    EXCEPT(SW_WRONG_P1P2);
  case 0x88:
    ret = openpgp_internal_authentication(capdu, rapdu);
    break;
  case 0xC0:
    ret = 0; // TODO
    break;
  case 0xE6:
    ret = openpgp_terminate_df(capdu, rapdu);
    break;
  case 0x44:
    ret = openpgp_activate_file(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
