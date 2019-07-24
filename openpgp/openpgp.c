#include "openpgp.h"
#include "key.h"
#include <common.h>
#include <rsa.h>

#define DATA_PATH "pgp-data"
#define CERT_PATH "pgp-cert"
#define KEY_SIG_PATH "pgp-sig"
#define KEY_DEC_PATH "pgp-dec"
#define KEY_AUT_PATH "pgp-aut"

#define RSA_N_BIT 2048u
#define E_LENGTH 4
#define N_LENGTH (RSA_N_BIT / 8)
#define PQ_LENGTH (RSA_N_BIT / 16)
#define MAX_CHALLENGE_LENGTH 16
#define MAX_LOGIN_LENGTH 254
#define MAX_URL_LENGTH 254
#define MAX_NAME_LENGTH 39
#define MAX_LANG_LENGTH 8
#define MAX_SEX_LENGTH 1
#define MAX_PIN_LENGTH 64
#define MAX_CERT_LENGTH 0x4C0u
#define ALGO_ATTRIBUTES_LENGTH 6
#define DIGITAL_SIG_COUNTER_LENGTH 3

#define ATTR_CA1_FP 0xFF
#define ATTR_CA2_FP 0xFE
#define ATTR_CA3_FP 0xFD

static const uint8_t default_lang[] = {0x65, 0x6E}; // English
static const uint8_t default_sex = 0x39;
static const uint8_t default_pw1_status = 0x00; // verify every time
static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, // aid
                              0x02, 0x01,                         // version
                              0xFF, 0xFE,             // manufacturer
                              0x00, 0x00, 0x00, 0x00, // serial number
                              0x00, 0x00};
static const uint8_t historical_bytes[] = {0x00, 0x73, 0x00, 0x00,
                                           0x40, 0x05, 0x90, 0x00};
static const uint8_t extended_capabilities[] = {
    0x30, // Support key import and pw1 status change
    0x00, // SM algorithm
    0x00, MAX_CHALLENGE_LENGTH, HI(MAX_CERT_LENGTH), LO(MAX_CERT_LENGTH), 0x08,
    0x00, // Maximum length of command data
    0x08,
    0x00, // Maximum length of response data
};
static const uint8_t pw_status[] = {
    0x00, MAX_PIN_LENGTH, MAX_PIN_LENGTH, MAX_PIN_LENGTH, 0x00, 0x00, 0x00};
static uint8_t pw1_mode;
pin_t pw1 = {.min_length = 6,
             .max_length = MAX_PIN_LENGTH,
             .is_validated = 0,
             .path = "pgp-pw1"};
pin_t pw3 = {.min_length = 8,
             .max_length = MAX_PIN_LENGTH,
             .is_validated = 0,
             .path = "pgp-pw3"};
pin_t rc = {.min_length = 8,
            .max_length = MAX_PIN_LENGTH,
            .is_validated = 0,
            .path = "pgp-rc"};

#define PW1_MODE81_ON() pw1_mode |= 1u
#define PW1_MODE81_OFF() pw1_mode &= 0XFEu
#define PW1_MODE81() (pw1_mode & 1u)
#define PW1_MODE82_ON() pw1_mode |= 2u
#define PW1_MODE82_OFF() pw1_mode &= 0XFDu
#define PW1_MODE82() (pw1_mode & 2u)
#define PW_RETRY_COUNTER_DEFAULT 3

#define ASSERT_ADMIN()                                                         \
  do {                                                                         \
    if (pw3.is_validated == 0) {                                               \
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);                                \
    }                                                                          \
  } while (0)

static const char *get_key_path(uint8_t tag) {
  if (tag == 0xB6)
    return KEY_SIG_PATH;
  else if (tag == 0xB8)
    return KEY_DEC_PATH;
  else if (tag == 0xA4)
    return KEY_AUT_PATH;
  else
    return NULL;
}

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
  if (write_attr(DATA_PATH, TAG_PW_STATUS, &default_pw1_status,
                 sizeof(default_pw1_status)))
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
  if (openpgp_key_set_datetime(KEY_DEC_PATH, buf) < 0)
    return -1;
  if (write_file(KEY_AUT_PATH, NULL, 0) < 0)
    return -1;
  if (openpgp_key_set_fingerprint(KEY_AUT_PATH, buf) < 0)
    return -1;
  if (openpgp_key_set_datetime(KEY_AUT_PATH, buf) < 0)
    return -1;
  if (write_attr(DATA_PATH, ATTR_CA1_FP, buf, KEY_FINGERPRINT_LENGTH) < 0)
    return -1;
  if (write_attr(DATA_PATH, ATTR_CA2_FP, buf, KEY_FINGERPRINT_LENGTH) < 0)
    return -1;
  if (write_attr(DATA_PATH, ATTR_CA3_FP, buf, KEY_FINGERPRINT_LENGTH) < 0)
    return -1;

  // Digital Sig Counter
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, buf,
                 DIGITAL_SIG_COUNTER_LENGTH) < 0)
    return -1;

  // Cert
  if (write_file(CERT_PATH, NULL, 0) < 0)
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
    RDATA[off++] = TAG_CARDHOLDER_RELATED_DATA;
    ++off; // for length
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
    RDATA[1] = off - 2;
    LL = off;
    break;

  case TAG_APPLICATION_RELATED_DATA:
    RDATA[off++] = TAG_APPLICATION_RELATED_DATA;
    RDATA[off++] = 0x82; // for length
    off += 2;
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
    RDATA[off++] = sizeof(extended_capabilities);
    memcpy(RDATA + off, extended_capabilities, sizeof(extended_capabilities));
    off += sizeof(extended_capabilities);

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
    if (read_attr(DATA_PATH, TAG_PW_STATUS, RDATA + off, 1) < 0)
      return -1;
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
    RDATA[off++] = KEY_FINGERPRINT_LENGTH * 3;
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
    RDATA[off++] = KEY_FINGERPRINT_LENGTH * 3;
    len =
        read_attr(DATA_PATH, ATTR_CA1_FP, RDATA + off, KEY_FINGERPRINT_LENGTH);
    if (len < 0)
      return -1;
    off += len;
    len =
        read_attr(DATA_PATH, ATTR_CA2_FP, RDATA + off, KEY_FINGERPRINT_LENGTH);
    if (len < 0)
      return -1;
    off += len;
    len =
        read_attr(DATA_PATH, ATTR_CA3_FP, RDATA + off, KEY_FINGERPRINT_LENGTH);
    if (len < 0)
      return -1;
    off += len;

    RDATA[off++] = TAG_KEY_GENERATION_DATES;
    RDATA[off++] = KEY_DATETIME_LENGTH * 3;
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

    RDATA[2] = HI((uint16_t)(off - 3));
    RDATA[3] = LO((uint16_t)(off - 3));
    RDATA[length_pos] = off - length_pos - 1;
    LL = off;
    break;

  case TAG_SECURITY_SUPPORT_TEMPLATE:
    RDATA[off++] = TAG_SECURITY_SUPPORT_TEMPLATE;
    RDATA[off++] = DIGITAL_SIG_COUNTER_LENGTH + 2;
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
    len = read_file(CERT_PATH, RDATA, MAX_CERT_LENGTH);
    if (len < 0)
      return -1;
    LL = len;
    break;

  case TAG_PW_STATUS:
    memcpy(RDATA, pw_status, sizeof(pw_status));
    if (read_attr(DATA_PATH, TAG_PW_STATUS, RDATA, 1) < 0)
      return -1;
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

int openpgp_send_public_key(const rsa_key_t *key, RAPDU *rapdu) {
  uint16_t offset = 0;
  RDATA[offset++] = 0x7F;
  RDATA[offset++] = 0x49;
  RDATA[offset++] = 0x82; // use two bytes to represent length
  uint8_t offset_for_length = offset;
  offset += 2;
  RDATA[offset++] = 0x81; // modulus
  RDATA[offset++] = 0x82;
  RDATA[offset++] = HI(N_LENGTH);
  RDATA[offset++] = LO(N_LENGTH);
  memcpy(RDATA + offset, key->n, N_LENGTH);
  offset += N_LENGTH;
  RDATA[offset++] = 0x82; // exponent
  RDATA[offset++] = E_LENGTH;
  memcpy(RDATA + offset, key->e, E_LENGTH);
  offset += E_LENGTH;
  LL = offset;
  offset = offset - offset_for_length - 2;
  RDATA[offset_for_length] = HI(offset);
  RDATA[offset_for_length + 1] = LO(offset);
  return 0;
}

int openpgp_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  if (P2 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  if (LC != 0x02)
    EXCEPT(SW_WRONG_LENGTH);
  const char *key_path = get_key_path(DATA[0]);
  if (key_path == NULL)
    EXCEPT(SW_WRONG_DATA);
  rsa_key_t key;
  if (P1 == 0x80) {
    ASSERT_ADMIN();
    if (rsa_generate_key(&key, RSA_N_BIT) < 0)
      return -1;
    if (openpgp_key_set_rsa_key(key_path, &key) < 0)
      return -1;
  } else if (P1 == 0x81) {
    if (get_file_size(key_path) == 0)
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    if (openpgp_key_get_rsa_key(key_path, &key) < 0)
      return -1;
  } else
    EXCEPT(SW_WRONG_P1P2);
  return openpgp_send_public_key(&key, rapdu);
}

int openpgp_compute_digital_signature(const CAPDU *capdu, RAPDU *rapdu) {
  if (PW1_MODE81() == 0)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  uint8_t pw1_status;
  if (read_attr(DATA_PATH, TAG_PW_STATUS, &pw1_status, 1) < 0)
    return -1;
  if (pw1_status == 0x00)
    PW1_MODE81_OFF();

  if (get_file_size(KEY_SIG_PATH) == 0)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  rsa_key_t sig_key;
  if (openpgp_key_get_rsa_key(KEY_SIG_PATH, &sig_key) < 0)
    return -1;
  if (rsa_sign_pkcs_v15(&sig_key, DATA, LC, RDATA) < 0)
    return -1;
  uint8_t ctr[3];
  if (read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr,
                DIGITAL_SIG_COUNTER_LENGTH) < 0)
    return -1;
  for (int i = 3; i > 0; --i)
    if (++ctr[i - 1] != 0)
      break;
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr,
                 DIGITAL_SIG_COUNTER_LENGTH) < 0)
    return -1;
  LL = N_LENGTH;
  return 0;
}

int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) {
  if (PW1_MODE82() == 0)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (get_file_size(KEY_DEC_PATH) == 0)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  rsa_key_t dec_key;
  if (openpgp_key_get_rsa_key(KEY_SIG_PATH, &dec_key) < 0)
    return -1;
  size_t olen;
  if (rsa_decrypt_pkcs_v15(&dec_key, DATA, &olen, RDATA) < 0)
    return -1;
  LL = olen;
  return 0;
}

int openpgp_put_data(const CAPDU *capdu, RAPDU *rapdu) {
  ASSERT_ADMIN();
  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  switch (tag) {
  case TAG_NAME:
    if (LC > MAX_NAME_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, TAG_NAME, DATA, LC) < 0)
      return -1;
    break;

  case TAG_LOGIN:
    if (LC > MAX_LOGIN_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, TAG_LOGIN, DATA, LC) < 0)
      return -1;
    break;

  case TAG_LANG:
    if (LC > MAX_LANG_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, LO(TAG_LANG), DATA, LC) < 0)
      return -1;
    break;

  case TAG_SEX:
    if (LC > MAX_SEX_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, LO(TAG_SEX), DATA, LC) < 0)
      return -1;
    break;

  case TAG_URL:
    if (LC > MAX_URL_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, LO(TAG_URL), DATA, LC) < 0)
      return -1;
    break;

  case TAG_CARDHOLDER_CERTIFICATE:
    if (LC > MAX_CERT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_file(CERT_PATH, DATA, LC) < 0)
      return -1;
    break;

  case TAG_PW_STATUS:
    if (LC != 1)
      EXCEPT(SW_WRONG_LENGTH);
    if (DATA[0] != 0x00 && DATA[0] != 0x01)
      EXCEPT(SW_WRONG_DATA);
    if (write_attr(DATA_PATH, TAG_PW_STATUS, DATA, LC) < 0)
      return -1;
    break;

  case TAG_KEY_SIG_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_fingerprint(KEY_SIG_PATH, DATA) < 0)
      return -1;
    break;

  case TAG_KEY_DEC_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_fingerprint(KEY_DEC_PATH, DATA) < 0)
      return -1;
    break;

  case TAG_KEY_AUT_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_fingerprint(KEY_AUT_PATH, DATA) < 0)
      return -1;
    break;

  case TAG_KEY_CA1_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, ATTR_CA1_FP, DATA, KEY_FINGERPRINT_LENGTH) < 0)
      return -1;
    break;

  case TAG_KEY_CA2_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, ATTR_CA2_FP, DATA, KEY_FINGERPRINT_LENGTH) < 0)
      return -1;
    break;

  case TAG_KEY_CA3_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, ATTR_CA3_FP, DATA, KEY_FINGERPRINT_LENGTH) < 0)
      return -1;
    break;

  case TAG_KEY_SIG_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_datetime(KEY_SIG_PATH, DATA) < 0)
      return -1;
    break;

  case TAG_KEY_DEC_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_datetime(KEY_DEC_PATH, DATA) < 0)
      return -1;
    break;

  case TAG_KEY_AUT_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH)
      EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_datetime(KEY_AUT_PATH, DATA) < 0)
      return -1;
    break;

  case TAG_RESETTING_CODE:
    if ((LC > 0 && LC < rc.min_length) || LC > rc.max_length)
      EXCEPT(SW_WRONG_LENGTH);
    if (LC == 0) {
      if (pin_clear(&rc) < 0)
        return -1;
      return 0;
    } else {
      int err = pin_update(&rc, DATA, LC);
      if (err == PIN_IO_FAIL)
        return -1;
      if (err == PIN_LENGTH_INVALID)
        EXCEPT(SW_WRONG_LENGTH);
      return 0;
    }

  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  return 0;
}

int openpgp_import_key(const CAPDU *capdu, RAPDU *rapdu) {
  ASSERT_ADMIN();
  if (P1 != 0x3F || P2 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);

  const uint8_t *p = DATA;
  if (*p++ != 0x4D)
    EXCEPT(SW_WRONG_DATA);
  uint16_t len = tlv_get_length(p);
  uint8_t off = tlv_length_size(len);
  if (len + off + 1 != LC)
    EXCEPT(SW_WRONG_LENGTH);
  p += off;
  const char *key_path = get_key_path(*p);
  if (key_path == NULL)
    EXCEPT(SW_WRONG_DATA);
  ++p;
  if (*p++ != 0x00)
    EXCEPT(SW_WRONG_DATA);
  if (*p++ != 0x7F || *p++ != 0x48)
    EXCEPT(SW_WRONG_DATA);
  uint16_t template_len = tlv_get_length(p);
  p += tlv_length_size(template_len);

  const uint8_t *data_tag = p + template_len;
  if (*p++ != 0x91)
    EXCEPT(SW_WRONG_DATA);
  int e_len = tlv_get_length(p);
  p += tlv_length_size(e_len);
  if (*p++ != 0x92)
    EXCEPT(SW_WRONG_DATA);
  int p_len = tlv_get_length(p);
  p += tlv_length_size(p_len);
  if (*p++ != 0x93)
    EXCEPT(SW_WRONG_DATA);
  int q_len = tlv_get_length(p);

  p = data_tag;
  if (*p++ != 0x5F || *p++ != 0x48)
    EXCEPT(SW_WRONG_DATA);
  p += tlv_length_size(tlv_get_length(p));

  rsa_key_t key;
  memset(&key, 0, sizeof(key));
  memcpy(key.e + (E_LENGTH - e_len), p, e_len);
  p += e_len;
  memcpy(key.p + (PQ_LENGTH - p_len), p, p_len);
  p += p_len;
  memcpy(key.q + (PQ_LENGTH - q_len), p, q_len);

  if (openpgp_key_set_rsa_key(key_path, &key) < 0)
    return -1;

  return 0;
}

int openpgp_internal_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  if (PW1_MODE82() == 0)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (get_file_size(KEY_AUT_PATH) == 0)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  rsa_key_t aut_key;
  if (openpgp_key_get_rsa_key(KEY_AUT_PATH, &aut_key) < 0)
    return -1;
  if (rsa_sign_pkcs_v15(&aut_key, DATA, LC, RDATA) < 0)
    return -1;
  LL = N_LENGTH;
  return 0;
}

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
  case OPENPGP_INS_PUT_DATA:
    ret = openpgp_put_data(capdu, rapdu);
    break;
  case OPENPGP_INS_IMPORT_KEY:
    ret = openpgp_import_key(capdu, rapdu);
    break;
  case OPENPGP_GENERATE_ASYMMETRIC_KEY_PAIR:
    ret = openpgp_generate_asymmetric_key_pair(capdu, rapdu);
    break;
  case OPENPGP_INS_PSO:
    if (P1 == 0x9E && P2 == 0x9A) {
      ret = openpgp_compute_digital_signature(capdu, rapdu);
      break;
    }
    if (P1 == 0x80 && P2 == 0x86) {
      ret = openpgp_decipher(capdu, rapdu);
      break;
    }
    EXCEPT(SW_WRONG_P1P2);
  case OPENPGP_INS_INTERNAL_AUTHENTICATE:
    ret = openpgp_internal_authenticate(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
