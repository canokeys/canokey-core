#include "key.h"
#include <common.h>
#include <ecc.h>
#include <memzero.h>
#include <openpgp.h>
#include <pin.h>
#include <rsa.h>

#define DATA_PATH "pgp-data"
#define SIG_KEY_PATH "pgp-sigk"
#define DEC_KEY_PATH "pgp-deck"
#define AUT_KEY_PATH "pgp-autk"
#define SIG_CERT_PATH "pgp-sigc"
#define DEC_CERT_PATH "pgp-decc"
#define AUT_CERT_PATH "pgp-autc"

#define KEY_NOT_PRESENT 0x00
#define KEY_GENERATED 0x01
#define KEY_IMPORTED 0x02

#define MAX_LOGIN_LENGTH 254
#define MAX_URL_LENGTH 254
#define MAX_NAME_LENGTH 39
#define MAX_LANG_LENGTH 8
#define MAX_SEX_LENGTH 1
#define MAX_PIN_LENGTH 64
#define MAX_CERT_LENGTH 0x480
#define MAX_DO_LENGTH 0xFF
#define MAX_KEY_LENGTH 0x200
#define MAX_KEY_TEMPLATE_LENGTH 14
#define DIGITAL_SIG_COUNTER_LENGTH 3
#define PW_STATUS_LENGTH 7

#define ATTR_CA1_FP 0xFF
#define ATTR_CA2_FP 0xFE
#define ATTR_CA3_FP 0xFD
#define ATTR_TERMINATED 0xFC

#define STATE_NORMAL 0x00
#define STATE_SELECT_DATA 0x01
#define STATE_GET_CERT_DATA 0x02

#define KEY_TYPE_RSA 0x01
#define KEY_TYPE_ECDSA 0x13
#define KEY_TYPE_ECDH 0x12

static const uint8_t rsa_attributes[] = {KEY_TYPE_RSA, 0x08, 0x00, 0x00, 0x20, 0x00};
static const uint8_t ec_attr[] = {0x00, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, // aid
                              0x03, 0x04,                         // version
                              0x80, 0x86,                         // manufacturer
                              0x00, 0x00, 0x00, 0x00,             // serial number
                              0x00, 0x00};
static const uint8_t historical_bytes[] = {0x00,
                                           0x31, // card services
                                           0xC5, // Section 6.2
                                           0x73, // card capabilities
                                           0xC0, // full/partial
                                           0x01, // data coding byte
                                           0x40, // extended apdu (Section 6.1)
                                           0x05, 0x90, 0x00};
static const uint8_t extended_length_info[] = {0x02, 0x02, HI(APDU_BUFFER_SIZE), LO(APDU_BUFFER_SIZE),
                                               0x02, 0x02, HI(APDU_BUFFER_SIZE), LO(APDU_BUFFER_SIZE)};
static const uint8_t extended_capabilities[] = {
    0x34, // Support key import, pw1 status change, and algorithm attributes changes
    0x00, // No SM algorithm
    0x00,
    0x00, // No challenge support
    HI(MAX_CERT_LENGTH),
    LO(MAX_CERT_LENGTH), // Cert length
    HI(MAX_DO_LENGTH),
    LO(MAX_DO_LENGTH), // Other DO length
    0x00,              // No PIN block 2 format
    0x00,              // No MSE
};
static uint8_t pw1_mode, current_occurrence, state;
static pin_t pw1 = {.min_length = 6, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-pw1"};
static pin_t pw3 = {.min_length = 8, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-pw3"};
static pin_t rc = {.min_length = 8, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-rc"};

#define PW1_MODE81_ON() pw1_mode |= 1u
#define PW1_MODE81_OFF() pw1_mode &= 0XFEu
#define PW1_MODE81() (pw1_mode & 1u)
#define PW1_MODE82_ON() pw1_mode |= 2u
#define PW1_MODE82_OFF() pw1_mode &= 0XFDu
#define PW1_MODE82() (pw1_mode & 2u)
#define PW_RETRY_COUNTER_DEFAULT 3

#define ASSERT_ADMIN()                                                                                                 \
  do {                                                                                                                 \
    if (pw3.is_validated == 0) {                                                                                       \
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);                                                                        \
    }                                                                                                                  \
  } while (0)

static const char *get_key_path(uint8_t tag) {
  if (tag == 0xB6)
    return SIG_KEY_PATH;
  else if (tag == 0xB8)
    return DEC_KEY_PATH;
  else if (tag == 0xA4)
    return AUT_KEY_PATH;
  else
    return NULL;
}

static int reset_sig_counter(void) {
  uint8_t buf[3] = {0};
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, buf, DIGITAL_SIG_COUNTER_LENGTH) < 0) return -1;
  return 0;
}

void openpgp_poweroff(void) {
  pw1_mode = 0;
  pw1.is_validated = 0;
  pw3.is_validated = 0;
  state = STATE_NORMAL;
}

int openpgp_install(uint8_t reset) {
  openpgp_poweroff();
  if (!reset && get_file_size(DATA_PATH) == 0) return 0;

  // PIN data
  if (pin_create(&pw1, "123456", 6, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;
  if (pin_create(&pw3, "12345678", 8, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;
  if (pin_create(&rc, NULL, 0, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;

  // Cardholder Data
  if (write_file(DATA_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_attr(DATA_PATH, TAG_LOGIN, NULL, 0) < 0) return -1;
  if (write_attr(DATA_PATH, LO(TAG_URL), NULL, 0) < 0) return -1;
  if (write_attr(DATA_PATH, TAG_NAME, NULL, 0)) return -1;
  // default lang = NULL
  if (write_attr(DATA_PATH, LO(TAG_LANG), NULL, 0) < 0) return -1;
  uint8_t default_sex = 0x39; // default sex
  if (write_attr(DATA_PATH, LO(TAG_SEX), &default_sex, 1) < 0) return -1;
  uint8_t default_pin_strategy = 0x00; // verify PIN every time
  if (write_attr(DATA_PATH, TAG_PW_STATUS, &default_pin_strategy, 1) < 0) return -1;
  uint8_t terminated = 0x00; // Terminated: no
  if (write_attr(DATA_PATH, ATTR_TERMINATED, &terminated, 1) < 0) return -1;

  // Key data
  uint8_t buf[20];
  memzero(buf, sizeof(buf));
  if (write_file(SIG_KEY_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (openpgp_key_set_fingerprint(SIG_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(SIG_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_attributes(SIG_KEY_PATH, rsa_attributes, sizeof(rsa_attributes)) < 0) return -1;
  if (openpgp_key_set_status(SIG_KEY_PATH, KEY_NOT_PRESENT) < 0) return -1;
  if (write_file(DEC_KEY_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (openpgp_key_set_fingerprint(DEC_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(DEC_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_attributes(DEC_KEY_PATH, rsa_attributes, sizeof(rsa_attributes)) < 0) return -1;
  if (openpgp_key_set_status(DEC_KEY_PATH, KEY_NOT_PRESENT) < 0) return -1;
  if (write_file(AUT_KEY_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (openpgp_key_set_fingerprint(AUT_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(AUT_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_attributes(AUT_KEY_PATH, rsa_attributes, sizeof(rsa_attributes)) < 0) return -1;
  if (openpgp_key_set_status(AUT_KEY_PATH, KEY_NOT_PRESENT) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA1_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA2_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA3_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;

  // Digital Sig Counter
  if (reset_sig_counter() < 0) return -1;

  // Certs
  if (write_file(SIG_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(DEC_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(AUT_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;

  return 0;
}

static int openpgp_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 6 || memcmp(DATA, aid, LC) != 0) EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

static int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  uint8_t off = 0;
  int len, retries, status;

  switch (tag) {
  case TAG_AID:
    memcpy(RDATA, aid, sizeof(aid));
    fill_sn(RDATA + 10);
    LL = sizeof(aid);
    break;

  case TAG_LOGIN:
    len = read_attr(DATA_PATH, TAG_LOGIN, RDATA, MAX_LOGIN_LENGTH);
    if (len < 0) return -1;
    LL = len;
    break;

  case TAG_URL:
    len = read_attr(DATA_PATH, LO(TAG_URL), RDATA, MAX_URL_LENGTH);
    if (len < 0) return -1;
    LL = len;
    break;

  case TAG_HISTORICAL_BYTES:
    memcpy(RDATA, historical_bytes, sizeof(historical_bytes));
    LL = sizeof(historical_bytes);
    break;

  case TAG_CARDHOLDER_RELATED_DATA:
    RDATA[off++] = TAG_NAME;
    len = read_attr(DATA_PATH, TAG_NAME, RDATA + off + 1, MAX_NAME_LENGTH);
    if (len < 0) return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = HI(TAG_LANG);
    RDATA[off++] = LO(TAG_LANG);
    len = read_attr(DATA_PATH, LO(TAG_LANG), RDATA + off + 1, MAX_LANG_LENGTH);
    if (len < 0) return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = HI(TAG_SEX);
    RDATA[off++] = LO(TAG_SEX);
    len = read_attr(DATA_PATH, LO(TAG_SEX), RDATA + off + 1, MAX_SEX_LENGTH);
    if (len < 0) return -1;
    RDATA[off++] = len;
    off += len;
    LL = off;
    break;

  case TAG_APPLICATION_RELATED_DATA:
    RDATA[off++] = TAG_AID;
    RDATA[off++] = sizeof(aid);
    memcpy(RDATA + off, aid, sizeof(aid));
    fill_sn(RDATA + off + 10);
    off += sizeof(aid);

    RDATA[off++] = HI(TAG_HISTORICAL_BYTES);
    RDATA[off++] = LO(TAG_HISTORICAL_BYTES);
    RDATA[off++] = sizeof(historical_bytes);
    memcpy(RDATA + off, historical_bytes, sizeof(historical_bytes));
    off += sizeof(historical_bytes);

    RDATA[off++] = HI(TAG_EXTENDED_LENGTH_INFO);
    RDATA[off++] = LO(TAG_EXTENDED_LENGTH_INFO);
    RDATA[off++] = sizeof(extended_length_info);
    memcpy(RDATA + off, extended_length_info, sizeof(extended_length_info));
    off += sizeof(extended_length_info);

    RDATA[off++] = TAG_DISCRETIONARY_DATA_OBJECTS;
    uint8_t length_pos = off + 1;
    RDATA[off++] = 0x81;
    RDATA[off++] = 0; // for length

    RDATA[off++] = TAG_EXTENDED_CAPABILITIES;
    RDATA[off++] = sizeof(extended_capabilities);
    memcpy(RDATA + off, extended_capabilities, sizeof(extended_capabilities));
    off += sizeof(extended_capabilities);

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_SIG;
    len = openpgp_key_get_attributes(SIG_KEY_PATH, RDATA + off + 1);
    if (len < 0) return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_DEC;
    len = openpgp_key_get_attributes(DEC_KEY_PATH, RDATA + off + 1);
    if (len < 0) return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_AUT;
    len = openpgp_key_get_attributes(AUT_KEY_PATH, RDATA + off + 1);
    if (len < 0) return -1;
    RDATA[off++] = len;
    off += len;

    RDATA[off++] = TAG_PW_STATUS;
    RDATA[off++] = PW_STATUS_LENGTH;
    if (read_attr(DATA_PATH, TAG_PW_STATUS, RDATA + off++, 1) < 0) return -1;
    RDATA[off++] = MAX_PIN_LENGTH;
    RDATA[off++] = MAX_PIN_LENGTH;
    RDATA[off++] = MAX_PIN_LENGTH;
    retries = pin_get_retries(&pw1);
    if (retries < 0) return -1;
    RDATA[off++] = retries;
    retries = pin_get_retries(&rc);
    if (retries < 0) return -1;
    RDATA[off++] = retries;
    retries = pin_get_retries(&pw3);
    if (retries < 0) return -1;
    RDATA[off++] = retries;

    RDATA[off++] = TAG_KEY_FINGERPRINTS;
    RDATA[off++] = KEY_FINGERPRINT_LENGTH * 3;
    len = openpgp_key_get_fingerprint(SIG_KEY_PATH, RDATA + off);
    if (len < 0) return -1;
    off += len;
    len = openpgp_key_get_fingerprint(DEC_KEY_PATH, RDATA + off);
    if (len < 0) return -1;
    off += len;
    len = openpgp_key_get_fingerprint(AUT_KEY_PATH, RDATA + off);
    if (len < 0) return -1;
    off += len;

    RDATA[off++] = TAG_CA_FINGERPRINTS;
    RDATA[off++] = KEY_FINGERPRINT_LENGTH * 3;
    len = read_attr(DATA_PATH, ATTR_CA1_FP, RDATA + off, KEY_FINGERPRINT_LENGTH);
    if (len < 0) return -1;
    off += len;
    len = read_attr(DATA_PATH, ATTR_CA2_FP, RDATA + off, KEY_FINGERPRINT_LENGTH);
    if (len < 0) return -1;
    off += len;
    len = read_attr(DATA_PATH, ATTR_CA3_FP, RDATA + off, KEY_FINGERPRINT_LENGTH);
    if (len < 0) return -1;
    off += len;

    RDATA[off++] = TAG_KEY_GENERATION_DATES;
    RDATA[off++] = KEY_DATETIME_LENGTH * 3;
    len = openpgp_key_get_datetime(SIG_KEY_PATH, RDATA + off);
    if (len < 0) return -1;
    off += len;
    len = openpgp_key_get_datetime(DEC_KEY_PATH, RDATA + off);
    if (len < 0) return -1;
    off += len;
    len = openpgp_key_get_datetime(AUT_KEY_PATH, RDATA + off);
    if (len < 0) return -1;
    off += len;

    RDATA[off++] = TAG_KEY_INFO;
    RDATA[off++] = 6;
    status = openpgp_key_get_status(SIG_KEY_PATH);
    if (status < 0) return -1;
    RDATA[off++] = 0x01;
    RDATA[off++] = status;
    status = openpgp_key_get_status(DEC_KEY_PATH);
    if (status < 0) return -1;
    RDATA[off++] = 0x02;
    RDATA[off++] = status;
    status = openpgp_key_get_status(AUT_KEY_PATH);
    if (status < 0) return -1;
    RDATA[off++] = 0x03;
    RDATA[off++] = status;

    RDATA[length_pos] = off - length_pos - 1;
    LL = off;
    break;

  case TAG_SECURITY_SUPPORT_TEMPLATE:
    RDATA[0] = TAG_DIGITAL_SIG_COUNTER;
    RDATA[1] = DIGITAL_SIG_COUNTER_LENGTH;
    len = read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, RDATA + 2, DIGITAL_SIG_COUNTER_LENGTH);
    if (len < 0) return -1;
    LL = 2 + DIGITAL_SIG_COUNTER_LENGTH;
    break;

  case TAG_CARDHOLDER_CERTIFICATE:
    if (current_occurrence == 0)
      len = read_file(SIG_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
    else if (current_occurrence == 1)
      len = read_file(DEC_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
    else if (current_occurrence == 2)
      len = read_file(AUT_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
    else
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    if (len < 0) return -1;
    LL = len;
    break;

  case TAG_EXTENDED_LENGTH_INFO:
    memcpy(RDATA, extended_length_info, sizeof(extended_length_info));
    LL = sizeof(extended_length_info);
    break;

  case TAG_PW_STATUS:
    if (read_attr(DATA_PATH, TAG_PW_STATUS, RDATA, 1) < 0) return -1;
    RDATA[1] = MAX_PIN_LENGTH;
    RDATA[2] = MAX_PIN_LENGTH;
    RDATA[3] = MAX_PIN_LENGTH;
    retries = pin_get_retries(&pw1);
    if (retries < 0) return -1;
    RDATA[4] = retries;
    retries = pin_get_retries(&rc);
    if (retries < 0) return -1;
    RDATA[5] = retries;
    retries = pin_get_retries(&pw3);
    if (retries < 0) return -1;
    RDATA[6] = retries;
    LL = PW_STATUS_LENGTH;
    break;

  case TAG_KEY_INFO:
    status = openpgp_key_get_status(SIG_KEY_PATH);
    if (status < 0) return -1;
    RDATA[0] = 0x01;
    RDATA[1] = status;
    status = openpgp_key_get_status(DEC_KEY_PATH);
    if (status < 0) return -1;
    RDATA[2] = 0x02;
    RDATA[3] = status;
    status = openpgp_key_get_status(AUT_KEY_PATH);
    if (status < 0) return -1;
    RDATA[4] = 0x03;
    RDATA[5] = status;
    LL = 6;
    break;

  default:
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }
  return 0;
}

static int openpgp_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 && P1 != 0xFF) EXCEPT(SW_WRONG_P1P2);
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
  if (P1 == 0xFF) {
    pw->is_validated = 0;
    return 0;
  }

  if (LC == 0) {
    if (pw->is_validated) return 0;
    int retries = pin_get_retries(pw);
    if (retries < 0) return -1;
    EXCEPT(SW_PIN_RETRIES + retries);
  }

  uint8_t ctr;
  int err = pin_verify(pw, DATA, LC, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (P2 == 0x81)
    PW1_MODE81_ON();
  else if (P2 == 0x82)
    PW1_MODE82_ON();
  return 0;
}

static int openpgp_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  pin_t *pw;
  if (P2 == 0x81) {
    pw = &pw1;
    pw1_mode = 0;
  } else if (P2 == 0x83)
    pw = &pw3;
  else
    EXCEPT(SW_WRONG_P1P2);
  int pw_length = pin_get_size(pw);
  uint8_t ctr;
  int err = pin_verify(pw, DATA, pw_length, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  err = pin_update(pw, DATA + pw_length, LC - pw_length);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static int openpgp_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if ((P1 != 0x00 && P1 != 0x02) || P2 != 0x81) EXCEPT(SW_WRONG_P1P2);
  int offset, err;
  if (P1 == 0x00) {
    offset = pin_get_size(&rc);
    if (offset == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    uint8_t ctr;
    err = pin_verify(&rc, DATA, offset, &ctr);
    if (err == PIN_IO_FAIL) return -1;
    if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
    if (err == PIN_AUTH_FAIL) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  } else {
    ASSERT_ADMIN();
    offset = 0;
  }
  err = pin_update(&pw1, DATA + offset, LC - offset);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static int openpgp_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0x02 && LC != 0x05) EXCEPT(SW_WRONG_LENGTH);
  const char *key_path = get_key_path(DATA[0]);
  if (key_path == NULL) EXCEPT(SW_WRONG_DATA);
  uint8_t attr[MAX_ATTR_LENGTH];
  if (openpgp_key_get_attributes(key_path, attr) < 0) return -1;
  uint8_t key[sizeof(rsa_key_t)];
  uint16_t key_len;
  if (P1 == 0x80) {
    ASSERT_ADMIN();
    if (attr[0] == KEY_TYPE_RSA) {
      key_len = sizeof(rsa_key_t);
      if (rsa_generate_key((rsa_key_t *)key) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
    } else {
      key_len = ECC_KEY_SIZE + ECC_PUB_KEY_SIZE;
      if (ecc_generate(ECC_SECP256R1, key, key + ECC_KEY_SIZE) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
    }
    if (openpgp_key_set_key(key_path, key, key_len) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    if (openpgp_key_set_status(key_path, KEY_GENERATED) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
  } else if (P1 == 0x81) {
    int status = openpgp_key_get_status(key_path);
    if (status < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    if (status == KEY_NOT_PRESENT) {
      memzero(key, sizeof(key));
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    }
    if (openpgp_key_get_key(key_path, &key, sizeof(key)) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
  } else {
    memzero(key, sizeof(key));
    EXCEPT(SW_WRONG_P1P2);
  }

  RDATA[0] = 0x7F;
  RDATA[1] = 0x49;
  if (attr[0] == KEY_TYPE_RSA) {
    RDATA[2] = 0x82;
    RDATA[3] = HI(6 + N_LENGTH + E_LENGTH);
    RDATA[4] = LO(6 + N_LENGTH + E_LENGTH);
    RDATA[5] = 0x81; // modulus
    RDATA[6] = 0x82;
    RDATA[7] = HI(N_LENGTH);
    RDATA[8] = LO(N_LENGTH);
    memcpy(RDATA + 9, ((rsa_key_t *)key)->n, N_LENGTH);
    RDATA[9 + N_LENGTH] = 0x82; // exponent
    RDATA[10 + N_LENGTH] = E_LENGTH;
    memcpy(RDATA + 11 + N_LENGTH, ((rsa_key_t *)key)->e, E_LENGTH);
    LL = 11 + N_LENGTH + E_LENGTH;
  } else {
    RDATA[2] = ECC_PUB_KEY_SIZE + 3;
    RDATA[3] = 0x86;
    RDATA[4] = ECC_PUB_KEY_SIZE + 1;
    RDATA[5] = 0x04;
    memcpy(RDATA + 6, key + ECC_KEY_SIZE, ECC_PUB_KEY_SIZE);
    LL = ECC_PUB_KEY_SIZE + 6;
  }

  memzero(key, sizeof(key));
  return reset_sig_counter();
}

static int openpgp_compute_digital_signature(const CAPDU *capdu, RAPDU *rapdu) {
  if (PW1_MODE81() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  uint8_t pw1_status;
  if (read_attr(DATA_PATH, TAG_PW_STATUS, &pw1_status, 1) < 0) return -1;
  if (pw1_status == 0x00) PW1_MODE81_OFF();

  int status = openpgp_key_get_status(SIG_KEY_PATH);
  if (status < 0) return -1;
  if (status == KEY_NOT_PRESENT) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  uint8_t attr[MAX_ATTR_LENGTH];
  if (openpgp_key_get_attributes(SIG_KEY_PATH, attr) < 0) return -1;
  if (attr[0] == KEY_TYPE_RSA) {
    rsa_key_t key;
    if (openpgp_key_get_key(SIG_KEY_PATH, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    if (rsa_sign_pkcs_v15(&key, DATA, LC, RDATA) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
    LL = N_LENGTH;
  } else if (attr[0] == KEY_TYPE_ECDSA) {
    uint8_t key[ECC_KEY_SIZE];
    if (openpgp_key_get_key(SIG_KEY_PATH, key, ECC_KEY_SIZE) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    if (ecdsa_sign(ECC_SECP256R1, key, DATA, RDATA) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    LL = ECC_KEY_SIZE * 2;
  } else
    return -1;

  uint8_t ctr[3];
  if (read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr, DIGITAL_SIG_COUNTER_LENGTH) < 0) return -1;
  for (int i = 3; i > 0; --i)
    if (++ctr[i - 1] != 0) break;
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr, DIGITAL_SIG_COUNTER_LENGTH) < 0) return -1;
  return 0;
}

static int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) {
  if (PW1_MODE82() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  int status = openpgp_key_get_status(DEC_KEY_PATH);
  if (status < 0) return -1;
  if (status == KEY_NOT_PRESENT) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  uint8_t attr[MAX_ATTR_LENGTH];
  if (openpgp_key_get_attributes(DEC_KEY_PATH, attr) < 0) return -1;
  if (attr[0] == KEY_TYPE_RSA) {
    rsa_key_t key;
    if (openpgp_key_get_key(DEC_KEY_PATH, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    size_t olen;
    if (rsa_decrypt_pkcs_v15(&key, DATA + 1, &olen, RDATA) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
    LL = olen;
  } else if (attr[0] == KEY_TYPE_ECDH) {
    if (DATA[0] != 0xA6 || DATA[1] != 70 || DATA[2] != 0x7F || DATA[3] != 0x49 || DATA[4] != 67 || DATA[5] != 0x86 ||
        DATA[6] != 65 || DATA[7] != 0x04)
      EXCEPT(SW_WRONG_DATA);
    uint8_t key[ECC_KEY_SIZE];
    if (openpgp_key_get_key(DEC_KEY_PATH, key, ECC_KEY_SIZE) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    RDATA[0] = 0x04;
    if (ecdh_decrypt(ECC_SECP256R1, key, DATA + 8, RDATA + 1) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    LL = ECC_KEY_SIZE * 2 + 1;
  } else
    return -1;

  return 0;
}

static int openpgp_put_data(const CAPDU *capdu, RAPDU *rapdu) {
  ASSERT_ADMIN();
  int err;
  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  switch (tag) {
  case TAG_NAME:
    if (LC > MAX_NAME_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, TAG_NAME, DATA, LC) < 0) return -1;
    break;

  case TAG_LOGIN:
    if (LC > MAX_LOGIN_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, TAG_LOGIN, DATA, LC) < 0) return -1;
    break;

  case TAG_LANG:
    if (LC > MAX_LANG_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, LO(TAG_LANG), DATA, LC) < 0) return -1;
    break;

  case TAG_SEX:
    if (LC > MAX_SEX_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, LO(TAG_SEX), DATA, LC) < 0) return -1;
    break;

  case TAG_URL:
    if (LC > MAX_URL_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, LO(TAG_URL), DATA, LC) < 0) return -1;
    break;

  case TAG_CARDHOLDER_CERTIFICATE:
    if (LC > MAX_CERT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (current_occurrence == 0)
      err = write_file(SIG_CERT_PATH, DATA, 0, LC, 1);
    else if (current_occurrence == 1)
      err = write_file(DEC_CERT_PATH, DATA, 0, LC, 1);
    else if (current_occurrence == 2)
      err = write_file(AUT_CERT_PATH, DATA, 0, LC, 1);
    else
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    if (err < 0) return -1;
    current_occurrence = 0;
    break;

  case TAG_ALGORITHM_ATTRIBUTES_SIG:
  case TAG_ALGORITHM_ATTRIBUTES_DEC:
  case TAG_ALGORITHM_ATTRIBUTES_AUT:
    if (LC > MAX_ATTR_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    const char *key_path;
    if (tag == TAG_ALGORITHM_ATTRIBUTES_SIG)
      key_path = SIG_KEY_PATH;
    else if (tag == TAG_ALGORITHM_ATTRIBUTES_DEC)
      key_path = DEC_KEY_PATH;
    else
      key_path = AUT_KEY_PATH;
    if (DATA[0] == KEY_TYPE_RSA) {
      if (LC != sizeof(rsa_attributes) || memcmp(DATA, rsa_attributes, sizeof(rsa_attributes)) != 0)
        EXCEPT(SW_WRONG_DATA);
      if (openpgp_key_set_attributes(key_path, rsa_attributes, LC) < 0) return -1;
    } else if (DATA[0] == KEY_TYPE_ECDSA || DATA[0] == KEY_TYPE_ECDH) {
      if (LC != sizeof(ec_attr) || memcmp(DATA + 1, ec_attr + 1, sizeof(ec_attr) - 1) != 0) EXCEPT(SW_WRONG_DATA);
      if (openpgp_key_set_attributes(key_path, DATA, LC) < 0) return -1;
    } else
      EXCEPT(SW_WRONG_DATA);
    break;

  case TAG_PW_STATUS:
    if (LC != 1) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[0] != 0x00 && DATA[0] != 0x01) EXCEPT(SW_WRONG_DATA);
    if (write_attr(DATA_PATH, TAG_PW_STATUS, DATA, LC) < 0) return -1;
    break;

  case TAG_KEY_SIG_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_fingerprint(SIG_KEY_PATH, DATA) < 0) return -1;
    break;

  case TAG_KEY_DEC_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_fingerprint(DEC_KEY_PATH, DATA) < 0) return -1;
    break;

  case TAG_KEY_AUT_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_fingerprint(AUT_KEY_PATH, DATA) < 0) return -1;
    break;

  case TAG_KEY_CA1_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, ATTR_CA1_FP, DATA, KEY_FINGERPRINT_LENGTH) < 0) return -1;
    break;

  case TAG_KEY_CA2_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, ATTR_CA2_FP, DATA, KEY_FINGERPRINT_LENGTH) < 0) return -1;
    break;

  case TAG_KEY_CA3_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_attr(DATA_PATH, ATTR_CA3_FP, DATA, KEY_FINGERPRINT_LENGTH) < 0) return -1;
    break;

  case TAG_KEY_SIG_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_datetime(SIG_KEY_PATH, DATA) < 0) return -1;
    break;

  case TAG_KEY_DEC_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_datetime(DEC_KEY_PATH, DATA) < 0) return -1;
    break;

  case TAG_KEY_AUT_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (openpgp_key_set_datetime(AUT_KEY_PATH, DATA) < 0) return -1;
    break;

  case TAG_RESETTING_CODE:
    if ((LC > 0 && LC < rc.min_length) || LC > rc.max_length) EXCEPT(SW_WRONG_LENGTH);
    if (LC == 0) {
      if (pin_clear(&rc) < 0) return -1;
      return 0;
    } else {
      err = pin_update(&rc, DATA, LC);
      if (err == PIN_IO_FAIL) return -1;
      if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
      return 0;
    }

  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  return 0;
}

static int openpgp_import_key(const CAPDU *capdu, RAPDU *rapdu) {
  ASSERT_ADMIN();
  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);

  const uint8_t *p = DATA;
  if (*p++ != 0x4D) EXCEPT(SW_WRONG_DATA);
  uint16_t len = tlv_get_length(p);
  if (len > MAX_KEY_LENGTH) EXCEPT(SW_WRONG_DATA);
  uint8_t off = tlv_length_size(len);
  if (len + off + 1 != LC) EXCEPT(SW_WRONG_LENGTH);
  p += off;
  const char *key_path = get_key_path(*p);
  if (key_path == NULL) EXCEPT(SW_WRONG_DATA);
  uint8_t attr[MAX_ATTR_LENGTH];
  if (openpgp_key_get_attributes(key_path, attr) < 0) return -1;
  ++p;
  if (*p++ != 0x00) EXCEPT(SW_WRONG_DATA);
  if (*p++ != 0x7F || *p++ != 0x48) EXCEPT(SW_WRONG_DATA);
  uint16_t template_len = tlv_get_length(p);
  if (template_len > MAX_KEY_TEMPLATE_LENGTH) EXCEPT(SW_WRONG_DATA);
  p += tlv_length_size(template_len);

  const uint8_t *data_tag = p + template_len;
  uint8_t key[sizeof(rsa_key_t)];
  uint16_t key_len;

  if (attr[0] == KEY_TYPE_RSA) {
    key_len = sizeof(rsa_key_t);
    if (*p++ != 0x91) EXCEPT(SW_WRONG_DATA);
    int e_len = tlv_get_length(p);
    if (e_len > E_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(e_len);
    if (*p++ != 0x92) EXCEPT(SW_WRONG_DATA);
    int p_len = tlv_get_length(p);
    if (p_len > PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(p_len);
    if (*p++ != 0x93) EXCEPT(SW_WRONG_DATA);
    int q_len = tlv_get_length(p);
    if (q_len > PQ_LENGTH) EXCEPT(SW_WRONG_DATA);

    p = data_tag;
    if (*p++ != 0x5F || *p++ != 0x48) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length(p); // Concatenation of key data
    if (len > MAX_KEY_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(len);

    memcpy(((rsa_key_t *)key)->e + (E_LENGTH - e_len), p, e_len);
    p += e_len;
    memcpy(((rsa_key_t *)key)->p + (PQ_LENGTH - p_len), p, p_len);
    p += p_len;
    memcpy(((rsa_key_t *)key)->q + (PQ_LENGTH - q_len), p, q_len);

    if (rsa_complete_key((rsa_key_t *)key) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
  } else {
    if (*p++ != 0x92) EXCEPT(SW_WRONG_DATA);
    key_len = tlv_get_length(p);
    if (key_len != ECC_KEY_SIZE) EXCEPT(SW_WRONG_DATA);

    p = data_tag;
    if (*p++ != 0x5F || *p++ != 0x48) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length(p); // Concatenation of key data
    if (len > MAX_KEY_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(len);
    memcpy(key, p, key_len);

    if (ecc_get_public_key(ECC_SECP256R1, key, key + ECC_KEY_SIZE) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    key_len += ECC_PUB_KEY_SIZE;
  }

  if (openpgp_key_set_key(key_path, key, key_len) < 0) {
    memzero(key, sizeof(key));
    return -1;
  }
  if (openpgp_key_set_status(key_path, KEY_IMPORTED) < 0) {
    memzero(key, sizeof(key));
    return -1;
  }
  memzero(key, sizeof(key));

  return reset_sig_counter();
}

static int openpgp_internal_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  if (PW1_MODE82() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

  int status = openpgp_key_get_status(AUT_KEY_PATH);
  if (status < 0) return -1;
  if (status == KEY_NOT_PRESENT) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  uint8_t attr[MAX_ATTR_LENGTH];
  if (openpgp_key_get_attributes(AUT_KEY_PATH, attr) < 0) return -1;
  if (attr[0] == KEY_TYPE_RSA) {
    rsa_key_t key;
    if (openpgp_key_get_key(AUT_KEY_PATH, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    if (rsa_sign_pkcs_v15(&key, DATA, LC, RDATA) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
    LL = N_LENGTH;
  } else if (attr[0] == KEY_TYPE_ECDSA) {
    uint8_t key[ECC_KEY_SIZE];
    if (openpgp_key_get_key(AUT_KEY_PATH, key, ECC_KEY_SIZE) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    if (ecdsa_sign(ECC_SECP256R1, key, DATA, RDATA) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    LL = ECC_KEY_SIZE * 2;
  } else
    return -1;

  return 0;
}

static int openpgp_select_data(const CAPDU *capdu, RAPDU *rapdu) {
  current_occurrence = 0;
  if (P1 > 2 || P2 != 0x04) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0x06) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x60 || DATA[1] != 0x04 || DATA[2] != 0x5C || DATA[3] != 0x02 || DATA[4] != 0x7F || DATA[5] != 0x21)
    EXCEPT(SW_WRONG_DATA);
  current_occurrence = P1;
  return 0;
}

static int openpgp_get_next_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x7F || P2 != 0x21) EXCEPT(SW_WRONG_P1P2);
  if (LC > 0) EXCEPT(SW_WRONG_LENGTH);
  int len;
  if (++current_occurrence == 0)
    len = read_file(SIG_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
  else if (current_occurrence == 1)
    len = read_file(DEC_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
  else if (current_occurrence == 2)
    len = read_file(AUT_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
  else
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (len < 0) return -1;
  LL = len;
  return 0;
}

static int openpgp_terminate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  int retries = pin_get_retries(&pw3);
  if (retries < 0) return -1;
  if (retries > 0) ASSERT_ADMIN();
  uint8_t terminated = 1;
  if (write_attr(DATA_PATH, ATTR_TERMINATED, &terminated, 1) < 0) return -1;
  return 0;
}

static int openpgp_activate(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  return openpgp_install(1);
}

int openpgp_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (CLA != 0x00) EXCEPT(SW_CLA_NOT_SUPPORTED);

  uint8_t terminated;
  if (read_attr(DATA_PATH, ATTR_TERMINATED, &terminated, 1) < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  if (terminated == 1) {
    if (INS == OPENPGP_INS_ACTIVATE) {
      if (openpgp_activate(capdu, rapdu) < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
      return 0;
    }
  }

  if (INS == OPENPGP_INS_SELECT_DATA) {
    state = STATE_SELECT_DATA;
  } else if (state == STATE_NORMAL) {
    if (INS == OPENPGP_INS_GET_NEXT_DATA) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (INS == OPENPGP_INS_GET_DATA && P1 == 0x7F && P2 == 0x21) {
      state = STATE_GET_CERT_DATA;
    }
  } else if (state == STATE_SELECT_DATA) {
    if (INS == OPENPGP_INS_GET_NEXT_DATA) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (INS == OPENPGP_INS_GET_DATA && P1 == 0x7F && P2 == 0x21) {
      state = STATE_GET_CERT_DATA;
    } else {
      if (INS != OPENPGP_INS_PUT_DATA || P1 != 0x7F || P2 != 0x21) current_occurrence = 0;
      state = STATE_NORMAL;
    }
  } else {
    if (INS != OPENPGP_INS_GET_NEXT_DATA) {
      current_occurrence = 0;
      state = STATE_NORMAL;
    }
  }

  int ret;
  switch (INS) {
  case OPENPGP_INS_SELECT:
    ret = openpgp_select(capdu, rapdu);
    break;
  case OPENPGP_INS_GET_DATA:
    ret = openpgp_get_data(capdu, rapdu);
    break;
  case OPENPGP_INS_SELECT_DATA:
    ret = openpgp_select_data(capdu, rapdu);
    break;
  case OPENPGP_INS_GET_NEXT_DATA:
    ret = openpgp_get_next_data(capdu, rapdu);
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
  case OPENPGP_INS_GENERATE_ASYMMETRIC_KEY_PAIR:
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
  case OPENPGP_INS_TERMINATE:
    ret = openpgp_terminate(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }

  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
