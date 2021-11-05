// SPDX-License-Identifier: Apache-2.0
#include "key.h"
#include <common.h>
#include <device.h>
#include <ecc.h>
#include <ed25519.h>
#include <memzero.h>
#include <openpgp.h>
#include <pin.h>
#include <rand.h>
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

#define MAX_LOGIN_LENGTH 63
#define MAX_URL_LENGTH 255
#define MAX_NAME_LENGTH 39
#define MAX_LANG_LENGTH 8
#define MAX_SEX_LENGTH 1
#define MAX_PIN_LENGTH 64
#define MAX_CERT_LENGTH 0x480
#define MAX_DO_LENGTH 0xFF
#define MAX_KEY_TEMPLATE_LENGTH 0x16
#define DIGITAL_SIG_COUNTER_LENGTH 3
#define PW_STATUS_LENGTH 7

#define ATTR_CA1_FP 0xFF
#define ATTR_CA2_FP 0xFE
#define ATTR_CA3_FP 0xFD
#define ATTR_TERMINATED 0xFC
#define ATTR_TOUCH_POLICY 0xFB

#define STATE_NORMAL 0x00
#define STATE_SELECT_DATA 0x01
#define STATE_GET_CERT_DATA 0x02

#define KEY_TYPE_RSA 0x01
#define KEY_TYPE_ECDH 0x12
#define KEY_TYPE_ECDSA 0x13
#define KEY_TYPE_ED25519 0x16

#define KEY_SIZE_25519 32

typedef enum {
  ECDSA_P256R1,
  ECDSA_P256K1,
  ECDSA_P384R1,
  ECDH_P256R1,
  ECDH_P256K1,
  ECDH_P384R1,
  ED25519,
  X25519,
  EC_ERROR = -1,
} EC_Algorithm;

static const ECC_Curve ec_algo2curve[] = {
    [ECDSA_P256R1] = ECC_SECP256R1, [ECDSA_P256K1] = ECC_SECP256K1, [ECDSA_P384R1] = ECC_SECP384R1,
    [ECDH_P256R1] = ECC_SECP256R1,  [ECDH_P256K1] = ECC_SECP256K1,  [ECDH_P384R1] = ECC_SECP384R1,
};

// clang-format off

static const uint8_t rsa_attr[] = {KEY_TYPE_RSA,
                                   0x08, 0x00,  // Reserved for length of modulus, default: 2048
                                   0x00, 0x20,  // length of exponent: 32 bit
                                   0x02};       // import using crt (Chinese Remainder Theorem)

static const uint8_t ec_attr[][MAX_ATTR_LENGTH] = {
    {ECDSA_P256R1, 9, KEY_TYPE_ECDSA, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
    {ECDSA_P256K1, 6, KEY_TYPE_ECDSA, 0x2B, 0x81, 0x04, 0x00, 0x0A},
    {ECDSA_P384R1, 6, KEY_TYPE_ECDSA, 0x2B, 0x81, 0x04, 0x00, 0x22},
    {ECDH_P256R1, 9, KEY_TYPE_ECDH, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
    {ECDH_P256K1, 6, KEY_TYPE_ECDH, 0x2B, 0x81, 0x04, 0x00, 0x0A},
    {ECDH_P384R1, 6, KEY_TYPE_ECDH, 0x2B, 0x81, 0x04, 0x00, 0x22},
    {ED25519, 10, KEY_TYPE_ED25519, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
    {X25519, 11, KEY_TYPE_ECDH, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
};

static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, // aid
                              0x03, 0x04,                         // version
                              0xf1, 0xd0,                         // manufacturer
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

// clang-format on
// big endian
static const ed25519_public_key gx = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};

static uint8_t pw1_mode, current_occurrence, state;
static pin_t pw1 = {.min_length = 6, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-pw1"};
static pin_t pw3 = {.min_length = 8, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-pw3"};
static pin_t rc = {.min_length = 8, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-rc"};
static uint8_t touch_policy[4]; // SIG DEC AUT, time
static uint32_t last_touch = UINT32_MAX;

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

#define UIF_SIG 0
#define UIF_DEC 1
#define UIF_AUT 2
#define UIF_CACHE_TIME 3
#define UIF_PERMANENTLY 2

#define OPENPGP_TOUCH()                                                                                                \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    uint32_t current_tick = device_get_tick();                                                                         \
    if (current_tick > last_touch && current_tick - last_touch < touch_policy[3] * 1000) break;                        \
    switch (wait_for_user_presence(WAIT_ENTRY_CCID)) {                                                                 \
    case USER_PRESENCE_CANCEL:                                                                                         \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      EXCEPT(SW_ERROR_WHILE_RECEIVING);                                                                                \
    }                                                                                                                  \
    last_touch = device_get_tick();                                                                                    \
  } while (0)

static const char *get_key_path(uint8_t tag) {
  switch (tag) {
  case 0xB6:
    return SIG_KEY_PATH;
  case 0xB8:
    return DEC_KEY_PATH;
  case 0xA4:
    return AUT_KEY_PATH;
  default:
    return NULL;
  }
}

static int reset_sig_counter(void) {
  uint8_t buf[3] = {0};
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, buf, DIGITAL_SIG_COUNTER_LENGTH) < 0) return -1;
  return 0;
}

static EC_Algorithm get_ec_algo(const uint8_t *attr, int len) {
  for (int i = 0; i < 8; ++i) {
    uint8_t *r = (uint8_t *)ec_attr[i];
    if (len == r[1] && memcmp(attr, r + 2, len) == 0) return (EC_Algorithm)r[0];
    if (len == r[1] + 1 && memcmp(attr, r + 2, r[1]) == 0) return (EC_Algorithm)r[0];
  }

  return EC_ERROR;
}

static inline int get_ec_key_length(EC_Algorithm algo) {
  if (algo == ECDSA_P384R1 || algo == ECDH_P384R1) return 48;
  return 32;
}

static inline void openpgp_start_blinking(void) {
  if (!is_nfc()) start_blinking_interval(0, 25);
}

static inline void openpgp_stop_blinking(void) {
  if (!is_nfc()) stop_blinking();
}

void openpgp_poweroff(void) {
  pw1_mode = 0;
  pw1.is_validated = 0;
  pw3.is_validated = 0;
  state = STATE_NORMAL;
}

int openpgp_install(uint8_t reset) {
  openpgp_poweroff();
  if (!reset && get_file_size(DATA_PATH) >= 0) return 0;

  // PIN data
  if (pin_create(&pw1, "123456", 6, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;
  if (pin_create(&pw3, "12345678", 8, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;
  if (pin_create(&rc, NULL, 0, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;

  // Cardholder Data
  if (write_file(DATA_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_attr(DATA_PATH, TAG_LOGIN, NULL, 0) < 0) return -1;
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
  if (openpgp_key_set_attributes(SIG_KEY_PATH, rsa_attr, sizeof(rsa_attr)) < 0) return -1;
  if (openpgp_key_set_status(SIG_KEY_PATH, KEY_NOT_PRESENT) < 0) return -1;
  if (write_file(DEC_KEY_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (openpgp_key_set_fingerprint(DEC_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(DEC_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_attributes(DEC_KEY_PATH, rsa_attr, sizeof(rsa_attr)) < 0) return -1;
  if (openpgp_key_set_status(DEC_KEY_PATH, KEY_NOT_PRESENT) < 0) return -1;
  if (write_file(AUT_KEY_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (openpgp_key_set_fingerprint(AUT_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(AUT_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_attributes(AUT_KEY_PATH, rsa_attr, sizeof(rsa_attr)) < 0) return -1;
  if (openpgp_key_set_status(AUT_KEY_PATH, KEY_NOT_PRESENT) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA1_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA2_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA3_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  memzero(touch_policy, sizeof(touch_policy));
  if (write_attr(DATA_PATH, ATTR_TOUCH_POLICY, touch_policy, sizeof(touch_policy)) < 0) return -1;

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
  if (read_attr(DATA_PATH, ATTR_TOUCH_POLICY, touch_policy, sizeof(touch_policy)) < 0) return -1;
  return 0;
}

static int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  uint16_t off = 0;
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
    len = read_file(DATA_PATH, RDATA, 0, MAX_URL_LENGTH);
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

    RDATA[off++] = HI(TAG_GENERAL_FEATURE_MANAGEMENT);
    RDATA[off++] = LO(TAG_GENERAL_FEATURE_MANAGEMENT);
    RDATA[off++] = 0x03;
    RDATA[off++] = 0x81;
    RDATA[off++] = 0x01;
    RDATA[off++] = 0x20; // announces a button

    RDATA[off++] = TAG_DISCRETIONARY_DATA_OBJECTS;
    RDATA[off++] = 0x82;
    uint8_t length_pos = off;
    RDATA[off++] = 0; // these two bytes are for length
    RDATA[off++] = 0;

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

    RDATA[off++] = TAG_UIF_SIG;
    RDATA[off++] = 2;
    RDATA[off++] = touch_policy[UIF_SIG];
    RDATA[off++] = 0x20;

    RDATA[off++] = TAG_UIF_DEC;
    RDATA[off++] = 2;
    RDATA[off++] = touch_policy[UIF_DEC];
    RDATA[off++] = 0x20;

    RDATA[off++] = TAG_UIF_AUT;
    RDATA[off++] = 2;
    RDATA[off++] = touch_policy[UIF_AUT];
    RDATA[off++] = 0x20;

    uint16_t ddo_length = off - length_pos - 2;
    RDATA[length_pos] = HI(ddo_length);
    RDATA[length_pos + 1] = LO(ddo_length);
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

  case TAG_GENERAL_FEATURE_MANAGEMENT:
    RDATA[0] = 0x81;
    RDATA[1] = 0x01;
    RDATA[2] = 0x20;
    LL = 3;
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

  case TAG_UIF_CACHE_TIME:
    RDATA[0] = touch_policy[UIF_CACHE_TIME];
    LL = 1;
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
  int err = pin_verify(pw, DATA, (LC < pw_length ? LC : pw_length), &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (LC < pw_length) EXCEPT(SW_WRONG_LENGTH);
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
    err = pin_verify(&rc, DATA, (LC < offset ? LC : offset), &ctr);
    if (err == PIN_IO_FAIL) return -1;
    if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
    if (err == PIN_AUTH_FAIL) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  } else {
#ifndef FUZZ
    ASSERT_ADMIN();
#endif
    offset = 0;
  }
  if (LC < offset) EXCEPT(SW_WRONG_LENGTH);
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
  int attr_len = openpgp_key_get_attributes(key_path, attr);
  if (attr_len < 0) return -1;

  EC_Algorithm algo = EC_ERROR;
  int ec_pri_key_len = 0;
  int ec_pub_key_len = 0;
  if (attr[0] != KEY_TYPE_RSA) {
    algo = get_ec_algo(attr, attr_len);
    ec_pri_key_len = get_ec_key_length(algo);
    ec_pub_key_len = ec_pri_key_len * 2;
  }

  uint8_t key[sizeof(rsa_key_t)];

  if (P1 == 0x80) {
    uint16_t key_len = 0;
#ifndef FUZZ
    ASSERT_ADMIN();
#endif
    if (attr[0] == KEY_TYPE_RSA) {
      uint16_t nbits = (attr[1] << 8) | attr[2];
      key_len = sizeof(rsa_key_t);
#ifndef FUZZ // to speed up fuzzing
      if (nbits != 2048 || rsa_generate_key((rsa_key_t *)key, nbits) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
#else
      memcpy(
          key,
          "\x00\x08\x00\x00\x00\x01\x00\x01\xD7\x5A\x04\xFF\x4A\x3A\xD8\xCA\x21\x65\xDD\x61\x0C\x3C\x31\x4B\xFB\xC7\x07\x89\x1E\x1D\x05\xD3\xE5\x61\x39\xD5\x00\x2A\xB7\x7C\x5F\x15\x78\xA6\x32\xE3\x52\x9F\xE9\x68\x0C\x8A\x34\x1D\x9E\x6F\x03\x27\x2D\xC1\x86\x20\x90\xD8\x2D\xFE\xCB\xD5\xA8\xC9\x75\x31\xE7\x20\x2B\x5F\x1A\xA9\x4A\x77\xB1\xE5\x23\x8E\x5C\x23\x0F\x30\x0B\x67\x46\x29\xEE\x90\x23\x72\x75\x23\x3A\x5B\x50\x5E\
          \xF0\x7E\x6F\x9D\x07\xAA\x02\x2C\x63\x47\x79\xFB\x32\xAC\x84\xEE\x08\xDA\x13\xA8\xCF\x28\x56\x0E\xCD\x75\xBD\xF1\xF4\x51\xF8\x87\xA5\x99\x87\x96\x4D\xD4\x44\x7F\x00\x00\xF0\xC6\x5F\xD4\x44\x7F\x00\x00\xA0\xB4\x64\xD4\x44\x7F\x00\x01\xD8\xC6\x5F\xD4\x44\x7F\x00\x00\x80\x96\x4D\xD4\x44\x7F\x00\x00\xB8\x7C\x84\xD2\x44\x7F\x01\x00\xC0\xC6\x5F\xD4\x44\x7F\x00\x00\x18\xBC\x64\xD4\x44\x7F\x00\x00\xA8\xC6\x5F\x00\
          \x00\x00\x00\x00\xA0\x5C\x84\xD2\x44\x7F\x00\x00\x49\xE5\x6F\xDD\x44\x7F\x00\x00\xF8\xBB\x64\xD4\x44\x7F\x00\x00\x49\xE5\x6F\xDD\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xF6\x96\xD7\xD3\x44\x7F\x00\x00\xC8\xBB\x64\xD4\x01\x00\x00\x00\xB7\x2E\x83\x4D\xAA\x3C\x94\x00\x01\xC4\xBB\x40\x6C\x4D\x29\x7A\xDB\xE9\xEC\x74\x7E\x15\x07\x68\xC5\x3E\xA9\x70\x60\xA1\x46\x85\x3F\x65\xB1\xE7\x92\x31\xEF\x91\xC9\xA3\
          \x96\xCA\x94\x5A\xF8\x89\xE3\x84\x96\x0A\xE6\x24\x31\xB9\x0D\x77\x17\xD3\x08\x2D\x54\xEE\xC7\x6C\x6E\x46\x7A\xC3\xD0\x6E\x91\x7C\xD5\x21\xBC\x0C\x11\x2E\xEB\x80\xBB\x9C\x4E\x21\x45\x7E\x55\xB8\xD4\x71\xB0\x2D\xFB\xC5\x4F\x65\x94\xD4\x62\x92\x0C\x0D\x59\x6E\xF7\x33\xE4\x03\xA8\x3C\xF3\xFD\xC7\xA3\xB6\xAA\x80\x09\x9D\x22\xC2\xA7\x58\x43\x6A\x7D\x24\x51\x84\xD2\x44\x7F\x00\x01\xC0\xBA\x61\xD4\x44\x7F\x00\x00\
          \x80\x96\x4D\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x68\xBB\x64\xD4\x44\x7F\x00\x00\x52\x00\x00\x00\x06\x00\x00\x01\x40\xBA\x61\xD4\x44\x7F\x00\x00\xE8\xC5\x5F\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x50\xBB\x64\xD4\x44\x7F\x00\x00\xB8\xE2\x63\xD4\x44\x7F\x01\x01\x40\xBA\x61\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\xBA\x61\xD4\x44\x7F\x00\x00\x40\xBB\x64\xD4\x44\x7F\
          \x00\x00\xA0\xE2\x63\xD4\x44\x7F\x00\x01\x00\x05\x00\x00\x44\x7F\x04\x00\xB8\xC5\x5F\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xA0\xC5\x5F\xD4\x44\x7F\x00\x00\x98\xE2\x63\xD4\x44\x7F\x00\x06\x80\x96\x4D\xD4\x44\x7F\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x90\xC5\x5F\xD4\x44\x7F\x00\x00\x24\x51\x84\x00\x06\x00\x00\x00\x70\xC5\x5F\xD4\x44\x7F\x00\x00\x46\x00\x00\x00\x00\x00\x00\x01\xF8\xBA\x64\xD4\
          \x44\x7F\x00\x00\x41\xE5\x6F\xDD\x44\x7F\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xD8\xBA\x64\xD4\x44\x7F\x00\x00\x42\xE5\x6F\xDD\x44\x7F\x00\x01\x50\x51\x5E\xD4\x44\x7F\x00\x00\x58\xC5\x5F\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xC0\xBA\x64\xD4\x44\x7F\x00\x00\x41\xE5\x6F\xDD\x44\x7F\x00\x01\x20\x51\x5E\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\xBA\x61\xD4\x44\x01\x01\x01\xA8\xBA\
          \x64\xD4\x44\x7F\x00\x00\xCC\x02\x00\x00\x00\x00\x00\x01\xC0\xBA\x61\xD4\x44\x7F\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x90\xBA\x64\xD4\x44\x7F\x00\x00\x24\x51\x84\xD2\x44\x7F\x00\x01\x40\xBA\x61\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x01\x00\x01\x04\x30\x01\x00\x00\x44\x7F\x00\x00\x24\x51\x84\xD2\x44\x7F\x00\x01\xF8\xC4\x5F\xD4\x44\x7F\x00\x00\
          \x98\x0F\x64\xD4\x44\x01\x01\x01\x40\xE5\x6F\xDD\x44\x7F\x00\x00\x40\xBA\x61\xD4\x44\x7F\x00\xFF\x40\xE5\x6F\xDD\x44\x7F\x00\x00\xF0\xE4\x6F\xDD\x44\x7F\x00\x00\x37\x00\x00\x00\x00\x00\x00\x00\x87\x96\x4D\xD4\x44\x7F\x00\x00\xE0\xC4\x5F\xD4\x44\x7F\x00\x00\x20\x51\x84\xD2\x44\x7F\x00\x01\xC8\xC4\x5F\xD4\x44\x7F\x00\x00\x80\x96\x4D\xD4\x44\x7F\x00\x00\x01\x00\x00\x00\x7C\x00\x00\x01\xB0\xC4\x5F\xD4\x44\x7F\
          \x00\x00\x4A\x00\x00\x00\x06\x00\x00\x00\x50\x00\x00\x00\x44\x7F\xFF\x00\x98\xC4\x5F\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x80\xC4\x5F\xD4\x44\x7F\x00\x00\xD0\xB2\x64\xD4\x44\x7F\x00\x01\x39\xE5\x6F\xDD\x44\x7F\x00\x00\x28\xE1\x63\xD4\x44\x7F\x00\xFF\x39\xE5\x6F\xDD\x44\x7F\x00\x00\xF0\xE4\x6F\xDD\x44\x7F\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x87\x96\x4D\xD4\x44\x7F\x00\x00\x68\xC4\x5F\xD4\
          \x44\x7F\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x50\xC4\x5F\xD4\x44\x7F\x00\x00\x18\x7C\x84\xD2\x44\x7F\x00\x06\x80\x96\x4D\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x40\xC4\x5F\xD4\x44\x7F\x00\x00\x40\xBA\x61\x00\x06\x00\x00\x00\x20\xC4\x5F\xD4\x44\x7F\x00\x00\x44\xBA\x61\xD4\x44\x7F\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x39\xE5\x6F\xDD\x44\x7F\x00\x00\xA4\x02\x00\x00\x00\x00\x00\x00\xA5\x02\
          \x00\x00\x00\x00\x00\x00\x3A\xE5\x6F\xDD\x44\x7F\x00\x00\x3A\xE5\x6F\xDD\x44\x7F\x00\x00\x08\xC4\x5F\xD4\x44\x7F\x00\x00\xD8\x0E\x64\xD4\x44\x01\x01\x00\x49\x00\x00\x00\x00\x00\x00\x00\x39\xE5\x6F\xDD\x44\x7F\x00\x00\x88\xB9\x64\xD4\x44\x7F\x00\x00\x39\xE5\x6F\xDD\x44\x7F\x01\x04\xCC\xFC\x0F\x50\x00\x00\x04\x04\xD2\xDC\xD6\x60\x00\x00\x04\x00\x60\xB9\x64\xD4\x44\x7F\x00\x00\xF0\xE4\x6F\xDD\x44\x7F\x00\x01\
          \x36\x87\x84\xD2\x44\x7F\x00\x00\x87\x96\x4D\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x48\xB9\x64\xD4\x44\x7F\x00\x00\xD8\xC3\x5F\xD4\x44\x7F\x00\x01\x20\x87\x84\xD2\x44\x7F\x00\x00\xC0\x51\x84\xD2\x44\x7F\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00",
          key_len);
#endif // FUZZ
    } else {
      key_len = ec_pri_key_len + ec_pub_key_len;
      switch (algo) {
      case ECDSA_P256R1:
      case ECDH_P256R1:
        if (ecc_generate(ECC_SECP256R1, key, key + ec_pri_key_len) < 0) {
          memzero(key, sizeof(key));
          return -1;
        }
        break;

      case ECDSA_P256K1:
      case ECDH_P256K1:
        if (ecc_generate(ECC_SECP256K1, key, key + ec_pri_key_len) < 0) {
          memzero(key, sizeof(key));
          return -1;
        }
        break;

      case ECDSA_P384R1:
      case ECDH_P384R1:
        if (ecc_generate(ECC_SECP384R1, key, key + ec_pri_key_len) < 0) {
          memzero(key, sizeof(key));
          return -1;
        }
        break;

      case ED25519:
      case X25519:
        key_len = KEY_SIZE_25519 * 2;
        random_buffer(key, ec_pri_key_len);
        if (algo == ED25519) {
          key[0] &= 248;
          key[31] &= 127;
          key[31] |= 64;
          ed25519_publickey(key, key + ec_pri_key_len);
        } else {
          curve25519_key_from_random(key);
          // public key and secret key use big endian
          x25519(key + ec_pri_key_len, key, gx);
        }
        break;

      default:
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
    uint16_t nbits = (attr[1] << 8) | attr[2];
    uint16_t n_len = nbits / 8;
    RDATA[2] = 0x82;
    RDATA[3] = HI(6 + n_len + E_LENGTH);
    RDATA[4] = LO(6 + n_len + E_LENGTH);
    RDATA[5] = 0x81; // modulus
    RDATA[6] = 0x82;
    RDATA[7] = HI(n_len);
    RDATA[8] = LO(n_len);
    rsa_get_public_key((rsa_key_t *)key, RDATA + 9);
    RDATA[9 + n_len] = 0x82; // exponent
    RDATA[10 + n_len] = E_LENGTH;
    memcpy(RDATA + 11 + n_len, ((rsa_key_t *)key)->e, E_LENGTH);
    LL = 11 + n_len + E_LENGTH;
  } else {
    switch (algo) {
    case ECDSA_P256R1:
    case ECDSA_P256K1:
    case ECDSA_P384R1:
    case ECDH_P256R1:
    case ECDH_P256K1:
    case ECDH_P384R1:
      RDATA[2] = ec_pub_key_len + 3;
      RDATA[3] = 0x86;
      RDATA[4] = ec_pub_key_len + 1;
      RDATA[5] = 0x04;
      memcpy(RDATA + 6, key + ec_pri_key_len, ec_pub_key_len);
      LL = ec_pub_key_len + 6;
      break;

    case X25519:
      // swap endianness only for x25519
      swap_big_number_endian(key + KEY_SIZE_25519);
    case ED25519:
      RDATA[2] = KEY_SIZE_25519 + 2;
      RDATA[3] = 0x86;
      RDATA[4] = KEY_SIZE_25519;
      memcpy(RDATA + 5, key + KEY_SIZE_25519, KEY_SIZE_25519);
      LL = KEY_SIZE_25519 + 6;
      break;

    default:
      memzero(key, sizeof(key));
      return -1;
    }
  }

  memzero(key, sizeof(key));
  if (P1 == 0x80 && strcmp(key_path, SIG_KEY_PATH) == 0) return reset_sig_counter();
  return 0;
}

static int openpgp_compute_digital_signature(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (PW1_MODE81() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  uint8_t pw1_status;
  if (read_attr(DATA_PATH, TAG_PW_STATUS, &pw1_status, 1) < 0) return -1;
  if (pw1_status == 0x00) PW1_MODE81_OFF();

  if (touch_policy[UIF_SIG]) OPENPGP_TOUCH();

  openpgp_start_blinking();

  int status = openpgp_key_get_status(SIG_KEY_PATH);
  if (status < 0) {
    openpgp_stop_blinking();
    return -1;
  }
  if (status == KEY_NOT_PRESENT) {
    openpgp_stop_blinking();
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }

  uint8_t attr[MAX_ATTR_LENGTH];
  int attr_len = openpgp_key_get_attributes(SIG_KEY_PATH, attr);
  if (attr_len < 0) {
    openpgp_stop_blinking();
    return -1;
  }

  if (attr[0] == KEY_TYPE_RSA) {
    if (LC > 102) {
      openpgp_stop_blinking();
      EXCEPT(SW_WRONG_LENGTH);
    }
    rsa_key_t key;
    if (openpgp_key_get_key(SIG_KEY_PATH, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      openpgp_stop_blinking();
      return -1;
    }
    if (rsa_sign_pkcs_v15(&key, DATA, LC, RDATA) < 0) {
      memzero(&key, sizeof(key));
      openpgp_stop_blinking();
      return -1;
    }
    LL = key.nbits / 8;
    memzero(&key, sizeof(key));
  } else {
    EC_Algorithm algo = get_ec_algo(attr, attr_len);
    int ec_pri_key_len = get_ec_key_length(algo);
    uint8_t key[64]; // max possible length: ecdsa: length of the private key; eddsa: length of the key pair
    uint8_t sig[64]; // signature buffer for ed25519

    switch (algo) {
    case ECDSA_P256R1:
    case ECDSA_P256K1:
    case ECDSA_P384R1:
      if (LC < ec_pri_key_len) {
        openpgp_stop_blinking();
        EXCEPT(SW_WRONG_LENGTH);
      }
      if (openpgp_key_get_key(SIG_KEY_PATH, key, ec_pri_key_len) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      ECC_Curve curve = ec_algo2curve[algo];
      if (ecdsa_sign(curve, key, DATA, RDATA) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      memzero(key, sizeof(key));
      LL = ec_pri_key_len * 2;
      break;

    case ED25519:
      if (openpgp_key_get_key(SIG_KEY_PATH, key, KEY_SIZE_25519 * 2) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      ed25519_sign(DATA, LC, key, key + KEY_SIZE_25519, sig);
      memzero(key, sizeof(key));
      memcpy(RDATA, sig, KEY_SIZE_25519 * 2);
      LL = KEY_SIZE_25519 * 2;
      break;

    default:
      openpgp_stop_blinking();
      return -1;
    }
  }

  uint8_t ctr[3];
  if (read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr, DIGITAL_SIG_COUNTER_LENGTH) < 0) {
    openpgp_stop_blinking();
    return -1;
  }
  for (int i = 3; i > 0; --i)
    if (++ctr[i - 1] != 0) break;
  if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr, DIGITAL_SIG_COUNTER_LENGTH) < 0) {
    openpgp_stop_blinking();
    return -1;
  }

  openpgp_stop_blinking();
  return 0;
}

static int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (PW1_MODE82() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  if (touch_policy[UIF_DEC]) OPENPGP_TOUCH();

  openpgp_start_blinking();

  int status = openpgp_key_get_status(DEC_KEY_PATH);
  if (status < 0) {
    openpgp_stop_blinking();
    return -1;
  }
  if (status == KEY_NOT_PRESENT) {
    openpgp_stop_blinking();
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }

  uint8_t attr[MAX_ATTR_LENGTH];
  int attr_len = openpgp_key_get_attributes(DEC_KEY_PATH, attr);
  if (attr_len < 0) {
    openpgp_stop_blinking();
    return -1;
  }

  if (attr[0] == KEY_TYPE_RSA) {
    if (LC < 10) EXCEPT(SW_WRONG_LENGTH); // TODO: more accurate checking
    rsa_key_t key;
    if (openpgp_key_get_key(DEC_KEY_PATH, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      openpgp_stop_blinking();
      return -1;
    }
    size_t olen;
    if (rsa_decrypt_pkcs_v15(&key, DATA + 1, &olen, RDATA) < 0) {
      memzero(&key, sizeof(key));
      openpgp_stop_blinking();
      return -1;
    }
    memzero(&key, sizeof(key));
    LL = olen;
  } else if (attr[0] == KEY_TYPE_ECDH) {
    // 7.2.11 PSO: DECIPHER
    if (LC < 8) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[0] != 0xA6 || DATA[2] != 0x7F || DATA[3] != 0x49 || DATA[5] != 0x86) {
      openpgp_stop_blinking();
      EXCEPT(SW_WRONG_DATA);
    }

    EC_Algorithm algo = get_ec_algo(attr, attr_len);
    int ec_pri_key_len = get_ec_key_length(algo);
    int ec_pub_key_len = ec_pri_key_len * 2;
    uint8_t key[48]; // max possible length of the private key

    switch (algo) {
    case ECDH_P256R1:
    case ECDH_P256K1:
    case ECDH_P384R1:
      if (DATA[1] != ec_pub_key_len + 6 || DATA[4] != ec_pub_key_len + 3 || DATA[6] != ec_pub_key_len + 1 ||
          DATA[7] != 0x04) {
        openpgp_stop_blinking();
        EXCEPT(SW_WRONG_DATA);
      }
      if (LC < 7 + DATA[6]) EXCEPT(SW_WRONG_LENGTH);
      if (openpgp_key_get_key(DEC_KEY_PATH, key, ec_pri_key_len) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      ECC_Curve curve = ec_algo2curve[algo];
      if (ecdh_decrypt(curve, key, DATA + 8, RDATA) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      memzero(key, sizeof(key));
      LL = ec_pri_key_len;
      break;

    case X25519:
      if (DATA[1] != KEY_SIZE_25519 + 5 || DATA[4] != KEY_SIZE_25519 + 2 || DATA[6] != KEY_SIZE_25519) {
        openpgp_stop_blinking();
        EXCEPT(SW_WRONG_DATA);
      }
      if (LC < 7 + DATA[6]) EXCEPT(SW_WRONG_LENGTH);
      if (openpgp_key_get_key(DEC_KEY_PATH, key, KEY_SIZE_25519) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      swap_big_number_endian(DATA + 7);
      // key is already big endian
      x25519(RDATA, key, DATA + 7);
      swap_big_number_endian(RDATA);
      memzero(key, sizeof(key));
      LL = KEY_SIZE_25519;
      break;

    default:
      openpgp_stop_blinking();
      return -1;
    }
  }

  openpgp_stop_blinking();
  return 0;
}

static int openpgp_put_data(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  ASSERT_ADMIN();
#endif
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
    if (write_file(DATA_PATH, DATA, 0, LC, 1) < 0) return -1;
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
    if (LC < 1 || LC > MAX_ATTR_LENGTH) EXCEPT(SW_WRONG_LENGTH);

    const char *key_path = NULL;
    if (tag == TAG_ALGORITHM_ATTRIBUTES_SIG)
      key_path = SIG_KEY_PATH;
    else if (tag == TAG_ALGORITHM_ATTRIBUTES_DEC)
      key_path = DEC_KEY_PATH;
    else
      key_path = AUT_KEY_PATH;

    if (DATA[0] == KEY_TYPE_RSA) {
      if (LC != sizeof(rsa_attr)) EXCEPT(SW_WRONG_DATA);
      uint16_t nbits = (DATA[1] << 8) | DATA[2];
      if (nbits != 2048 && nbits != 4096) EXCEPT(SW_WRONG_DATA);
      DATA[3] = 0x00;
      DATA[4] = 0x20;
      DATA[5] = 0x02;
    } else {
      switch (get_ec_algo(DATA, LC)) {
      case ECDSA_P256R1:
      case ECDSA_P256K1:
      case ECDSA_P384R1:
      case ED25519:
        if (tag == TAG_ALGORITHM_ATTRIBUTES_DEC) DATA[0] = KEY_TYPE_ECDH;
        break;

      case ECDH_P256R1:
      case ECDH_P256K1:
      case ECDH_P384R1:
      case X25519:
        if (tag != TAG_ALGORITHM_ATTRIBUTES_DEC) DATA[0] = KEY_TYPE_ECDSA;
        break;

      default:
        EXCEPT(SW_WRONG_DATA);
      }
    }
    if (openpgp_key_set_attributes(key_path, DATA, LC) < 0) return -1;
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

  case TAG_UIF_SIG:
    if (LC != 2) EXCEPT(SW_WRONG_LENGTH);
    if (touch_policy[UIF_SIG] == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
    touch_policy[UIF_SIG] = DATA[0];
    if (write_attr(DATA_PATH, ATTR_TOUCH_POLICY, touch_policy, sizeof(touch_policy)) < 0) return -1;
    break;

  case TAG_UIF_DEC:
    if (LC != 2) EXCEPT(SW_WRONG_LENGTH);
    if (touch_policy[UIF_DEC] == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
    touch_policy[UIF_DEC] = DATA[0];
    if (write_attr(DATA_PATH, ATTR_TOUCH_POLICY, touch_policy, sizeof(touch_policy)) < 0) return -1;
    break;

  case TAG_UIF_AUT:
    if (LC != 2) EXCEPT(SW_WRONG_LENGTH);
    if (touch_policy[UIF_AUT] == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
    touch_policy[UIF_AUT] = DATA[0];
    if (write_attr(DATA_PATH, ATTR_TOUCH_POLICY, touch_policy, sizeof(touch_policy)) < 0) return -1;
    break;

  case TAG_UIF_CACHE_TIME:
    if (LC != 1) EXCEPT(SW_WRONG_LENGTH);
    touch_policy[UIF_CACHE_TIME] = DATA[0];
    if (write_attr(DATA_PATH, ATTR_TOUCH_POLICY, touch_policy, sizeof(touch_policy)) < 0) return -1;
    break;

  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  return 0;
}

static int openpgp_import_key(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  ASSERT_ADMIN();
#endif
  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);

  size_t length_size;
  int fail;
  const uint8_t *p = DATA;
  // Extended Header list, 4D
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (*p++ != 0x4D) EXCEPT(SW_WRONG_DATA);

  uint16_t len = tlv_get_length_safe(p, LC - 1, &fail, &length_size);
  if (fail || len < 2) EXCEPT(SW_WRONG_LENGTH);

  if (len + length_size + 1 != LC) EXCEPT(SW_WRONG_LENGTH);
  p += length_size;

  // Control Reference Template to indicate the private key: B6, B8 or A4
  const char *key_path = get_key_path(*p);
  if (key_path == NULL) EXCEPT(SW_WRONG_DATA);

  uint8_t attr[MAX_ATTR_LENGTH];
  int attr_len = openpgp_key_get_attributes(key_path, attr);
  if (attr_len < 0) return -1;

  // XX 00 or XX 03 84 01 01, XX = B6 / B8 / A4
  ++p;
  if (*p != 0x00 && *p != 0x03) EXCEPT(SW_WRONG_DATA);
  p += *p + 1;

  // Cardholder private key template
  if (p + 2 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
  if (*p++ != 0x7F || *p++ != 0x48) EXCEPT(SW_WRONG_DATA);
  uint16_t template_len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
  if (fail) EXCEPT(SW_WRONG_LENGTH);
  if (template_len > MAX_KEY_TEMPLATE_LENGTH) EXCEPT(SW_WRONG_DATA);
  p += length_size;

  const uint8_t *data_tag = p + template_len; // saved for tag 5F48
  uint8_t key[sizeof(rsa_key_t)];             // rsa_key_t is larger than any ec key
  uint16_t key_len = 0;
  memzero(key, sizeof(key));

  if (attr[0] == KEY_TYPE_RSA) {
    uint16_t nbits = (attr[1] << 8) | attr[2];
    uint16_t pq_len = nbits / 16, qinv_len, dp_len, dq_len;
    key_len = sizeof(rsa_key_t);

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x91) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len != E_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x92) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len != pq_len) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x93) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len != pq_len) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x94) EXCEPT(SW_WRONG_DATA);
    qinv_len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (qinv_len > pq_len) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x95) EXCEPT(SW_WRONG_DATA);
    dp_len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (dp_len > pq_len) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x96) EXCEPT(SW_WRONG_DATA);
    dq_len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (dq_len > pq_len) EXCEPT(SW_WRONG_DATA);

    p = data_tag;
    if (p + 2 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x5F || *p++ != 0x48) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size); // Concatenation of key data
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len != pq_len * 2 + qinv_len + dp_len + dq_len + E_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    if (p + len - DATA > LC) EXCEPT(SW_WRONG_LENGTH);
    ((rsa_key_t *)key)->nbits = nbits;
    memcpy(((rsa_key_t *)key)->e, p, E_LENGTH);
    p += E_LENGTH;
    memcpy(((rsa_key_t *)key)->p, p, pq_len);
    p += pq_len;
    memcpy(((rsa_key_t *)key)->q, p, pq_len);
    p += pq_len;
    memcpy(((rsa_key_t *)key)->qinv + pq_len - qinv_len, p, qinv_len);
    p += qinv_len;
    memcpy(((rsa_key_t *)key)->dp + pq_len - dp_len, p, dp_len);
    p += dp_len;
    memcpy(((rsa_key_t *)key)->dq + pq_len - dq_len, p, dq_len);
  } else {
    EC_Algorithm algo = get_ec_algo(attr, attr_len);
    int ec_pri_key_len = get_ec_key_length(algo);
    key_len = ec_pri_key_len * 3;

    if (p + 1 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x92) EXCEPT(SW_WRONG_DATA);
    int data_pri_key_len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (data_pri_key_len > ec_pri_key_len) EXCEPT(SW_WRONG_DATA);
    p += length_size;

    int data_pub_key_len = 0; // this is optional
    if (*p++ == 0x99) {
      data_pub_key_len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
      if (fail) EXCEPT(SW_WRONG_LENGTH);
      if (data_pub_key_len > ec_pri_key_len * 2 + 1) EXCEPT(SW_WRONG_DATA);
    }

    p = data_tag;
    if (p + 2 - DATA >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x5F || *p++ != 0x48) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size); // Concatenation of key data
    if (fail || len != data_pri_key_len + data_pub_key_len) EXCEPT(SW_WRONG_LENGTH);
    p += length_size;
    int n_leading_zeros = ec_pri_key_len - data_pri_key_len;
    if (p + data_pri_key_len - DATA > LC) EXCEPT(SW_WRONG_LENGTH);
    memzero(key, n_leading_zeros);
    memcpy(key + n_leading_zeros, p, data_pri_key_len);

    ECC_Curve curve = 0;
    switch (algo) {
    case ECDSA_P256R1:
    case ECDSA_P256K1:
    case ECDSA_P384R1:
    case ECDH_P256R1:
    case ECDH_P256K1:
    case ECDH_P384R1:
      curve = ec_algo2curve[algo];
      if (!ecc_verify_private_key(curve, key)) {
        memzero(key, sizeof(key));
        EXCEPT(SW_WRONG_DATA);
      }
      if (ecc_get_public_key(curve, key, key + ec_pri_key_len) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      break;

    case ED25519:
      ed25519_publickey(key, key + KEY_SIZE_25519);
      key_len = KEY_SIZE_25519 * 2;
      break;

    case X25519:
      // import secret key is big endian
      x25519(key + KEY_SIZE_25519, key, gx);
      key_len = KEY_SIZE_25519 * 2;
      break;

    default:
      memzero(key, sizeof(key));
      return -1;
    }
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

  if (strcmp(key_path, SIG_KEY_PATH) == 0) return reset_sig_counter();
  return 0;
}

static int openpgp_internal_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (PW1_MODE82() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  if (touch_policy[UIF_AUT]) OPENPGP_TOUCH();

  openpgp_start_blinking();

  int status = openpgp_key_get_status(AUT_KEY_PATH);
  if (status < 0) {
    openpgp_stop_blinking();
    return -1;
  }
  if (status == KEY_NOT_PRESENT) {
    openpgp_stop_blinking();
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }

  uint8_t attr[MAX_ATTR_LENGTH];
  int attr_len = openpgp_key_get_attributes(AUT_KEY_PATH, attr);
  if (attr_len < 0) {
    openpgp_stop_blinking();
    return -1;
  }

  if (attr[0] == KEY_TYPE_RSA) {
    if (LC > 102) {
      openpgp_stop_blinking();
      EXCEPT(SW_WRONG_LENGTH);
    }
    rsa_key_t key;
    if (openpgp_key_get_key(AUT_KEY_PATH, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      openpgp_stop_blinking();
      return -1;
    }
    if (rsa_sign_pkcs_v15(&key, DATA, LC, RDATA) < 0) {
      memzero(&key, sizeof(key));
      openpgp_stop_blinking();
      return -1;
    }
    LL = key.nbits / 8;
    memzero(&key, sizeof(key));
  } else {
    EC_Algorithm algo = get_ec_algo(attr, attr_len);
    int ec_pri_key_len = get_ec_key_length(algo);
    uint8_t key[64]; // max possible length: ecdsa: length of the private key; eddsa: length of the key pair
    uint8_t sig[64]; // signature buffer for ed25519

    switch (algo) {
    case ECDSA_P256R1:
    case ECDSA_P256K1:
    case ECDSA_P384R1:
      if (LC < ec_pri_key_len) {
        openpgp_stop_blinking();
        EXCEPT(SW_WRONG_LENGTH);
      }
      if (openpgp_key_get_key(AUT_KEY_PATH, key, ec_pri_key_len) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      ECC_Curve curve = ec_algo2curve[algo];
      if (ecdsa_sign(curve, key, DATA, RDATA) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      memzero(key, sizeof(key));
      LL = ec_pri_key_len * 2;
      break;

    case ED25519:
      if (openpgp_key_get_key(AUT_KEY_PATH, key, KEY_SIZE_25519 * 2) < 0) {
        memzero(key, sizeof(key));
        openpgp_stop_blinking();
        return -1;
      }
      ed25519_sign(DATA, LC, key, key + KEY_SIZE_25519, sig);
      memzero(key, sizeof(key));
      memcpy(RDATA, sig, KEY_SIZE_25519 * 2);
      LL = KEY_SIZE_25519 * 2;
      break;

    default:
      openpgp_stop_blinking();
      return -1;
    }
  }

  openpgp_stop_blinking();
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
  int len = 0;
  ++current_occurrence;
  if (current_occurrence == 1)
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
#ifndef FUZZ
  if (terminated == 1) {
    if (INS == OPENPGP_INS_ACTIVATE) {
      if (openpgp_activate(capdu, rapdu) < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
      return 0;
    } else
    {
      EXCEPT(SW_TERMINATED);
    }
  }
#endif

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
