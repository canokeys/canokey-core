// SPDX-License-Identifier: Apache-2.0
#include "key.h"
#include <common.h>
#include <device.h>
#include <ecc.h>
#include <key.h>
#include <memzero.h>
#include <openpgp.h>
#include <pin.h>
#include <rand.h>
#include <rsa.h>

#define DATA_PATH "pgp-data" // Content: URL
#define SIG_KEY_PATH "pgp-sigk"
#define DEC_KEY_PATH "pgp-deck"
#define AUT_KEY_PATH "pgp-autk"
#define SIG_CERT_PATH "pgp-sigc"
#define DEC_CERT_PATH "pgp-decc"
#define AUT_CERT_PATH "pgp-autc"

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
#define ATTR_TOUCH_CACHE_TIME 0xFB

#define STATE_NORMAL 0x00
#define STATE_SELECT_DATA 0x01
#define STATE_GET_CERT_DATA 0x02

// Algorithm ID
#define ALGO_ID_RSA 0x01
#define ALGO_ID_ECDH 0x12
#define ALGO_ID_ECDSA 0x13
#define ALGO_ID_ED25519 0x16 // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-08#section-9.1

static const uint8_t algo_attr[][12] = {
    [SECP256R1] = {9, 0x00, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07},
    [SECP256K1] = {6, 0x00, 0x2B, 0x81, 0x04, 0x00, 0x0A},
    [SECP384R1] = {6, 0x00, 0x2B, 0x81, 0x04, 0x00, 0x22},
    [SM2] = {11, 0x00, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D},
    [ED25519] = {10, ALGO_ID_ED25519, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
    [X25519] = {11, ALGO_ID_ECDH, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
    [RSA2048] = {6, ALGO_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x02},
    [RSA3072] = {6, ALGO_ID_RSA, 0x0C, 0x00, 0x00, 0x20, 0x02},
    [RSA4096] = {6, ALGO_ID_RSA, 0x10, 0x00, 0x00, 0x20, 0x02},
};

// clang-format off
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
static uint8_t pw1_mode, current_occurrence, state;
static pin_t pw1 = {.min_length = 6, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-pw1"};
static pin_t pw3 = {.min_length = 8, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-pw3"};
static pin_t rc = {.min_length = 8, .max_length = MAX_PIN_LENGTH, .is_validated = 0, .path = "pgp-rc"};
static uint8_t touch_cache_time;
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

#define UIF_DISABLED 0
#define UIF_ENABLED 1
#define UIF_PERMANENTLY 2

#define OPENPGP_TOUCH()                                                                                                \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    uint32_t current_tick = device_get_tick();                                                                         \
    if (current_tick > last_touch && current_tick - last_touch < touch_cache_time * 1000) break;                       \
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

static inline int fill_attr(const key_meta_t *meta, uint8_t *buf) {
  const uint8_t *attr = algo_attr[meta->type];
  memcpy(buf, attr, attr[0] + 1);
  if (IS_SHORT_WEIERSTRASS(meta->type)) {
    if (meta->usage == SIGN)
      buf[1] = ALGO_ID_ECDSA;
    else if (meta->usage == ENCRYPT)
      buf[1] = ALGO_ID_ECDH;
    else
      return -1;
  }
  return attr[0] + 1;
}

static inline int get_touch_policy(uint8_t touch_policy) {
  switch (touch_policy) {
  case TOUCH_POLICY_DEFAULT:
    return UIF_DISABLED;
  case TOUCH_POLICY_CACHED:
    return UIF_ENABLED;
  case TOUCH_POLICY_PERMANENT:
    return UIF_PERMANENTLY;
  default:
    return -1;
  }
}

static int UIF_TO_TOUCH_POLICY[3] = {[UIF_DISABLED] = TOUCH_POLICY_DEFAULT,
                                     [UIF_ENABLED] = TOUCH_POLICY_CACHED,
                                     [UIF_PERMANENTLY] = TOUCH_POLICY_PERMANENT};

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

  // Cardholder Data
  if (write_file(DATA_PATH, NULL, 0, 0, 1) < 0) return -1;
  uint8_t terminated = 0x01; // Terminated: yes
  if (write_attr(DATA_PATH, ATTR_TERMINATED, &terminated, 1) < 0) return -1;
  if (write_attr(DATA_PATH, TAG_LOGIN, NULL, 0) < 0) return -1;
  if (write_attr(DATA_PATH, TAG_NAME, NULL, 0)) return -1;
  // default lang = NULL
  if (write_attr(DATA_PATH, LO(TAG_LANG), NULL, 0) < 0) return -1;
  uint8_t default_sex = 0x39; // default sex
  if (write_attr(DATA_PATH, LO(TAG_SEX), &default_sex, 1) < 0) return -1;
  uint8_t default_pin_strategy = 0x00; // verify PIN every time
  if (write_attr(DATA_PATH, TAG_PW_STATUS, &default_pin_strategy, 1) < 0) return -1;

  // Key data, default to RSA2048
  uint8_t buf[20];
  memzero(buf, sizeof(buf));
  ck_key_t key = {.meta.origin = KEY_ORIGIN_NOT_PRESENT, .meta.type = RSA2048};

  key.meta.usage = SIGN;
  if (ck_write_key(SIG_KEY_PATH, &key) < 0) return -1;
  if (openpgp_key_set_fingerprint(SIG_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(SIG_KEY_PATH, buf) < 0) return -1;

  key.meta.usage = ENCRYPT;
  if (ck_write_key(DEC_KEY_PATH, &key) < 0) return -1;
  if (openpgp_key_set_fingerprint(DEC_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(DEC_KEY_PATH, buf) < 0) return -1;

  key.meta.usage = SIGN;
  if (ck_write_key(AUT_KEY_PATH, &key) < 0) return -1;
  if (openpgp_key_set_fingerprint(AUT_KEY_PATH, buf) < 0) return -1;
  if (openpgp_key_set_datetime(AUT_KEY_PATH, buf) < 0) return -1;

  if (write_attr(DATA_PATH, ATTR_CA1_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA2_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
  if (write_attr(DATA_PATH, ATTR_CA3_FP, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;

  // Touch policy
  touch_cache_time = 0;
  if (write_attr(DATA_PATH, ATTR_TOUCH_CACHE_TIME, &touch_cache_time, sizeof(touch_cache_time)) < 0) return -1;

  // Digital Sig Counter
  if (reset_sig_counter() < 0) return -1;

  // Certs
  if (write_file(SIG_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(DEC_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(AUT_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;

  // PIN data
  if (pin_create(&pw1, "123456", 6, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;
  if (pin_create(&pw3, "12345678", 8, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;
  if (pin_create(&rc, NULL, 0, PW_RETRY_COUNTER_DEFAULT) < 0) return -1;

  terminated = 0x00; // Terminated: no
  if (write_attr(DATA_PATH, ATTR_TERMINATED, &terminated, 1) < 0) return -1;

  return 0;
}

static int openpgp_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 6 || memcmp(DATA, aid, LC) != 0) EXCEPT(SW_FILE_NOT_FOUND);
  if (read_attr(DATA_PATH, ATTR_TOUCH_CACHE_TIME, &touch_cache_time, sizeof(touch_cache_time)) < 0) return -1;
  return 0;
}

static int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  uint16_t off = 0;
  int len, retries;
  key_meta_t sig_meta, dec_meta, aut_meta;
  if (ck_read_key_metadata(SIG_KEY_PATH, &sig_meta) < 0) return -1;
  if (ck_read_key_metadata(DEC_KEY_PATH, &dec_meta) < 0) return -1;
  if (ck_read_key_metadata(AUT_KEY_PATH, &aut_meta) < 0) return -1;

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
    len = fill_attr(&sig_meta, RDATA + off);
    if (len < 0) return -1;
    off += len;

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_DEC;
    len = fill_attr(&dec_meta, RDATA + off);
    if (len < 0) return -1;
    off += len;

    RDATA[off++] = TAG_ALGORITHM_ATTRIBUTES_AUT;
    len = fill_attr(&aut_meta, RDATA + off);
    if (len < 0) return -1;
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
    RDATA[off++] = 0x01; // Key-ref: sig
    RDATA[off++] = sig_meta.origin;
    RDATA[off++] = 0x02; // Key-ref: dec
    RDATA[off++] = dec_meta.origin;
    RDATA[off++] = 0x03; // Key-ref: aut
    RDATA[off++] = aut_meta.origin;

    RDATA[off++] = TAG_UIF_SIG;
    RDATA[off++] = 2;
    RDATA[off++] = get_touch_policy(sig_meta.touch_policy);
    RDATA[off++] = 0x20; // button

    RDATA[off++] = TAG_UIF_DEC;
    RDATA[off++] = 2;
    RDATA[off++] = get_touch_policy(dec_meta.touch_policy);
    RDATA[off++] = 0x20; // button

    RDATA[off++] = TAG_UIF_AUT;
    RDATA[off++] = 2;
    RDATA[off++] = get_touch_policy(aut_meta.touch_policy);
    RDATA[off++] = 0x20; // button

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
    RDATA[0] = 0x01; // Key-ref: sig
    RDATA[1] = sig_meta.origin;
    RDATA[2] = 0x02; // Key-ref: dec
    RDATA[3] = dec_meta.origin;
    RDATA[4] = 0x03; // Key-ref: aut
    RDATA[5] = aut_meta.origin;
    LL = 6;
    break;

  case TAG_ALGORITHM_INFORMATION:
#define ALGO_INFO(tag, algo, id)                                                                                       \
  do {                                                                                                                 \
    RDATA[off++] = tag;                                                                                                \
    const uint8_t *attr = algo_attr[algo];                                                                             \
    memcpy(RDATA + off, attr, attr[0] + 1);                                                                            \
    RDATA[off + 1] = id;                                                                                               \
    off += attr[0] + 1;                                                                                                \
  } while (0)

    // SIG
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, RSA2048, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, RSA3072, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, RSA4096, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, SECP256R1, ALGO_ID_ECDSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, SECP256K1, ALGO_ID_ECDSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, SECP384R1, ALGO_ID_ECDSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, ED25519, ALGO_ID_ED25519);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_SIG, SM2, ALGO_ID_ECDSA);
    // DEC
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, RSA2048, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, RSA3072, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, RSA4096, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, SECP256R1, ALGO_ID_ECDH);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, SECP256K1, ALGO_ID_ECDH);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, SECP384R1, ALGO_ID_ECDH);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, X25519, ALGO_ID_ECDH);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_DEC, SM2, ALGO_ID_ECDH);
    // AUT
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, RSA2048, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, RSA3072, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, RSA4096, ALGO_ID_RSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, SECP256R1, ALGO_ID_ECDSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, SECP256K1, ALGO_ID_ECDSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, SECP384R1, ALGO_ID_ECDSA);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, ED25519, ALGO_ID_ED25519);
    ALGO_INFO(TAG_ALGORITHM_ATTRIBUTES_AUT, SM2, ALGO_ID_ECDSA);

    LL = off;
    break;

  case TAG_UIF_CACHE_TIME:
    RDATA[0] = touch_cache_time;
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
  } else if (P2 == 0x83) {
    pw = &pw3;
  } else {
    EXCEPT(SW_WRONG_P1P2);
  }

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
  if (P2 == 0x81) {
    PW1_MODE81_ON();
  } else if (P2 == 0x82) {
    PW1_MODE82_ON();
  }

  return 0;
}

static int openpgp_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);

  pin_t *pw;
  if (P2 == 0x81) {
    pw = &pw1;
    pw1_mode = 0;
  } else if (P2 == 0x83) {
    pw = &pw3;
  } else {
    EXCEPT(SW_WRONG_P1P2);
  }

  uint8_t ctr;
  int pw_length = pin_get_size(pw);
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

  ck_key_t key;
  if (ck_read_key(key_path, &key) < 0) return -1;

  if (P1 == 0x80) {
    openpgp_start_blinking();
    if (ck_generate_key(&key) < 0) {
      ERR_MSG("Generate key %s failed\n", key_path);
      return -1;
    }
    if (ck_write_key(key_path, &key) < 0) {
      ERR_MSG("Write key %s failed\n", key_path);
      return -1;
    }
    DBG_MSG("Generate key %s successful\n", key_path);
    DBG_KEY_META(&key.meta);
  } else if (P1 == 0x81) {
    if (key.meta.origin == KEY_ORIGIN_NOT_PRESENT) {
      DBG_MSG("Generate key %s not set\n", key_path);
      memzero(&key, sizeof(key));
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    }
  } else {
    memzero(&key, sizeof(key));
    EXCEPT(SW_WRONG_P1P2);
  }

  RDATA[0] = 0x7F;
  RDATA[1] = 0x49;
  int len = ck_encode_public_key(&key, &RDATA[2], true);
  memzero(&key, sizeof(key));
  if (len < 0) return -1;
  LL = len + 2;
  if (P1 == 0x80 && strcmp(key_path, SIG_KEY_PATH) == 0) return reset_sig_counter();

  return 0;
}

static int openpgp_sign_or_auth(const CAPDU *capdu, RAPDU *rapdu, bool is_sign) {
#ifndef FUZZ
  if (is_sign) {
    if (PW1_MODE81() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  } else {
    if (PW1_MODE82() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  }
#endif

  if (is_sign) {
    uint8_t pw1_status;
    if (read_attr(DATA_PATH, TAG_PW_STATUS, &pw1_status, 1) < 0) return -1;
    if (pw1_status == 0x00) PW1_MODE81_OFF();
  }

  const char *key_path = is_sign ? SIG_KEY_PATH : AUT_KEY_PATH;

  ck_key_t key;
  if (ck_read_key_metadata(key_path, &key.meta) < 0) {
    ERR_MSG("Read metadata failed\n");
    return -1;
  }

  if (key.meta.touch_policy == TOUCH_POLICY_CACHED || key.meta.touch_policy == TOUCH_POLICY_PERMANENT) OPENPGP_TOUCH();
  if (key.meta.origin == KEY_ORIGIN_NOT_PRESENT) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if ((key.meta.usage & SIGN) == 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  openpgp_start_blinking();

  if (IS_RSA(key.meta.type)) {
    if (LC > PUBLIC_KEY_LENGTH[key.meta.type] * 2 / 5) {
      DBG_MSG("DigestInfo should be not longer than 40%% of the length of the modulus\n");
      EXCEPT(SW_WRONG_LENGTH);
    }
  } else if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
    if (LC != PRIVATE_KEY_LENGTH[key.meta.type]) {
      DBG_MSG("digest should has the same length as the private key\n");
      EXCEPT(SW_WRONG_LENGTH);
    }
  }

  if (ck_read_key(key_path, &key) < 0) {
    ERR_MSG("Read key failed\n");
    return -1;
  }

  int len = ck_sign(&key, DATA, LC, RDATA);
  if (len < 0) {
    ERR_MSG("Sign failed\n");
    return -1;
  }

  memzero(&key, sizeof(key));
  LL = len;

  if (is_sign) {
    uint8_t ctr[3];
    if (read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr, DIGITAL_SIG_COUNTER_LENGTH) < 0) {
      ERR_MSG("Read sig counter failed\n");
      return -1;
    }
    for (int i = 3; i > 0; --i)
      if (++ctr[i - 1] != 0) break;
    if (write_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, ctr, DIGITAL_SIG_COUNTER_LENGTH) < 0) {
      ERR_MSG("Write sig counter failed\n");
      return -1;
    }

  }

  return 0;
}

static int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (PW1_MODE82() == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  ck_key_t key;
  if (ck_read_key_metadata(DEC_KEY_PATH, &key.meta) < 0) return -1;

  if (key.meta.touch_policy == TOUCH_POLICY_CACHED || key.meta.touch_policy == TOUCH_POLICY_PERMANENT) OPENPGP_TOUCH();
  if (key.meta.origin == KEY_ORIGIN_NOT_PRESENT) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if ((key.meta.usage & ENCRYPT) == 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  openpgp_start_blinking();

  if (ck_read_key(DEC_KEY_PATH, &key) < 0) {
    ERR_MSG("Read DEC key failed\n");
    return -1;
  }

  DBG_KEY_META(&key.meta);

  if (IS_RSA(key.meta.type)) {
    DBG_MSG("Using RSA key: %d\n", key.meta.type);

    size_t olen;
    uint8_t invalid_padding;

    if (LC < PUBLIC_KEY_LENGTH[key.meta.type] + 1) {
      DBG_MSG("Incorrect LC\n");
      memzero(&key, sizeof(key));
      EXCEPT(SW_WRONG_LENGTH);
    }
    if (DATA[0] != 0x00) { // Padding indicator byte (00) for RSA
      DBG_MSG("Incorrect padding indicator\n");
      memzero(&key, sizeof(key));
      EXCEPT(SW_WRONG_DATA);
    }

    if (rsa_decrypt_pkcs_v15(&key.rsa, DATA + 1, &olen, RDATA, &invalid_padding) < 0) {
      ERR_MSG("Decrypt failed\n");
      memzero(&key, sizeof(key));
      if (invalid_padding) EXCEPT(SW_WRONG_DATA);
      return -1;
    }

    memzero(&key, sizeof(key));
    LL = olen;
  } else {
    DBG_MSG("Using ECC key: %d\n", key.meta.type);

    // check data and length first
    // A6 xx Cipher DO
    //       7F49 xx Public Key DO
    //               86 xx // External Public Key (04 || x || y, for short Weierstrass; x for X25519)
    if (LC < 8) {
      DBG_MSG("Incorrect LC\n");
      memzero(&key, sizeof(key));
      EXCEPT(SW_WRONG_LENGTH);
    }
    if (DATA[0] != 0xA6 || DATA[2] != 0x7F || DATA[3] != 0x49 || DATA[5] != 0x86) {
      DBG_MSG("Incorrect data\n");
      memzero(&key, sizeof(key));
      EXCEPT(SW_WRONG_DATA);
    }
    if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
      if (DATA[1] != PUBLIC_KEY_LENGTH[key.meta.type] + 6 || DATA[4] != PUBLIC_KEY_LENGTH[key.meta.type] + 3 ||
          DATA[6] != PUBLIC_KEY_LENGTH[key.meta.type] + 1 || DATA[7] != 0x04) {
        DBG_MSG("Incorrect length data\n");
        memzero(&key, sizeof(key));
        EXCEPT(SW_WRONG_DATA);
      }
    } else {
      if (DATA[1] != PUBLIC_KEY_LENGTH[key.meta.type] + 5 || DATA[4] != PUBLIC_KEY_LENGTH[key.meta.type] + 2 ||
          DATA[6] != PUBLIC_KEY_LENGTH[key.meta.type]) {
        DBG_MSG("Incorrect length data\n");
        memzero(&key, sizeof(key));
        EXCEPT(SW_WRONG_DATA);
      }
    }

    if (ecdh(key.meta.type, key.ecc.pri, DATA, RDATA) < 0) {
      ERR_MSG("ECDH failed\n");
      memzero(&key, sizeof(key));
      return -1;
    }

    memzero(&key, sizeof(key));
    LL = PRIVATE_KEY_LENGTH[key.meta.type];
  }

  return 0;
}

static int openpgp_put_data(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  ASSERT_ADMIN();
#endif
  int err;
  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  key_meta_t meta;

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

    key_type_t type;
    for (type = SECP256R1 /* i.e., 0 */; type < KEY_TYPE_END; ++type) {
      const uint8_t *attr = algo_attr[type];
      if (LC == attr[0] && memcmp(&attr[2], &DATA[1], LC - 1) == 0) { // OID or RSA params
        break;
      }
    }
    if (type == KEY_TYPE_END) {
      DBG_MSG("Invalid attr type\n");
      EXCEPT(SW_WRONG_DATA);
    }
    DBG_MSG("New attr type: %d\n", type);

    const char *key_path = NULL;
    if (tag == TAG_ALGORITHM_ATTRIBUTES_SIG) {
      key_path = SIG_KEY_PATH;
    } else if (tag == TAG_ALGORITHM_ATTRIBUTES_DEC) {
      key_path = DEC_KEY_PATH;
    } else {
      key_path = AUT_KEY_PATH;
    }

    if (ck_read_key_metadata(key_path, &meta) < 0) return -1;
    if (type == meta.type) { // Key algorithm attribute unchanged
      DBG_MSG("Attr unchanged\n");
      break;
    }
    if (tag == TAG_ALGORITHM_ATTRIBUTES_DEC) {
      if (type == ED25519) {
        DBG_MSG("DEC key disallows ed25519\n");
        EXCEPT(SW_WRONG_DATA);
      }
    } else { // TAG_ALGORITHM_ATTRIBUTES_SIG or TAG_ALGORITHM_ATTRIBUTES_AUT
      if (type == X25519) {
        DBG_MSG("SIG/AUT key disallows x25519\n");
        EXCEPT(SW_WRONG_DATA);
      }
    }
    meta.type = type;
    meta.origin = KEY_ORIGIN_NOT_PRESENT;
    if (ck_write_key_metadata(key_path, &meta) < 0) return -1;
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
    if (ck_read_key_metadata(SIG_KEY_PATH, &meta) < 0) return -1;
    if (get_touch_policy(meta.touch_policy) == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
    meta.touch_policy = UIF_TO_TOUCH_POLICY[DATA[0]];
    if (ck_write_key_metadata(SIG_KEY_PATH, &meta) < 0) return -1;
    break;

  case TAG_UIF_DEC:
    if (LC != 2) EXCEPT(SW_WRONG_LENGTH);
    if (ck_read_key_metadata(DEC_KEY_PATH, &meta) < 0) return -1;
    if (get_touch_policy(meta.touch_policy) == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
    meta.touch_policy = UIF_TO_TOUCH_POLICY[DATA[0]];
    if (ck_write_key_metadata(DEC_KEY_PATH, &meta) < 0) return -1;
    break;

  case TAG_UIF_AUT:
    if (ck_read_key_metadata(AUT_KEY_PATH, &meta) < 0) return -1;
    if (get_touch_policy(meta.touch_policy) == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
    meta.touch_policy = UIF_TO_TOUCH_POLICY[DATA[0]];
    if (ck_write_key_metadata(AUT_KEY_PATH, &meta) < 0) return -1;
    break;

  case TAG_UIF_CACHE_TIME:
    if (LC != 1) EXCEPT(SW_WRONG_LENGTH);
    touch_cache_time = DATA[0];
    if (write_attr(DATA_PATH, ATTR_TOUCH_CACHE_TIME, &touch_cache_time, sizeof(touch_cache_time)) < 0) return -1;
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

  // 4D xx Extended Header list
  //       B6/B8/A4 00/03 Control Reference Template
  //       Below are processed by ck_parse_openpgp
  //       7F48 ...
  //       5F48 ...

  const uint8_t *p = DATA;
  int fail, len;
  size_t length_size;

  // Extended Header list
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (*p++ != 0x4D) EXCEPT(SW_WRONG_DATA);

  len = tlv_get_length_safe(p, LC - 1, &fail, &length_size);
  if (fail || len < 2) EXCEPT(SW_WRONG_DATA);

  if (len + length_size + 1 != LC) EXCEPT(SW_WRONG_LENGTH);
  p += length_size;

  // Control Reference Template to indicate the private key: B6, B8 or A4
  uint8_t key_ref = *p;
  const char *key_path = get_key_path(key_ref);
  if (key_path == NULL) EXCEPT(SW_WRONG_DATA);

  // XX 00 or XX 03 84 01 01, XX = B6 / B8 / A4
  ++p;
  if (*p != 0x00 && *p != 0x03) EXCEPT(SW_WRONG_DATA);
  p += *p + 1;

  ck_key_t key;
  if (ck_read_key_metadata(key_path, &key.meta) < 0) return -1;
  int err = ck_parse_openpgp(&key, p, LC - (p - DATA));
  if (err == KEY_ERR_LENGTH) EXCEPT(SW_WRONG_LENGTH);
  else if (err == KEY_ERR_DATA) EXCEPT(SW_WRONG_DATA);
  else if (err < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  if (ck_write_key(key_path, &key) < 0) {
    memzero(&key, sizeof(key));
    return -1;
  }
  memzero(&key, sizeof(key));

  if (key_ref == 0xB6) return reset_sig_counter();
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
  ++current_occurrence;
  if (current_occurrence == 1) {
    len = read_file(DEC_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
  } else if (current_occurrence == 2) {
    len = read_file(AUT_CERT_PATH, RDATA, 0, MAX_CERT_LENGTH);
  } else {
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }
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

  uint8_t terminated;
  if (read_attr(DATA_PATH, ATTR_TERMINATED, &terminated, 1) < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
#ifndef FUZZ
  if (terminated == 1 && INS != OPENPGP_INS_ACTIVATE && INS != OPENPGP_INS_SELECT) EXCEPT(SW_TERMINATED);
#endif

  int ret;
  switch (INS) {
  case OPENPGP_INS_SELECT:
    ret = openpgp_select(capdu, rapdu);
    break;
  case OPENPGP_INS_ACTIVATE:
    if (terminated == 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    ret = openpgp_activate(capdu, rapdu);
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
    openpgp_stop_blinking();
    break;
  case OPENPGP_INS_PSO:
    if (P1 == 0x9E && P2 == 0x9A) {
      ret = openpgp_sign_or_auth(capdu, rapdu, true);
      openpgp_stop_blinking();
      break;
    }
    if (P1 == 0x80 && P2 == 0x86) {
      ret = openpgp_decipher(capdu, rapdu);
      openpgp_stop_blinking();
      break;
    }
    EXCEPT(SW_WRONG_P1P2);
  case OPENPGP_INS_INTERNAL_AUTHENTICATE:
    ret = openpgp_sign_or_auth(capdu, rapdu, false);
    openpgp_stop_blinking();
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
