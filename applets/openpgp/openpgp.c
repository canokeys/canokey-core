// SPDX-License-Identifier: Apache-2.0
#include "algo.h"
#include "key.h"
#include <applet-scratch.h>
#include <common.h>
#include <device-config.h>
#include <device.h>
#include <ecc.h>
#include <key.h>
#include <memzero.h>
#include <openpgp.h>
#include <pke.h>
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
#define MAX_DECIPHER_INPUT_LENGTH 513
#define MAX_PUBKEY_RESPONSE_LENGTH 527
#define MAX_CRYPTO_RESULT_LENGTH 512
#define OPENPGP_CRYPTO_BUFFER_LENGTH MAX(MAX_DECIPHER_INPUT_LENGTH, MAX_CRYPTO_RESULT_LENGTH)
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
    [SECP521R1] = {6, 0x00, 0x2B, 0x81, 0x04, 0x00, 0x23},
    [SM2] = {11, 0x00, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D},
    [ED25519] = {10, ALGO_ID_ED25519, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
    [X25519] = {11, ALGO_ID_ECDH, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
    [RSA2048] = {6, ALGO_ID_RSA, 0x08, 0x00, 0x00, 0x20, 0x02},
    [RSA3072] = {6, ALGO_ID_RSA, 0x0C, 0x00, 0x00, 0x20, 0x02},
    [RSA4096] = {6, ALGO_ID_RSA, 0x10, 0x00, 0x00, 0x20, 0x02},
};
#define OPENPGP_ALGO_ATTR_COUNT (sizeof(algo_attr) / sizeof(algo_attr[0]))

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
                                           0x80, // command chaining (Section 6.1)
                                           0x05, 0x90, 0x00};

static const uint8_t extended_capabilities[] = {
    0x74, // Support get challenge, key import, pw1 status change, and algorithm attributes changes
    0x00, // No SM algorithm
    HI(APDU_BUFFER_SIZE),
    LO(APDU_BUFFER_SIZE), // Challenge size
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

typedef struct {
  const char *path;
} openpgp_cert_source_t;

static openpgp_cert_source_t cert_source;
static const char *cert_write_path;
static int16_t cert_write_remaining = -1;
static const char *import_key_path;
static uint8_t import_key_ref;
static uint16_t import_total_len;
static uint16_t import_received;
static ck_openpgp_stream_t import_stream;
static uint16_t decipher_received;
static uint8_t openpgp_crypto_owned;
static uint8_t openpgp_pke_owned;
#define openpgp_crypto_buffer_storage applet_session_scratch.buffer

static int openpgp_crypto_acquire(void) {
  openpgp_crypto_owned = 1;
  return 0;
}

static void openpgp_crypto_release(void) {
  if (!openpgp_crypto_owned) return;
  memzero(openpgp_crypto_buffer_storage, sizeof(openpgp_crypto_buffer_storage));
  openpgp_crypto_owned = 0;
}

static uint8_t *openpgp_crypto_buffer(void) { return openpgp_crypto_buffer_storage; }

static int openpgp_pke_acquire(void) {
  if (openpgp_pke_owned) return 0;
  if (pke_buffer_acquire(PKE_BUFFER_OWNER_OPENPGP) < 0) {
    DBG_MSG("OpenPGP PKE acquire failed\n");
    return -1;
  }
  openpgp_pke_owned = 1;
  return 0;
}

static void openpgp_pke_release(void) {
  if (!openpgp_pke_owned) return;
  pke_buffer_clear();
  pke_buffer_release(PKE_BUFFER_OWNER_OPENPGP);
  openpgp_pke_owned = 0;
}

static int openpgp_buffer_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  const uint8_t *data = (const uint8_t *)ctx;
  memcpy(buf, data + offset, len);
  return len;
}

static int openpgp_pke_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  UNUSED(ctx);
  return pke_buffer_read(offset, buf, len) < 0 ? -1 : len;
}

static void openpgp_pke_source_close(void *ctx) {
  (void)ctx;
  openpgp_pke_release();
}

static void openpgp_crypto_source_close(void *ctx) {
  (void)ctx;
  openpgp_crypto_release();
}

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

static int openpgp_cert_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  const openpgp_cert_source_t *source = (const openpgp_cert_source_t *)ctx;
  return read_file(source->path, buf, offset, len);
}

static void openpgp_cert_write_reset(void) {
  cert_write_path = NULL;
  cert_write_remaining = -1;
}

static void openpgp_import_reset(void) {
  openpgp_pke_release();
  import_key_path = NULL;
  import_key_ref = 0;
  import_total_len = 0;
  import_received = 0;
  memzero(&import_stream, sizeof(import_stream));
}

static void openpgp_decipher_reset(void) { decipher_received = 0; }

static int openpgp_set_result(const uint8_t *data, uint16_t len, uint8_t *inline_dest) {
  if (len > MAX_CRYPTO_RESULT_LENGTH) return -1;
  if (len > APDU_COMMAND_BUFFER_SIZE) {
    if (openpgp_crypto_acquire() < 0) return -1;
    uint8_t *result = openpgp_crypto_buffer();
    if (data != result) memcpy(result, data, len);
    apdu_response_source_set(len, SW_NO_ERROR, openpgp_buffer_source_read, openpgp_crypto_source_close, result);
    return 1;
  }
  if (data != inline_dest) memcpy(inline_dest, data, len);
  openpgp_crypto_release();
  return 0;
}

static int openpgp_send_cert(const CAPDU *capdu, RAPDU *rapdu, const char *path) {
  UNUSED(capdu);
  int len = get_file_size(path);
  if (len < 0) return -1;
  if (len > MAX_CERT_LENGTH) EXCEPT(SW_WRONG_LENGTH);

  cert_source.path = path;
  apdu_response_source_set((uint32_t)len, SW_NO_ERROR, openpgp_cert_source_read, NULL, &cert_source);
  LL = 0;
  return 0;
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

enum PGP_KEY_TYPE { SIG_KEY_IDX = 0, DEC_KEY_IDX, AUT_KEY_IDX, NUM_KEYS };

/* Per-key constant data for SIG, DEC, and AUT keys.
 * All tag fields hold single-byte BER-TLV tags (≤ 0xFF) and are stored
 * as uint8_t; comparisons with the uint16_t `tag` variable rely on the
 * standard integer promotion rules and are safe for these values.
 */
typedef struct {
  const char *key_path;  /* LittleFS path of the private-key object */
  const char *cert_path; /* LittleFS path of the cardholder certificate */
  uint8_t key_usage;     /* SIGN or ENCRYPT */
  uint8_t ca_attr;       /* ATTR_CA{1,2,3}_FP – attribute id for CA fingerprint */
  uint8_t alg_tag;       /* TAG_ALGORITHM_ATTRIBUTES_{SIG,DEC,AUT} */
  uint8_t key_ref;       /* Key-information reference byte (0x01/0x02/0x03) */
  uint8_t uif_tag;       /* TAG_UIF_{SIG,DEC,AUT} */
  uint8_t fp_tag;        /* TAG_KEY_{SIG,DEC,AUT}_FINGERPRINT */
  uint8_t ca_fp_tag;     /* TAG_KEY_CA{1,2,3}_FINGERPRINT */
  uint8_t dt_tag;        /* TAG_KEY_{SIG,DEC,AUT}_GENERATION_DATES */
} openpgp_key_info_t;

static const openpgp_key_info_t key_info[NUM_KEYS] = {
    [SIG_KEY_IDX] = {SIG_KEY_PATH, SIG_CERT_PATH, SIGN, ATTR_CA1_FP, TAG_ALGORITHM_ATTRIBUTES_SIG, 0x01, TAG_UIF_SIG,
                     TAG_KEY_SIG_FINGERPRINT, TAG_KEY_CA1_FINGERPRINT, TAG_KEY_SIG_GENERATION_DATES},
    [DEC_KEY_IDX] = {DEC_KEY_PATH, DEC_CERT_PATH, ENCRYPT, ATTR_CA2_FP, TAG_ALGORITHM_ATTRIBUTES_DEC, 0x02, TAG_UIF_DEC,
                     TAG_KEY_DEC_FINGERPRINT, TAG_KEY_CA2_FINGERPRINT, TAG_KEY_DEC_GENERATION_DATES},
    [AUT_KEY_IDX] = {AUT_KEY_PATH, AUT_CERT_PATH, SIGN, ATTR_CA3_FP, TAG_ALGORITHM_ATTRIBUTES_AUT, 0x03, TAG_UIF_AUT,
                     TAG_KEY_AUT_FINGERPRINT, TAG_KEY_CA3_FINGERPRINT, TAG_KEY_AUT_GENERATION_DATES},
};

// Algorithm information structure to reduce code size
typedef struct {
  uint8_t tag;
  int algo_index; // Algorithm index in algo_attr array
  uint8_t id;
} algo_info_t;

// Add a single algorithm information to the buffer
static uint16_t add_algo_info(uint8_t *buffer, uint16_t offset, uint8_t tag, int algo_index, uint8_t id) {
  buffer[offset++] = tag;
  const uint8_t *attr = algo_attr[algo_index];
  memcpy(buffer + offset, attr, attr[0] + 1);
  buffer[offset + 1] = id;
  return offset + attr[0] + 1;
}

// Add all supported algorithm information to the buffer
static uint16_t add_all_algorithm_info(uint8_t *buffer) {
  uint16_t offset = 0;

  // Define a static array of all algorithm information to avoid duplicate code
  static const algo_info_t all_algo_infos[] = {
      // SIG algorithms
      {TAG_ALGORITHM_ATTRIBUTES_SIG, RSA2048, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, RSA3072, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, RSA4096, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, SECP256R1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, SECP256K1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, SECP384R1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, SECP521R1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, ED25519, ALGO_ID_ED25519},
      {TAG_ALGORITHM_ATTRIBUTES_SIG, SM2, ALGO_ID_ECDSA},
      // DEC algorithms
      {TAG_ALGORITHM_ATTRIBUTES_DEC, RSA2048, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, RSA3072, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, RSA4096, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, SECP256R1, ALGO_ID_ECDH},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, SECP256K1, ALGO_ID_ECDH},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, SECP384R1, ALGO_ID_ECDH},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, SECP521R1, ALGO_ID_ECDH},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, X25519, ALGO_ID_ECDH},
      {TAG_ALGORITHM_ATTRIBUTES_DEC, SM2, ALGO_ID_ECDH},
      // AUT algorithms
      {TAG_ALGORITHM_ATTRIBUTES_AUT, RSA2048, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, RSA3072, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, RSA4096, ALGO_ID_RSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, SECP256R1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, SECP256K1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, SECP384R1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, SECP521R1, ALGO_ID_ECDSA},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, ED25519, ALGO_ID_ED25519},
      {TAG_ALGORITHM_ATTRIBUTES_AUT, SM2, ALGO_ID_ECDSA},
  };

  // Use a loop to iterate through all algorithm information instead of repeated code blocks
  for (size_t i = 0; i < sizeof(all_algo_infos) / sizeof(algo_info_t); i++) {
    offset = add_algo_info(buffer, offset, all_algo_infos[i].tag, all_algo_infos[i].algo_index, all_algo_infos[i].id);
  }

  return offset;
}

void openpgp_poweroff(void) {
  pw1_mode = 0;
  pw1.is_validated = 0;
  pw3.is_validated = 0;
  state = STATE_NORMAL;
  cert_write_path = NULL;
  cert_write_remaining = -1;
  openpgp_import_reset();
  openpgp_decipher_reset();
  openpgp_crypto_release();
  openpgp_pke_release();
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

  for (size_t i = 0; i < NUM_KEYS; ++i) {
    key.meta.usage = key_info[i].key_usage;
    if (ck_write_key(key_info[i].key_path, &key) < 0) return -1;
    if (openpgp_key_set_fingerprint(key_info[i].key_path, buf) < 0) return -1;
    if (openpgp_key_set_datetime(key_info[i].key_path, buf) < 0) return -1;
    if (write_attr(DATA_PATH, key_info[i].ca_attr, buf, KEY_FINGERPRINT_LENGTH) < 0) return -1;
    if (write_file(key_info[i].cert_path, NULL, 0, 0, 1) < 0) return -1;
  }

  // Touch policy
  touch_cache_time = 0;
  if (write_attr(DATA_PATH, ATTR_TOUCH_CACHE_TIME, &touch_cache_time, sizeof(touch_cache_time)) < 0) return -1;

  // Digital Sig Counter
  if (reset_sig_counter() < 0) return -1;

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

/**
 * Fill PW_STATUS bytes into buf[0..PW_STATUS_LENGTH-1].
 * Returns PW_STATUS_LENGTH on success, -1 on I/O error.
 */
static int fill_pw_status(uint8_t *buf) {
  if (read_attr(DATA_PATH, TAG_PW_STATUS, buf, 1) < 0) return -1;
  buf[1] = MAX_PIN_LENGTH;
  buf[2] = MAX_PIN_LENGTH;
  buf[3] = MAX_PIN_LENGTH;
  int retries = pin_get_retries(&pw1);
  if (retries < 0) return -1;
  buf[4] = retries;
  retries = pin_get_retries(&rc);
  if (retries < 0) return -1;
  buf[5] = retries;
  retries = pin_get_retries(&pw3);
  if (retries < 0) return -1;
  buf[6] = retries;
  return PW_STATUS_LENGTH;
}

static int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  uint16_t tag = (uint16_t)(P1 << 8u) | P2;
  uint16_t off = 0;
  int len;
  key_meta_t metas[NUM_KEYS];
  for (size_t i = 0; i < NUM_KEYS; ++i) {
    if (ck_read_key_metadata(key_info[i].key_path, &metas[i]) < 0) return -1;
  }

  switch (tag) {
  case TAG_AID:
    memcpy(RDATA, aid, sizeof(aid));
    device_config_fill_serial(RDATA + 10);
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
    RDATA[off++] = TAG_CARDHOLDER_RELATED_DATA;
    RDATA[off++] = 0; // to be filled later
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
    RDATA[1] = off - 2;
    LL = off;
    break;

  case TAG_APPLICATION_RELATED_DATA:
    RDATA[off++] = TAG_APPLICATION_RELATED_DATA;
    RDATA[off++] = 0x82; // extended length
    RDATA[off++] = 0;    // to be filled later
    RDATA[off++] = 0;    // to be filled later
    RDATA[off++] = TAG_AID;
    RDATA[off++] = sizeof(aid);
    memcpy(RDATA + off, aid, sizeof(aid));
    device_config_fill_serial(RDATA + off + 10);
    off += sizeof(aid);

    RDATA[off++] = HI(TAG_HISTORICAL_BYTES);
    RDATA[off++] = LO(TAG_HISTORICAL_BYTES);
    RDATA[off++] = sizeof(historical_bytes);
    memcpy(RDATA + off, historical_bytes, sizeof(historical_bytes));
    off += sizeof(historical_bytes);

    RDATA[off++] = HI(TAG_GENERAL_FEATURE_MANAGEMENT);
    RDATA[off++] = LO(TAG_GENERAL_FEATURE_MANAGEMENT);
    RDATA[off++] = 0x03;
    RDATA[off++] = 0x81;
    RDATA[off++] = 0x01;
    RDATA[off++] = 0x20; // announces a button

    RDATA[off++] = TAG_DISCRETIONARY_DATA_OBJECTS;
    RDATA[off++] = 0x82;
    uint16_t length_pos = off;
    RDATA[off++] = 0; // these two bytes are for length
    RDATA[off++] = 0;

    RDATA[off++] = TAG_EXTENDED_CAPABILITIES;
    RDATA[off++] = sizeof(extended_capabilities);
    memcpy(RDATA + off, extended_capabilities, sizeof(extended_capabilities));
    off += sizeof(extended_capabilities);

    for (size_t i = 0; i < NUM_KEYS; ++i) {
      RDATA[off++] = key_info[i].alg_tag;
      len = fill_attr(&metas[i], RDATA + off);
      if (len < 0) return -1;
      off += len;
    }

    RDATA[off++] = TAG_PW_STATUS;
    RDATA[off++] = PW_STATUS_LENGTH;
    if (fill_pw_status(RDATA + off) < 0) return -1;
    off += PW_STATUS_LENGTH;

    RDATA[off++] = TAG_KEY_FINGERPRINTS;
    RDATA[off++] = KEY_FINGERPRINT_LENGTH * NUM_KEYS;
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      len = openpgp_key_get_fingerprint(key_info[i].key_path, RDATA + off);
      if (len < 0) return -1;
      off += len;
    }

    RDATA[off++] = TAG_CA_FINGERPRINTS;
    RDATA[off++] = KEY_FINGERPRINT_LENGTH * NUM_KEYS;
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      len = read_attr(DATA_PATH, key_info[i].ca_attr, RDATA + off, KEY_FINGERPRINT_LENGTH);
      if (len < 0) return -1;
      off += len;
    }

    RDATA[off++] = TAG_KEY_GENERATION_DATES;
    RDATA[off++] = KEY_DATETIME_LENGTH * NUM_KEYS;
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      len = openpgp_key_get_datetime(key_info[i].key_path, RDATA + off);
      if (len < 0) return -1;
      off += len;
    }

    RDATA[off++] = TAG_KEY_INFO;
    RDATA[off++] = NUM_KEYS * 2;
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      RDATA[off++] = key_info[i].key_ref;
      RDATA[off++] = metas[i].origin;
    }

    for (size_t i = 0; i < NUM_KEYS; ++i) {
      RDATA[off++] = key_info[i].uif_tag;
      RDATA[off++] = 2;
      RDATA[off++] = get_touch_policy(metas[i].touch_policy);
      RDATA[off++] = 0x20; // button
    }

    uint16_t ddo_length = off - length_pos - 2;
    RDATA[length_pos] = HI(ddo_length);
    RDATA[length_pos + 1] = LO(ddo_length);

    ddo_length = off - 4;
    RDATA[2] = HI(ddo_length);
    RDATA[3] = LO(ddo_length);
    LL = off;
    break;

  case TAG_SECURITY_SUPPORT_TEMPLATE:
    RDATA[0] = TAG_SECURITY_SUPPORT_TEMPLATE;
    RDATA[1] = DIGITAL_SIG_COUNTER_LENGTH + 2;
    RDATA[2] = TAG_DIGITAL_SIG_COUNTER;
    RDATA[3] = DIGITAL_SIG_COUNTER_LENGTH;
    len = read_attr(DATA_PATH, TAG_DIGITAL_SIG_COUNTER, RDATA + 4, DIGITAL_SIG_COUNTER_LENGTH);
    if (len < 0) return -1;
    LL = 4 + DIGITAL_SIG_COUNTER_LENGTH;
    break;

  case TAG_CARDHOLDER_CERTIFICATE:
    if (current_occurrence >= NUM_KEYS) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    return openpgp_send_cert(capdu, rapdu, key_info[current_occurrence].cert_path);

  case TAG_GENERAL_FEATURE_MANAGEMENT:
    RDATA[0] = 0x81;
    RDATA[1] = 0x01;
    RDATA[2] = 0x20;
    LL = 3;
    break;

  case TAG_PW_STATUS:
    if (fill_pw_status(RDATA) < 0) return -1;
    LL = PW_STATUS_LENGTH;
    break;

  case TAG_KEY_INFO:
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      RDATA[i * 2] = key_info[i].key_ref;
      RDATA[i * 2 + 1] = metas[i].origin;
    }
    LL = NUM_KEYS * 2;
    break;

  case TAG_ALGORITHM_INFORMATION:
    RDATA[0] = TAG_ALGORITHM_INFORMATION;
    RDATA[1] = 0x81;
    RDATA[2] = add_all_algorithm_info(RDATA + 3);
    LL = RDATA[2] + 3;
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
    EXCEPT(pin_get_retry_sw((uint8_t)retries));
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

static int openpgp_set_pin_retries(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 3) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] == 0 || DATA[0] > PIN_MAX_RETRIES || DATA[1] == 0 || DATA[1] > PIN_MAX_RETRIES || DATA[2] == 0 ||
      DATA[2] > PIN_MAX_RETRIES)
    EXCEPT(SW_WRONG_DATA);

#ifndef FUZZ
  ASSERT_ADMIN();
#endif

  // A retry reset rewrites PW1/PW3. Clear volatile authorization first so an
  // interrupted persistent write cannot leave the old session authorized.
  pw1_mode = 0;
  pw1.is_validated = 0;
  pw3.is_validated = 0;
  rc.is_validated = 0;

  if (pin_create(&pw1, "123456", 6, DATA[0]) < 0) return -1;
  if (pin_set_retries(&rc, DATA[1]) < 0) return -1;
  if (pin_create(&pw3, "12345678", 8, DATA[2]) < 0) return -1;

  return 0;
}

static int openpgp_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(rapdu);
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0x02 && LC != 0x05) EXCEPT(SW_WRONG_LENGTH);

  const char *key_path = get_key_path(DATA[0]);
  if (key_path == NULL) EXCEPT(SW_WRONG_DATA);

  ck_key_t key;
  if (ck_read_key(key_path, &key) < 0) {
    DBG_MSG("Generate/read key failed: p1=%02X key_ref=%02X path=%s\n", P1, DATA[0], key_path);
    return -1;
  }
  DBG_MSG("Generate/read key ok: p1=%02X key_ref=%02X type=%u origin=%u nbits=%u\n", P1, DATA[0], key.meta.type,
          key.meta.origin, key.rsa.nbits);

  if (P1 == 0x80) {
    start_quick_blinking(0);
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

  const int encoded_len = ck_encoded_public_key_length(key.meta.type, true);
  DBG_MSG("Generate pubkey length: type=%u encoded=%d inline_limit=%u\n", key.meta.type, encoded_len,
          APDU_COMMAND_BUFFER_SIZE - 2);
  if (encoded_len < 0 || encoded_len + 2 > MAX_PUBKEY_RESPONSE_LENGTH) {
    memzero(&key, sizeof(key));
    EXCEPT(SW_WRONG_LENGTH);
  }

  if (encoded_len + 2 > APDU_COMMAND_BUFFER_SIZE) {
    if (openpgp_pke_acquire() < 0) {
      DBG_MSG("Generate pubkey acquire PKE failed\n");
      memzero(&key, sizeof(key));
      return -1;
    }
    uint8_t response[MAX_PUBKEY_RESPONSE_LENGTH];
    response[0] = 0x7F;
    response[1] = 0x49;
    int len = ck_encode_public_key(&key, &response[2], true);
    DBG_MSG("Generate pubkey encoded: len=%d\n", len);
    memzero(&key, sizeof(key));
    if (len < 0) {
      DBG_MSG("Generate pubkey encode failed\n");
      openpgp_pke_release();
      return -1;
    }
    if (pke_buffer_write(0, response, (size_t)(len + 2)) < 0) {
      DBG_MSG("Generate pubkey buffer write failed: len=%d\n", len + 2);
      openpgp_pke_release();
      return -1;
    }
    DBG_MSG("Generate pubkey response streaming: total=%d\n", len + 2);
    apdu_response_source_set((uint32_t)(len + 2), SW_NO_ERROR, openpgp_pke_source_read, openpgp_pke_source_close, NULL);
    LL = 0;
  } else {
    uint8_t *response = RDATA;
    response[0] = 0x7F;
    response[1] = 0x49;
    int len = ck_encode_public_key(&key, &response[2], true);
    DBG_MSG("Generate pubkey inline encoded: len=%d\n", len);
    memzero(&key, sizeof(key));
    if (len < 0) return -1;
    LL = len + 2;
  }
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
  start_quick_blinking(0);

  size_t input_size = LC;
  if (IS_RSA(key.meta.type)) {
    if (LC > PUBLIC_KEY_LENGTH[key.meta.type] * 2 / 5) {
      DBG_MSG("DigestInfo should be not longer than 40%% of the length of the modulus\n");
      EXCEPT(SW_WRONG_LENGTH);
    }
  } else if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
    if (LC > PRIVATE_KEY_LENGTH[key.meta.type]) {
      DBG_MSG("digest should has the same length as the private key\n");
      EXCEPT(SW_WRONG_LENGTH);
    }
    // prepend zeros
    memmove(DATA + (PRIVATE_KEY_LENGTH[key.meta.type] - LC), DATA, LC);
    memzero(DATA, PRIVATE_KEY_LENGTH[key.meta.type] - LC);
    input_size = PRIVATE_KEY_LENGTH[key.meta.type];
  }

  if (ck_read_key(key_path, &key) < 0) {
    ERR_MSG("Read key failed\n");
    return -1;
  }

  DBG_KEY_META(&key.meta);

  uint8_t *result = RDATA;
  if (SIGNATURE_LENGTH[key.meta.type] > APDU_COMMAND_BUFFER_SIZE) {
    if (openpgp_crypto_acquire() < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    result = openpgp_crypto_buffer();
  }
  const int sig_len = ck_sign(&key, DATA, input_size, result);
  if (sig_len < 0) {
    ERR_MSG("Sign failed\n");
    openpgp_crypto_release();
    return -1;
  }

  memzero(&key, sizeof(key));
  int ret = openpgp_set_result(result, sig_len, RDATA);
  if (ret < 0) EXCEPT(SW_WRONG_LENGTH);
  LL = ret > 0 ? 0 : sig_len;

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

// Parse and validate the specific TLV structure for ECC key
static int parse_ecc_key_tlv(const uint8_t *data, size_t data_len, key_type_t key_type, int *public_key_offset) {
  const uint8_t *p = data;
  size_t remaining = data_len;
  int fail;
  size_t length_size;
  uint16_t length;

  // 1. Check Cipher DO (A6)
  if (remaining < 1 || *p != 0xA6) {
    DBG_MSG("Invalid Cipher DO tag\n");
    return -1;
  }
  p++;
  remaining--;

  // Get Cipher DO length
  length = tlv_get_length_safe(p, remaining, &fail, &length_size);
  if (fail || length != remaining - length_size) {
    DBG_MSG("Invalid Cipher DO length\n");
    return -1;
  }
  p += length_size;
  remaining -= length_size;

  // 2. Check Public Key DO (7F49)
  if (remaining < 2 || *p != 0x7F || *(p + 1) != 0x49) {
    DBG_MSG("Invalid Public Key DO\n");
    return -1;
  }
  p += 2; // Skip 7F49 tag
  remaining -= 2;

  // Get Public Key DO length
  length = tlv_get_length_safe(p, remaining, &fail, &length_size);
  if (fail || length != remaining - length_size) {
    DBG_MSG("Invalid Public Key DO length\n");
    return -1;
  }
  p += length_size;
  remaining -= length_size;

  // 3. Check External Public Key (86)
  if (remaining < 1 || *p != 0x86) {
    DBG_MSG("Invalid External Public Key\n");
    return -1;
  }
  p++;
  remaining--;

  // Get External Public Key length
  length = tlv_get_length_safe(p, remaining, &fail, &length_size);
  if (fail || length != remaining - length_size) {
    DBG_MSG("Invalid External Public Key length\n");
    return -1;
  }
  p += length_size;
  remaining -= length_size;

  // 4. Validate key data based on key type
  uint16_t expected_pubkey_len = PUBLIC_KEY_LENGTH[key_type];

  // For Short Weierstrass curves (SECP*, BP*), we need the 0x04 prefix
  if (IS_SHORT_WEIERSTRASS(key_type)) {
    if (length != expected_pubkey_len + 1 || *p != 0x04) {
      DBG_MSG("Invalid public key format for Short Weierstrass curve\n");
      return -1;
    }
    *public_key_offset = (p - data) + 1; // Skip 0x04 prefix
  } else {                               // For X25519
    if (length == expected_pubkey_len + 1 && *p == 0x40) {
      *public_key_offset = (p - data) + 1;
    } else if (length == expected_pubkey_len) {
      *public_key_offset = p - data;
    } else {
      DBG_MSG("Invalid public key length for X25519\n");
      return -1;
    }
  }

  return 0;
}

static int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) {
  const bool final = (CLA & 0x10) == 0;
  const uint8_t *input = DATA;
  uint16_t input_len = LC;

  if (!final || decipher_received > 0) {
    if (openpgp_crypto_acquire() < 0) return -1;
    if ((uint32_t)decipher_received + LC > OPENPGP_CRYPTO_BUFFER_LENGTH) {
      openpgp_decipher_reset();
      openpgp_crypto_release();
      EXCEPT(SW_WRONG_LENGTH);
    }
    memcpy(openpgp_crypto_buffer() + decipher_received, DATA, LC);
    decipher_received += LC;
    DBG_MSG("Decipher chunk: lc=%u total=%u final=%u\n", LC, decipher_received, final);
    if (!final) return 0;
    input = openpgp_crypto_buffer();
    input_len = decipher_received;
  }

#ifndef FUZZ
  if (PW1_MODE82() == 0) {
    openpgp_decipher_reset();
    openpgp_crypto_release();
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  }
#endif

  ck_key_t key;
  if (ck_read_key_metadata(DEC_KEY_PATH, &key.meta) < 0) {
    openpgp_decipher_reset();
    openpgp_crypto_release();
    return -1;
  }

  if (key.meta.touch_policy == TOUCH_POLICY_CACHED || key.meta.touch_policy == TOUCH_POLICY_PERMANENT) OPENPGP_TOUCH();
  if (key.meta.origin == KEY_ORIGIN_NOT_PRESENT) {
    openpgp_decipher_reset();
    openpgp_crypto_release();
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }
  if ((key.meta.usage & ENCRYPT) == 0) {
    openpgp_decipher_reset();
    openpgp_crypto_release();
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  }
  start_quick_blinking(0);

  if (ck_read_key(DEC_KEY_PATH, &key) < 0) {
    ERR_MSG("Read DEC key failed\n");
    openpgp_decipher_reset();
    openpgp_crypto_release();
    return -1;
  }

  DBG_KEY_META(&key.meta);

  if (IS_RSA(key.meta.type)) {
    DBG_MSG("Using RSA key: %d\n", key.meta.type);

    size_t olen;
    uint8_t invalid_padding;

    if (input_len < PUBLIC_KEY_LENGTH[key.meta.type] + 1) {
      DBG_MSG("Incorrect LC\n");
      openpgp_decipher_reset();
      memzero(&key, sizeof(key));
      openpgp_crypto_release();
      EXCEPT(SW_WRONG_LENGTH);
    }
    if (input[0] != 0x00) { // Padding indicator byte (00) for RSA
      DBG_MSG("Incorrect padding indicator\n");
      openpgp_decipher_reset();
      memzero(&key, sizeof(key));
      openpgp_crypto_release();
      EXCEPT(SW_WRONG_DATA);
    }

    uint8_t *result = RDATA;
    if (PUBLIC_KEY_LENGTH[key.meta.type] > APDU_COMMAND_BUFFER_SIZE) {
      if (openpgp_crypto_acquire() < 0) {
        memzero(&key, sizeof(key));
        openpgp_decipher_reset();
        return -1;
      }
      result = openpgp_crypto_buffer();
    }
    if (rsa_decrypt_pkcs_v15(&key.rsa, input + 1, &olen, result, &invalid_padding) < 0) {
      ERR_MSG("Decrypt failed\n");
      openpgp_decipher_reset();
      memzero(&key, sizeof(key));
      openpgp_crypto_release();
      if (invalid_padding) EXCEPT(SW_WRONG_DATA);
      return -1;
    }

    decipher_received = 0;
    memzero(&key, sizeof(key));
    int ret = openpgp_set_result(result, (uint16_t)olen, RDATA);
    if (ret < 0) EXCEPT(SW_WRONG_LENGTH);
    LL = ret > 0 ? 0 : olen;
  } else if (IS_ECC(key.meta.type)) {
    DBG_MSG("Using ECC key: %d\n", key.meta.type);

    // check data and length first
    // A6 xx Cipher DO
    //       7F49 xx Public Key DO
    //               86 xx // External Public Key (04 || x || y, for short Weierstrass; x for X25519)
    if (input_len < 8) {
      DBG_MSG("Incorrect LC\n");
      openpgp_decipher_reset();
      memzero(&key, sizeof(key));
      openpgp_crypto_release();
      EXCEPT(SW_WRONG_LENGTH);
    }

    int public_key_offset;

    // Use our new TLV parsing function to process the data
    if (parse_ecc_key_tlv(input, input_len, key.meta.type, &public_key_offset) < 0) {
      DBG_MSG("Incorrect TLV data structure\n");
      openpgp_decipher_reset();
      memzero(&key, sizeof(key));
      openpgp_crypto_release();
      EXCEPT(SW_WRONG_DATA);
    }

    if (ecdh(key.meta.type, key.ecc.pri, input + public_key_offset, RDATA) < 0) {
      ERR_MSG("ECDH failed\n");
      openpgp_decipher_reset();
      memzero(&key, sizeof(key));
      openpgp_crypto_release();
      return -1;
    }

    LL = PRIVATE_KEY_LENGTH[key.meta.type];
    openpgp_decipher_reset();
    memzero(&key, sizeof(key));
    openpgp_crypto_release();
  } else {
    openpgp_decipher_reset();
    openpgp_crypto_release();
    return -1;
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
  size_t key_index = 0;

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
    if (current_occurrence >= NUM_KEYS) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    if (cert_write_remaining < 0) {
      err = write_file(key_info[current_occurrence].cert_path, DATA, 0, LC, 1);
      if (err < 0) return -1;
      if ((CLA & 0x10) != 0) {
        cert_write_path = key_info[current_occurrence].cert_path;
        cert_write_remaining = MAX_CERT_LENGTH - LC;
      } else {
        current_occurrence = 0;
        openpgp_cert_write_reset();
      }
    } else {
      if (cert_write_path != key_info[current_occurrence].cert_path) {
        openpgp_cert_write_reset();
        EXCEPT(SW_WRONG_DATA);
      }
      if (LC > cert_write_remaining) {
        openpgp_cert_write_reset();
        EXCEPT(SW_WRONG_LENGTH);
      }
      err = append_file(cert_write_path, DATA, LC);
      if (err < 0) return -1;
      cert_write_remaining -= LC;
      if ((CLA & 0x10) == 0) {
        current_occurrence = 0;
        openpgp_cert_write_reset();
      }
    }
    break;

  case TAG_ALGORITHM_ATTRIBUTES_SIG:
    key_index = SIG_KEY_IDX;
    goto handle_algo_attr;
  case TAG_ALGORITHM_ATTRIBUTES_DEC:
    key_index = DEC_KEY_IDX;
    goto handle_algo_attr;
  case TAG_ALGORITHM_ATTRIBUTES_AUT:
    key_index = AUT_KEY_IDX;

  handle_algo_attr:
    if (LC < 1 || LC > MAX_ATTR_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (LC == 1) EXCEPT(SW_WRONG_DATA);

    key_type_t type;
    for (type = SECP256R1 /* i.e., 0 */; type < OPENPGP_ALGO_ATTR_COUNT; ++type) {
      const uint8_t *attr = algo_attr[type];
      if (DATA[0] == ALGO_ID_RSA) { // For RSA, we only care the nbits
        if (LC == attr[0]) {
          if (DATA[2] != 0) {
            DBG_MSG("Invalid attr type\n");
            EXCEPT(SW_WRONG_DATA);
          }
          if (DATA[1] == 0x08) {
            type = RSA2048;
            break;
          } else if (DATA[1] == 0x0C) {
            type = RSA3072;
            break;
          } else if (DATA[1] == 0x10) {
            type = RSA4096;
            break;
          } else {
            DBG_MSG("Invalid attr type\n");
            EXCEPT(SW_WRONG_DATA);
          }
        }
      } else if (LC == attr[0] && memcmp(&attr[2], &DATA[1], LC - 1) == 0) { // OID
        if (IS_SHORT_WEIERSTRASS(type)) {
          if (DATA[0] != (key_info[key_index].key_usage == SIGN ? ALGO_ID_ECDSA : ALGO_ID_ECDH)) continue;
        } else if (DATA[0] != attr[1]) {
          continue;
        }
        break;
      }
    }
    if (type == OPENPGP_ALGO_ATTR_COUNT) {
      DBG_MSG("Invalid attr type\n");
      EXCEPT(SW_WRONG_DATA);
    }
    DBG_MSG("New attr type: %d\n", type);

    const char *key_path = key_info[key_index].key_path;
    if (ck_read_key_metadata(key_path, &meta) < 0) return -1;
    if (type == meta.type) { // Key algorithm attribute unchanged
      DBG_MSG("Attr unchanged\n");
      break;
    }
    if (key_index == DEC_KEY_IDX && type == ED25519) {
      DBG_MSG("DEC key disallows ed25519\n");
      EXCEPT(SW_WRONG_DATA);
    }
    if (key_index != DEC_KEY_IDX && type == X25519) {
      DBG_MSG("SIG/AUT key disallows x25519\n");
      EXCEPT(SW_WRONG_DATA);
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
    CNK_FALLTHROUGH;
  case TAG_KEY_DEC_FINGERPRINT:
    CNK_FALLTHROUGH;
  case TAG_KEY_AUT_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      if (tag == key_info[i].fp_tag) {
        if (openpgp_key_set_fingerprint(key_info[i].key_path, DATA) < 0) return -1;
        break;
      }
    }
    break;

  case TAG_KEY_CA1_FINGERPRINT:
    CNK_FALLTHROUGH;
  case TAG_KEY_CA2_FINGERPRINT:
    CNK_FALLTHROUGH;
  case TAG_KEY_CA3_FINGERPRINT:
    if (LC != KEY_FINGERPRINT_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      if (tag == key_info[i].ca_fp_tag) {
        if (write_attr(DATA_PATH, key_info[i].ca_attr, DATA, KEY_FINGERPRINT_LENGTH) < 0) return -1;
        break;
      }
    }
    break;

  case TAG_KEY_SIG_GENERATION_DATES:
    CNK_FALLTHROUGH;
  case TAG_KEY_DEC_GENERATION_DATES:
    CNK_FALLTHROUGH;
  case TAG_KEY_AUT_GENERATION_DATES:
    if (LC != KEY_DATETIME_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      if (tag == key_info[i].dt_tag) {
        if (openpgp_key_set_datetime(key_info[i].key_path, DATA) < 0) return -1;
        break;
      }
    }
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
    CNK_FALLTHROUGH;
  case TAG_UIF_DEC:
    CNK_FALLTHROUGH;
  case TAG_UIF_AUT:
    if (LC != 2) EXCEPT(SW_WRONG_LENGTH);
    for (size_t i = 0; i < NUM_KEYS; ++i) {
      if (tag != key_info[i].uif_tag) continue;
      if (ck_read_key_metadata(key_info[i].key_path, &meta) < 0) return -1;
      if (get_touch_policy(meta.touch_policy) == UIF_PERMANENTLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
      if (DATA[0] > UIF_PERMANENTLY) EXCEPT(SW_WRONG_DATA);
      meta.touch_policy = UIF_TO_TOUCH_POLICY[DATA[0]];
      if (ck_write_key_metadata(key_info[i].key_path, &meta) < 0) return -1;
      break;
    }
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
  ck_key_t key;
  uint16_t error_sw = SW_NO_ERROR;
  uint8_t key_ref = 0;
  DBG_MSG("Import enter: cla=%02X p1=%02X p2=%02X lc=%u received=%u path=%p\n", CLA, P1, P2, LC, import_received,
          (const void *)import_key_path);
  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);

  // 4D xx Extended Header list
  //       B6/B8/A4 00/03 Control Reference Template
  //       Below are processed by ck_parse_openpgp
  //       7F48 ...
  //       5F48 ...

  if (import_key_path != NULL) {
    if (pke_buffer_read(0, &key, sizeof(key)) < 0) {
      DBG_MSG("Import state restore failed\n");
      openpgp_import_reset();
      return -1;
    }
  } else {
    memzero(&key, sizeof(key));
  }

  if (import_key_path == NULL) {
    const uint8_t *p = DATA;
    int len;
    size_t length_size;

    // Extended Header list
    if (LC < 5) {
      DBG_MSG("Import short lc=%u\n", LC);
      error_sw = SW_WRONG_LENGTH;
      goto fail;
    }
    if (*p++ != 0x4D) {
      DBG_MSG("Import bad first tag=%02X\n", DATA[0]);
      error_sw = SW_WRONG_DATA;
      goto fail;
    }

    if (LC < 2) {
      DBG_MSG("Import bad 4D len: lc=%u\n", LC);
      error_sw = SW_WRONG_LENGTH;
      goto fail;
    }
    if (*p < 0x80) {
      len = *p;
      length_size = 1;
    } else if (*p == 0x81) {
      if (LC < 3) {
        DBG_MSG("Import bad 4D len: need 2-byte len lc=%u\n", LC);
        error_sw = SW_WRONG_LENGTH;
        goto fail;
      }
      len = p[1];
      length_size = 2;
    } else if (*p == 0x82) {
      if (LC < 4) {
        DBG_MSG("Import bad 4D len: need 3-byte len lc=%u\n", LC);
        error_sw = SW_WRONG_LENGTH;
        goto fail;
      }
      len = ((uint16_t)p[1] << 8u) | p[2];
      length_size = 3;
    } else {
      DBG_MSG("Import bad 4D len tag=%02X\n", *p);
      error_sw = SW_WRONG_DATA;
      goto fail;
    }
    if (len < 2) {
      DBG_MSG("Import bad 4D value len=%d size=%u\n", len, (unsigned)length_size);
      error_sw = SW_WRONG_DATA;
      goto fail;
    }
    if ((uint32_t)len + length_size + 1 > CK_KEY_IMPORT_MAX_LENGTH) {
      DBG_MSG("Import total too large: len=%d size=%u total=%u\n", len, (unsigned)length_size,
              (unsigned)(len + length_size + 1));
      error_sw = SW_WRONG_LENGTH;
      goto fail;
    }
    import_total_len = len + length_size + 1;
    p += length_size;

    // Control Reference Template to indicate the private key: B6, B8 or A4
    key_ref = *p;
    const char *key_path = get_key_path(key_ref);
    if (key_path == NULL) {
      DBG_MSG("Import bad key ref=%02X\n", key_ref);
      error_sw = SW_WRONG_DATA;
      goto fail;
    }

    // XX 00 or XX 03 84 01 01, XX = B6 / B8 / A4
    ++p;
    if (p >= DATA + LC || (*p != 0x00 && *p != 0x03) || p + *p + 1 > DATA + LC) {
      DBG_MSG("Import bad CRT len: p_off=%u len=%u lc=%u\n", (unsigned)(p - DATA), *p, LC);
      error_sw = SW_WRONG_DATA;
      goto fail;
    }
    p += *p + 1;

    if (openpgp_pke_acquire() < 0) {
      DBG_MSG("Import could not acquire PKE buffer\n");
      return -1;
    }
    if (ck_read_key_metadata(key_path, &key.meta) < 0) {
      DBG_MSG("Import metadata read failed for %s\n", key_path);
      memzero(&key, sizeof(key));
      openpgp_import_reset();
      return -1;
    }
    ck_parse_openpgp_stream_init(&import_stream, &key, import_total_len - (p - DATA));
    DBG_MSG("Import init: key_ref=%02X type=%u total=%u stream_total=%u header=%u lc=%u\n", key_ref, key.meta.type,
            import_total_len, import_stream.total_len, (unsigned)(p - DATA), LC);
    import_key_path = key_path;
    import_key_ref = key_ref;
    import_received = 0;
  }

  if ((uint32_t)import_received + LC > import_total_len) {
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  }
  const uint16_t chunk_offset = import_received == 0 ? (import_total_len - import_stream.total_len) : 0;
  const uint16_t chunk_len = LC - chunk_offset;
  const bool final = (CLA & 0x10) == 0;
  DBG_MSG("Import chunk: received=%u lc=%u offset=%u len=%u final=%u\n", import_received, LC, chunk_offset, chunk_len,
          final);
  int err = ck_parse_openpgp_stream_update(&import_stream, &key, DATA + chunk_offset, chunk_len, final);
  if (err == KEY_ERR_LENGTH) {
    DBG_MSG("Import length err: phase=%u processed=%u comp_idx=%u comp_off=%u data_len=%u template_end=%u\n",
            import_stream.phase, import_stream.processed, import_stream.comp_idx, import_stream.comp_off,
            import_stream.data_len, import_stream.template_end);
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  } else if (err == KEY_ERR_DATA) {
    DBG_MSG("Import data err: type=%u phase=%u processed=%u comp_idx=%u comp_off=%u data_len=%u template_end=%u\n",
            key.meta.type, import_stream.phase, import_stream.processed, import_stream.comp_idx, import_stream.comp_off,
            import_stream.data_len, import_stream.template_end);
    error_sw = SW_WRONG_DATA;
    goto fail;
  } else if (err < 0) {
    DBG_MSG("Import proc err: err=%d phase=%u processed=%u\n", err, import_stream.phase, import_stream.processed);
    error_sw = SW_UNABLE_TO_PROCESS;
    goto fail;
  }
  import_received += LC;
  if ((CLA & 0x10) != 0) {
    if (pke_buffer_write(0, &key, sizeof(key)) < 0) {
      DBG_MSG("Import state save failed\n");
      goto fail_proc;
    }
    memzero(&key, sizeof(key));
    return 0;
  }
  if (import_received != import_total_len) {
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  }
  if (err != 1) {
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  }
  if (ck_write_key(import_key_path, &key) < 0) {
    goto fail_proc;
  }

  memzero(&key, sizeof(key));
  key_ref = import_key_ref;
  openpgp_import_reset();
  if (key_ref == 0xB6) return reset_sig_counter();
  return 0;

fail:
  memzero(&key, sizeof(key));
  openpgp_import_reset();
  EXCEPT(error_sw);

fail_proc:
  memzero(&key, sizeof(key));
  openpgp_import_reset();
  return -1;
}

static int openpgp_select_data(const CAPDU *capdu, RAPDU *rapdu) {
  current_occurrence = 0;
  if (P1 > 0x02 || P2 != 0x04) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0x06) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x60 || DATA[1] != 0x04 || DATA[2] != 0x5C || DATA[3] != 0x02 || DATA[4] != 0x7F || DATA[5] != 0x21)
    EXCEPT(SW_WRONG_DATA);
  current_occurrence = P1;
  return 0;
}

static int openpgp_get_next_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x7F || P2 != 0x21) EXCEPT(SW_WRONG_P1P2);
  if (LC > 0) EXCEPT(SW_WRONG_LENGTH);
  if (++current_occurrence >= NUM_KEYS) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  return openpgp_send_cert(capdu, rapdu, key_info[current_occurrence].cert_path);
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

static int openpgp_get_challenge(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LE > APDU_BUFFER_SIZE) EXCEPT(SW_WRONG_LENGTH);
  random_buffer(RDATA, LE);
  LL = LE;
  return 0;
}

int openpgp_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (!(CLA == 0x00 ||
        (CLA == 0x10 && ((INS == OPENPGP_INS_PUT_DATA && P1 == 0x7F && P2 == 0x21) || INS == OPENPGP_INS_IMPORT_KEY ||
                         (INS == OPENPGP_INS_PSO && P1 == 0x80 && P2 == 0x86)))))
    EXCEPT(SW_CLA_NOT_SUPPORTED);
  if (INS != OPENPGP_INS_PUT_DATA || P1 != 0x7F || P2 != 0x21) openpgp_cert_write_reset();
  if (INS != OPENPGP_INS_IMPORT_KEY) openpgp_import_reset();
  if (INS != OPENPGP_INS_PSO || P1 != 0x80 || P2 != 0x86) {
    openpgp_decipher_reset();
    openpgp_crypto_release();
  }
  if (INS != OPENPGP_INS_IMPORT_KEY) {
    openpgp_pke_release();
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
    stop_blinking();
    break;
  case OPENPGP_INS_PSO:
    if (P1 == 0x9E && P2 == 0x9A) {
      ret = openpgp_sign_or_auth(capdu, rapdu, true);
      stop_blinking();
      break;
    }
    if (P1 == 0x80 && P2 == 0x86) {
      ret = openpgp_decipher(capdu, rapdu);
      stop_blinking();
      break;
    }
    EXCEPT(SW_WRONG_P1P2);
  case OPENPGP_INS_INTERNAL_AUTHENTICATE:
    ret = openpgp_sign_or_auth(capdu, rapdu, false);
    stop_blinking();
    break;
  case OPENPGP_INS_GET_CHALLENGE:
    ret = openpgp_get_challenge(capdu, rapdu);
    break;
  case OPENPGP_INS_SET_PIN_RETRIES:
    ret = openpgp_set_pin_retries(capdu, rapdu);
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

int openpgp_process_apdu_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu) {
  return apdu_process_streaming_message(rapdu_chaining, capdu, rapdu, apdu_is_get_response(capdu), APDU_BUFFER_SIZE,
                                        openpgp_process_apdu);
}
