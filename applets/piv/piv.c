// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <common.h>
#include <crypto-util.h>
#include <des.h>
#include <device.h>
#include <ecc.h>
#include <key.h>
#include <memzero.h>
#include <pin.h>
#include <piv.h>
#include <rand.h>
#include <rsa.h>

// data object path
#define MAX_DO_PATH_LEN             9
#define PIV_AUTH_CERT_PATH          "piv-pauc" // 9A
#define SIG_CERT_PATH               "piv-sigc" // 9C
#define CARD_AUTH_CERT_PATH         "piv-cauc" // 9E
#define KEY_MANAGEMENT_CERT_PATH    "piv-mntc" // 9D
#define KEY_MANAGEMENT_82_CERT_PATH "piv-82c"  // 82
#define KEY_MANAGEMENT_83_CERT_PATH "piv-83c"  // 83
#define CHUID_PATH                  "piv-chu"  // card holder uid
#define CCC_PATH                    "piv-ccc"  // card capability container
#define PI_PATH                     "piv-pi"   // printed information
#define FINGER_PATH                 "piv-fig"  // card holder fingerprints
#define FACE_PATH                   "piv-face" // card holder facial image

// key tags and path
#define TAG_PIN_KEY_DEFAULT        0x81       // DO if pin or admin key is default
#define AUTH_KEY_PATH              "piv-pauk" // 9A
#define SIG_KEY_PATH               "piv-sigk" // 9C
#define CARD_AUTH_KEY_PATH         "piv-cauk" // 9E
#define KEY_MANAGEMENT_KEY_PATH    "piv-mntk" // 9D
#define KEY_MANAGEMENT_82_KEY_PATH "piv-82"   // 82
#define KEY_MANAGEMENT_83_KEY_PATH "piv-83"   // 83
#define CARD_ADMIN_KEY_PATH        "piv-admk" // 9B

// alg
#define ALGORITHM_EXT_CONFIG_PATH  "piv-alg"
#define ALG_DEFAULT   0x00
#define ALG_TDEA_3KEY 0x03
#define ALG_RSA_2048  0x07
#define ALG_ECC_256   0x11
#define ALG_ECC_384   0x14
#define ALG_ED25519_DEFAULT   0xE0
#define ALG_RSA_3072_DEFAULT  0x05 // defined in NIST SP 800-78-5 (Initial Public Draft)
#define ALG_RSA_4096_DEFAULT  0x16
#define ALG_X25519_DEFAULT    0xE1
#define ALG_SECP256K1_DEFAULT 0x53
#define ALG_SM2_DEFAULT       0x54

#define TDEA_BLOCK_SIZE      8

// tags for general auth
#define TAG_WITNESS   0x80
#define TAG_CHALLENGE 0x81
#define TAG_RESPONSE  0x82
#define TAG_EXP       0x85
#define IDX_WITNESS   (TAG_WITNESS   - 0x80)
#define IDX_CHALLENGE (TAG_CHALLENGE - 0x80)
#define IDX_RESPONSE  (TAG_RESPONSE  - 0x80)
#define IDX_EXP       (TAG_EXP       - 0x80)

// offsets for auth
#define OFFSET_AUTH_STATE     0
#define OFFSET_AUTH_CHALLENGE 1
#define LENGTH_CHALLENGE      16
#define LENGTH_AUTH_STATE     (1 + LENGTH_CHALLENGE)

// states for auth
#define AUTH_STATE_NONE     0
#define AUTH_STATE_EXTERNAL 1
#define AUTH_STATE_MUTUAL   2

#define PIV_TOUCH(cached)                                                                                              \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    uint32_t current_tick = device_get_tick();                                                                         \
    if ((cached) && current_tick > last_touch && current_tick - last_touch < 15000) break;                             \
    switch (wait_for_user_presence(WAIT_ENTRY_CCID)) {                                                                 \
    case USER_PRESENCE_CANCEL:                                                                                         \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      EXCEPT(SW_ERROR_WHILE_RECEIVING);                                                                                \
    }                                                                                                                  \
    last_touch = device_get_tick();                                                                                    \
  } while (0)

static const uint8_t DEFAULT_MGMT_KEY[] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
static const char *DEFAULT_PIN = "123456\xFF\xFF";
static const char *DEFAULT_PUK = "12345678";

static const uint8_t rid[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t pix[] = {0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
static const uint8_t pin_policy[] = {0x40, 0x10};
static uint8_t auth_ctx[LENGTH_AUTH_STATE];
static uint8_t in_admin_status;
static uint8_t pin_is_consumed;
static char piv_do_path[MAX_DO_PATH_LEN]; // data object file path during chaining read/write
static int piv_do_write;                  // -1: not in chaining write, otherwise: count of remaining bytes
static int piv_do_read;                   // -1: not in chaining read mode, otherwise: data object offset
static uint32_t last_touch = UINT32_MAX;
static piv_algorithm_extension_config_t alg_ext_cfg;

static pin_t pin = {.min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-pin"};
static pin_t puk = {.min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-puk"};

static void authenticate_reset(void) {
  auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;
  memset(auth_ctx + OFFSET_AUTH_CHALLENGE, 0, LENGTH_CHALLENGE);
}

static int create_key(const char *path, const key_usage_t usage, const pin_policy_t pin_policy) {
  const ck_key_t key = {.meta = {.type = KEY_TYPE_PKC_END,
                           .origin = KEY_ORIGIN_NOT_PRESENT,
                           .usage = usage,
                           .pin_policy = pin_policy,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  if (ck_write_key(path, &key) < 0) return -1;
  return 0;
}

static key_type_t algo_id_to_key_type(const uint8_t id) {
  switch (id) {
  case ALG_ECC_256:
    return SECP256R1;
  case ALG_ECC_384:
    return SECP384R1;
  case ALG_RSA_2048:
    return RSA2048;
  case ALG_DEFAULT:
  case ALG_TDEA_3KEY:
    return TDEA;
  default:
    break;
  }

  if (alg_ext_cfg.enabled == 0) return KEY_TYPE_PKC_END;
  if (id == alg_ext_cfg.ed25519) return ED25519;
  if (id == alg_ext_cfg.rsa3072) return RSA3072;
  if (id == alg_ext_cfg.rsa4096) return RSA4096;
  if (id == alg_ext_cfg.x25519) return X25519;
  if (id == alg_ext_cfg.secp256k1) return SECP256K1;
  if (id == alg_ext_cfg.sm2) return SM2;
  return KEY_TYPE_PKC_END;
}

static uint8_t key_type_to_algo_id(const key_type_t type) {
  switch (type) {
  case SECP256R1:
    return ALG_ECC_256;
  case SECP384R1:
    return ALG_ECC_384;
  case RSA2048:
    return ALG_RSA_2048;
  case ED25519:
    return alg_ext_cfg.ed25519;
  case X25519:
    return alg_ext_cfg.x25519;
  case SECP256K1:
    return alg_ext_cfg.secp256k1;
  case SM2:
    return alg_ext_cfg.sm2;
  case RSA3072:
    return alg_ext_cfg.rsa3072;
  case RSA4096:
    return alg_ext_cfg.rsa4096;
  case TDEA:
    return ALG_TDEA_3KEY;
  case KEY_TYPE_PKC_END:
  default:
    return ALG_DEFAULT;
  }
}

int piv_security_status_check(uint8_t id __attribute__((unused)), const key_meta_t *meta) {
  switch (meta->pin_policy) {
    case PIN_POLICY_NEVER:
      break;
    default:
    case PIN_POLICY_ONCE:
      if (pin.is_validated == 0) return 1;
      break;
    case PIN_POLICY_ALWAYS:
      if (pin.is_validated == 0 || pin_is_consumed) return 1;
      break;
  }
  pin_is_consumed = 1;
  return 0;
}

void piv_poweroff(void) {
  in_admin_status = 0;
  pin_is_consumed = 0;
  pin.is_validated = 0;
  puk.is_validated = 0;
  piv_do_write = -1;
  piv_do_read = -1;
  piv_do_path[0] = '\0';
}

int piv_install(const uint8_t reset) {
  piv_poweroff();
  if (!reset && get_file_size(ALGORITHM_EXT_CONFIG_PATH) >= 0) {
    if (read_file(ALGORITHM_EXT_CONFIG_PATH, &alg_ext_cfg, 0, sizeof(alg_ext_cfg)) < 0) return -1;
    return 0;
  }

  // objects
  if (write_file(PIV_AUTH_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(SIG_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(KEY_MANAGEMENT_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(CARD_AUTH_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(KEY_MANAGEMENT_82_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(KEY_MANAGEMENT_83_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(PI_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(FINGER_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(FACE_PATH, NULL, 0, 0, 1) < 0) return -1;
  uint8_t ccc_tpl[] = {0x53, 0x33, 0xf0, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x01, 0x21,
                       0xf2, 0x01, 0x21, 0xf3, 0x00, 0xf4, 0x01, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7,
                       0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00};
  random_buffer(ccc_tpl + 4, 21);
  if (write_file(CCC_PATH, ccc_tpl, 0, sizeof(ccc_tpl), 1) < 0) return -1;
  uint8_t chuid_tpl[] = {0x53, 0x3b, 0x30, 0x19, 0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d, 0x83,
                         0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 0x10, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35,
                         0x08, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3e, 0x00, 0xfe, 0x00};
  random_buffer(chuid_tpl + 31, 16);
  if (write_file(CHUID_PATH, chuid_tpl, 0, sizeof(chuid_tpl), 1) < 0) return -1;

  // keys
  if (create_key(AUTH_KEY_PATH, SIGN, PIN_POLICY_ONCE) < 0) return -1;
  if (create_key(SIG_KEY_PATH, SIGN, PIN_POLICY_ONCE) < 0) return -1;
  if (create_key(KEY_MANAGEMENT_KEY_PATH, KEY_AGREEMENT, PIN_POLICY_ONCE) < 0) return -1;
  if (create_key(CARD_AUTH_KEY_PATH, SIGN, PIN_POLICY_NEVER) < 0) return -1;
  if (create_key(KEY_MANAGEMENT_82_KEY_PATH, KEY_AGREEMENT, PIN_POLICY_ONCE) < 0) return -1;
  if (create_key(KEY_MANAGEMENT_83_KEY_PATH, KEY_AGREEMENT, PIN_POLICY_ONCE) < 0) return -1;

  // TDEA admin key
  ck_key_t admin_key = {.meta = {.type = TDEA,
                                 .origin = KEY_ORIGIN_GENERATED,
                                 .usage = ENCRYPT,
                                 .pin_policy = PIN_POLICY_NEVER,
                                 .touch_policy = TOUCH_POLICY_NEVER}};
  memcpy(admin_key.data, DEFAULT_MGMT_KEY, 24);
  if (ck_write_key(CARD_ADMIN_KEY_PATH, &admin_key) < 0) return -1;
  const uint8_t tmp = 0x01;
  if (write_attr(CARD_ADMIN_KEY_PATH, TAG_PIN_KEY_DEFAULT, &tmp, sizeof(tmp)) < 0) return -1;

  // PIN data
  if (pin_create(&pin, DEFAULT_PIN, 8, 3) < 0) return -1;
  if (write_attr(pin.path, TAG_PIN_KEY_DEFAULT, &tmp, sizeof(tmp)) < 0) return -1;
  if (pin_create(&puk, DEFAULT_PUK, 8, 3) < 0) return -1;
  if (write_attr(puk.path, TAG_PIN_KEY_DEFAULT, &tmp, sizeof(tmp)) < 0) return -1;
  
  if (get_file_size(ALGORITHM_EXT_CONFIG_PATH) == sizeof(alg_ext_cfg))  return 0;
  // Algorithm extensions
  alg_ext_cfg.enabled = 1;
  alg_ext_cfg.ed25519 = ALG_ED25519_DEFAULT;
  alg_ext_cfg.rsa3072 = ALG_RSA_3072_DEFAULT;
  alg_ext_cfg.rsa4096 = ALG_RSA_4096_DEFAULT;
  alg_ext_cfg.x25519 = ALG_X25519_DEFAULT;
  alg_ext_cfg.secp256k1 = ALG_SECP256K1_DEFAULT;
  alg_ext_cfg.sm2 = ALG_SM2_DEFAULT;
  if (write_file(ALGORITHM_EXT_CONFIG_PATH, &alg_ext_cfg, 0, sizeof(alg_ext_cfg), 1) < 0) return -1;

  return 0;
}

static const char *get_object_path_by_tag(const uint8_t tag) {
  // Part 1 Table 3 0x5FC1XX
  switch (tag) {
  case 0x05: // X.509 Certificate for PIV Authentication
    return PIV_AUTH_CERT_PATH;
  case 0x0A: // X.509 Certificate for Digital Signature
    return SIG_CERT_PATH;
  case 0x0B: // X.509 Certificate for Key Management
    return KEY_MANAGEMENT_CERT_PATH;
  case 0x01: // X.509 Certificate for Card Authentication
    return CARD_AUTH_CERT_PATH;
  case 0x0D: // Retired X.509 Certificate for Key Management 1
    return KEY_MANAGEMENT_82_CERT_PATH;
  case 0x0E: // Retired X.509 Certificate for Key Management 2
    return KEY_MANAGEMENT_83_CERT_PATH;
  case 0x02: // Card Holder Unique Identifier
    return CHUID_PATH;
  case 0x07: // Card Capability Container
    return CCC_PATH;
  case 0x09: // Printed Information
    return PI_PATH;
  case 0x03: // Fingerprints
    return FINGER_PATH;
  case 0x08: // Facial Images
    return FACE_PATH;
  default:
    return NULL;
  }
}

static uint16_t get_capacity_by_tag(const uint8_t tag) {
  // Part 1 Table 7 Container Minimum Capacity, 5FC1XX
  switch (tag) {
  case 0x05: // X.509 Certificate for PIV Authentication (9A)
  case 0x0A: // X.509 Certificate for Digital Signature (9C)
  case 0x0B: // X.509 Certificate for Key Management (9D)
  case 0x01: // X.509 Certificate for Card Authentication (9E)
  case 0x0D: // Retired X.509 Certificate for Key Management 1 (82)
  case 0x0E: // Retired X.509 Certificate for Key Management 2 (83)
    return 3000;
  case 0x02: // Card Holder Unique Identifier
    return 2916;
  case 0x07: // Card Capability Container
    return 287;
  case 0x09: // Printed Information
    return 245;
  case 0x03: // Fingerprints
  case 0x08: // Facial Images
    return 512;
  default:
    return 0;
  }
}

static int piv_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  // reset internal states
  in_admin_status = 0;
  pin_is_consumed = 0;
  pin.is_validated = 0;
  puk.is_validated = 0;
  piv_do_write = -1;
  piv_do_read = -1;
  authenticate_reset();

  RDATA[0] = 0x61;
  RDATA[1] = 6 + sizeof(pix) + sizeof(rid);
  RDATA[2] = 0x4F;
  RDATA[3] = sizeof(pix);
  memcpy(RDATA + 4, pix, sizeof(pix));
  RDATA[4 + sizeof(pix)] = 0x79;
  RDATA[5 + sizeof(pix)] = 2 + sizeof(rid);
  RDATA[6 + sizeof(pix)] = 0x4F;
  RDATA[7 + sizeof(pix)] = sizeof(rid);
  memcpy(RDATA + 8 + sizeof(pix), rid, sizeof(rid));
  LL = 8 + sizeof(pix) + sizeof(rid);

  return 0;
}

static int piv_get_large_data(const CAPDU *capdu, RAPDU *rapdu, const char *path, const int size) {
  // piv_do_read should equal to -1 before calling this function

  const int read = read_file(path, RDATA, 0, LE); // return first chunk
  if (read < 0) return -1;
  LL = read;
  DBG_MSG("read file %s, expected: %d, read: %d\n", path, LE, read);
  const int remains = size - read;
  if (remains == 0) { // sent all
    SW = SW_NO_ERROR;
  } else {
    // save state for GET REPONSE command
    strcpy(piv_do_path, path);
    piv_do_read = read;
    if (remains > 0xFF)
      SW = 0x61FF;
    else
      SW = 0x6100 + remains;
  }
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
static int piv_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x5C) EXCEPT(SW_WRONG_DATA);
  if (DATA[1] + 2 != LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[1] == 1) {
    if (DATA[2] != 0x7E) EXCEPT(SW_FILE_NOT_FOUND);
    // For the Discovery Object, the 0x7E template nests two data elements:
    // 1) tag 0x4F contains the AID of the PIV Card Application and
    // 2) tag 0x5F2F lists the PIN Usage Policy.
    RDATA[0] = 0x7E;
    RDATA[1] = 5 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
    RDATA[2] = 0x4F;
    RDATA[3] = sizeof(rid) + sizeof(pix);
    memcpy(RDATA + 4, rid, sizeof(rid));
    memcpy(RDATA + 4 + sizeof(rid), pix, sizeof(pix));
    RDATA[4 + sizeof(rid) + sizeof(pix)] = 0x5F;
    RDATA[5 + sizeof(rid) + sizeof(pix)] = 0x2F;
    RDATA[6 + sizeof(rid) + sizeof(pix)] = sizeof(pin_policy);
    memcpy(RDATA + 7 + sizeof(rid) + sizeof(pix), pin_policy, sizeof(pin_policy));
    LL = 7 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
  } else if (DATA[1] == 3) {
    if (LC != 5 || DATA[2] != 0x5F || DATA[3] != 0xC1) EXCEPT(SW_FILE_NOT_FOUND);
    // Reading Printed Information, Fingerprints, and Facial Images requires PIN verification
    if ((DATA[4] == 0x09 || DATA[4] == 0x03 || DATA[4] == 0x08) && 
      !pin.is_validated) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    const char *path = get_object_path_by_tag(DATA[4]);
    if (path == NULL) EXCEPT(SW_FILE_NOT_FOUND);
    const int size = get_file_size(path);
    if (size < 0) return -1;
    if (size == 0) EXCEPT(SW_FILE_NOT_FOUND);
    return piv_get_large_data(capdu, rapdu, path, size);
  } else
    EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

static int piv_get_data_response(const CAPDU *capdu, RAPDU *rapdu) {
  if (piv_do_read == -1) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  if (piv_do_path[0] == '\0') return -1;

  const int size = get_file_size(piv_do_path);
  if (size < 0) return -1;
  const int read = read_file(piv_do_path, RDATA, piv_do_read, LE);
  if (read < 0) return -1;
  DBG_MSG("continue to read file %s, expected: %d, read: %d\n", piv_do_path, LE, read);
  LL = read;
  piv_do_read += read;

  const int remains = size - piv_do_read;
  if (remains == 0) { // sent all
    piv_do_read = -1;
    piv_do_path[0] = '\0';
    SW = SW_NO_ERROR;
  } else if (remains > 0xFF)
    SW = 0x61FF;
  else
    SW = 0x6100 + remains;

  return 0;
}

static int piv_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 && P1 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (P1 == 0xFF) {
    if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
    pin.is_validated = 0;
    pin_is_consumed = 0;
    return 0;
  }
  if (LC == 0) {
    if (pin.is_validated) return 0;
    const int retries = pin_get_retries(&pin);
    if (retries < 0) return -1;
    EXCEPT(SW_PIN_RETRIES + retries);
  }
  if (LC != 8) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  const int err = pin_verify(&pin, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_PIN_RETRIES + ctr);
  pin_is_consumed = 0;
  return 0;
}

static int piv_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  pin_t *p;
  const char *default_val;
  if (P2 == 0x80)
    p = &pin, default_val = DEFAULT_PIN;
  else if (P2 == 0x81)
    p = &puk, default_val = DEFAULT_PUK;
  else
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(p, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_PIN_RETRIES + ctr);
  err = pin_update(p, DATA + 8, 8);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  const uint8_t is_default = !memcmp(DATA + 8, default_val, 8);
  if (write_attr(p->path, TAG_PIN_KEY_DEFAULT, &is_default, sizeof(is_default)) < 0) return -1;
  return 0;
}

static int piv_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(&puk, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(0x63C0 + ctr);
  err = pin_update(&pin, DATA + 8, 8);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static const char *get_key_path(const uint8_t id) {
  switch (id) {
  case 0x9A:
    return AUTH_KEY_PATH;
  case 0x9B:
    return CARD_ADMIN_KEY_PATH;
  case 0x9C:
    return SIG_KEY_PATH;
  case 0x9D:
    return KEY_MANAGEMENT_KEY_PATH;
  case 0x9E:
    return CARD_AUTH_KEY_PATH;
  case 0x82:
    return KEY_MANAGEMENT_82_KEY_PATH;
  case 0x83:
    return KEY_MANAGEMENT_83_KEY_PATH;
  default:
    return NULL;
  }
}

static int piv_general_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC == 0) EXCEPT(SW_WRONG_LENGTH);
  if (*DATA != 0x7C) EXCEPT(SW_WRONG_DATA);

  const char *key_path = get_key_path(P2);
  if (key_path == NULL) {
    DBG_MSG("Invalid key ref\n");
    EXCEPT(SW_WRONG_P1P2);
  }

  ck_key_t key;
  if (P2 == 0x9B) { // Card admin
    if (P1 != ALG_DEFAULT && P1 != ALG_TDEA_3KEY) {
      DBG_MSG("Invalid P1/P2 for card admin key\n");
      EXCEPT(SW_WRONG_P1P2);
    }
  }
  if (ck_read_key_metadata(key_path, &key.meta) < 0) return -1;
  DBG_KEY_META(&key.meta);

  // empty slot after reset
  if (key.meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  if (algo_id_to_key_type(P1) != key.meta.type) {
    DBG_MSG("The value of P1 mismatches the key specified by P2\n");
    EXCEPT(SW_WRONG_P1P2);
  }

  uint16_t pos[6] = {0}, len[6] = {0};
  int fail = 0;
  size_t length_size = 0;
  tlv_get_length_safe(DATA + 1, LC - 1, &fail, &length_size);
  if (fail) EXCEPT(SW_WRONG_LENGTH);
  uint16_t dat_pos = 1 + length_size;
  while (dat_pos < LC) {
    const uint8_t tag = DATA[dat_pos++];
    if (tag != 0x80 && tag != 0x81 && tag != 0x82 && tag != 0x85) EXCEPT(SW_WRONG_DATA);
    len[tag - 0x80] = tlv_get_length_safe(DATA + dat_pos, LC - dat_pos, &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    dat_pos += length_size;
    pos[tag - 0x80] = dat_pos;
    dat_pos += len[tag - 0x80];
    DBG_MSG("Tag %02X, pos: %d, len: %d\n", tag, pos[tag - 0x80], len[tag - 0x80]);
  }

  // User presence test
  if (key.meta.touch_policy == TOUCH_POLICY_CACHED || key.meta.touch_policy == TOUCH_POLICY_ALWAYS) PIV_TOUCH(key.meta.touch_policy == TOUCH_POLICY_CACHED);

  //
  // CASE 1 - INTERNAL AUTHENTICATE (Key ID = 9A / 9E)
  // Authenticates the CARD to the CLIENT and is also used for KEY ESTABLISHMENT
  // and DIGITAL SIGNATURES. Documented in SP800-73-4 Part 2 Appendix A.3
  //
  // OR - Signature Generation (Key ID = 9C)
  // Documented in SP800-73-4 Part 2 Appendix A.4
  //
  // OR - KEY ESTABLISHMENT (Key ID = 9D, RSA only)
  // Documented in SP800-73-4 Part 2 Appendix A.5
  //

  // > Client application sends a challenge to the PIV Card Application
  if (pos[IDX_WITNESS] == 0 && pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] > 0 && pos[IDX_RESPONSE] > 0 &&
      len[IDX_RESPONSE] == 0) {
    DBG_MSG("Case 1\n");
    authenticate_reset();
#ifndef FUZZ
    if (piv_security_status_check(P2, &key.meta) != 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

    if ((IS_SHORT_WEIERSTRASS(key.meta.type) && len[IDX_CHALLENGE] > PRIVATE_KEY_LENGTH[key.meta.type]) ||
        (IS_RSA(key.meta.type) && len[IDX_CHALLENGE] != PUBLIC_KEY_LENGTH[key.meta.type])) {
      DBG_MSG("Incorrect challenge data length\n");
      EXCEPT(SW_WRONG_LENGTH);
    }
    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    start_quick_blinking(0);

    if (IS_RSA(key.meta.type)) {
      // The input has been padded
      DBG_MSG("e: ");
      PRINT_HEX(key.rsa.e, E_LENGTH);
      DBG_MSG("p: ");
      PRINT_HEX(key.rsa.p, PRIVATE_KEY_LENGTH[key.meta.type]);
      DBG_MSG("q: ");
      PRINT_HEX(key.rsa.q, PRIVATE_KEY_LENGTH[key.meta.type]);
      if (rsa_private(&key.rsa, DATA + pos[IDX_CHALLENGE], RDATA + 8) < 0) {
        ERR_MSG("Sign failed\n");
        memzero(&key, sizeof(key));
        return -1;
      }
      RDATA[0] = 0x7C;
      RDATA[1] = 0x82;
      RDATA[2] = HI(SIGNATURE_LENGTH[key.meta.type] + 4);
      RDATA[3] = LO(SIGNATURE_LENGTH[key.meta.type] + 4);
      RDATA[4] = TAG_RESPONSE;
      RDATA[5] = 0x82;
      RDATA[6] = HI(SIGNATURE_LENGTH[key.meta.type]);
      RDATA[7] = LO(SIGNATURE_LENGTH[key.meta.type]);
      LL = SIGNATURE_LENGTH[key.meta.type] + 8;

      memzero(&key, sizeof(key));
    } else if (IS_ECC(key.meta.type)) {
      if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
        // prepend zeros
        memmove(DATA + pos[IDX_CHALLENGE] + (PRIVATE_KEY_LENGTH[key.meta.type] - len[IDX_CHALLENGE]),
                DATA + pos[IDX_CHALLENGE],
                len[IDX_CHALLENGE]);
        memzero(DATA + pos[IDX_CHALLENGE], PRIVATE_KEY_LENGTH[key.meta.type] - len[IDX_CHALLENGE]);
      }
      int sig_len = ck_sign(&key, DATA + pos[IDX_CHALLENGE], PRIVATE_KEY_LENGTH[key.meta.type], RDATA + 4);
      if (sig_len < 0) {
        ERR_MSG("Sign failed\n");
        return -1;
      }

      if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
        sig_len = (int) ecdsa_sig2ansi(PRIVATE_KEY_LENGTH[key.meta.type], RDATA + 4, RDATA + 4);
      }

      RDATA[0] = 0x7C;
      RDATA[1] = sig_len + 2;
      RDATA[2] = TAG_RESPONSE;
      RDATA[3] = sig_len;
      LL = sig_len + 4;

      memzero(&key, sizeof(key));
    } else return -1;
  }

  //
  // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
  // Authenticates the HOST to the CARD
  //

  // > Client application requests a challenge from the PIV Card Application.
  else if (pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] == 0) {
    DBG_MSG("Case 2\n");
    authenticate_reset();
    in_admin_status = 0;

    if (P2 != 0x9B) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    RDATA[0] = 0x7C;
    RDATA[1] = TDEA_BLOCK_SIZE + 2;
    RDATA[2] = TAG_CHALLENGE;
    RDATA[3] = TDEA_BLOCK_SIZE;
    random_buffer(RDATA + 4, TDEA_BLOCK_SIZE);
    LL = TDEA_BLOCK_SIZE + 4;

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    if (tdes_enc(RDATA + 4, auth_ctx + OFFSET_AUTH_CHALLENGE, key.data) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
  }

  //
  // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
  //

  // > Client application requests a challenge from the PIV Card Application.
  else if (pos[IDX_RESPONSE] > 0 && len[IDX_RESPONSE] > 0) {
    DBG_MSG("Case 3\n");
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL ||
        P2 != 0x9B ||
        TDEA_BLOCK_SIZE != len[IDX_RESPONSE] ||
        memcmp_s(auth_ctx + OFFSET_AUTH_CHALLENGE, DATA + pos[IDX_RESPONSE], TDEA_BLOCK_SIZE) != 0) {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    authenticate_reset();
    in_admin_status = 1;
  }

  //
  // CASE 4 - MUTUAL AUTHENTICATE REQUEST
  //

  // > Client application requests a WITNESS from the PIV Card Application.
  else if (pos[IDX_WITNESS] > 0 && len[IDX_WITNESS] == 0) {
    DBG_MSG("Case 4\n");
    authenticate_reset();
    in_admin_status = 0;

    if (P2 != 0x9B) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
    random_buffer(auth_ctx + OFFSET_AUTH_CHALLENGE, TDEA_BLOCK_SIZE);

    RDATA[0] = 0x7C;
    RDATA[1] = TDEA_BLOCK_SIZE + 2;
    RDATA[2] = TAG_WITNESS;
    RDATA[3] = TDEA_BLOCK_SIZE;
    LL = TDEA_BLOCK_SIZE + 4;

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    if (tdes_enc(auth_ctx + OFFSET_AUTH_CHALLENGE, RDATA + 4, key.data) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
  }

  //
  // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
  //

  // > Client application returns the decrypted witness referencing the original
  // algorithm key reference
  else if (pos[IDX_WITNESS] > 0 && len[IDX_WITNESS] > 0 && pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] > 0) {
    DBG_MSG("Case 5\n");
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL ||
        P2 != 0x9B ||
        TDEA_BLOCK_SIZE != len[IDX_WITNESS] ||
        memcmp_s(auth_ctx + OFFSET_AUTH_CHALLENGE, DATA + pos[IDX_WITNESS], TDEA_BLOCK_SIZE) != 0) {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (TDEA_BLOCK_SIZE != len[IDX_CHALLENGE]) {
      authenticate_reset();
      EXCEPT(SW_WRONG_LENGTH);
    }

    RDATA[0] = 0x7C;
    RDATA[1] = TDEA_BLOCK_SIZE + 2;
    RDATA[2] = TAG_RESPONSE;
    RDATA[3] = TDEA_BLOCK_SIZE;
    LL = TDEA_BLOCK_SIZE + 4;

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    if (tdes_enc(DATA + pos[IDX_CHALLENGE], RDATA + 4, key.data) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));

    authenticate_reset();
    in_admin_status = 1;
  }

  //
  // CASE 6 - ECDH with the PIV KMK
  // Documented in SP800-73-4 Part 2 Appendix A.5
  //

  else if (pos[IDX_RESPONSE] > 0 && len[IDX_RESPONSE] == 0 && pos[IDX_EXP] > 0 && len[IDX_EXP] > 0) {
    DBG_MSG("Case 6\n");
    authenticate_reset();
#ifndef FUZZ
    if (piv_security_status_check(P2, &key.meta) != 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

    if (len[IDX_EXP] != PUBLIC_KEY_LENGTH[key.meta.type] + (IS_SHORT_WEIERSTRASS(key.meta.type) ? 1 : 0)) {
      DBG_MSG("Incorrect data length\n");
      EXCEPT(SW_WRONG_DATA);
    }
    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    start_quick_blinking(0);

    if (ecdh(key.meta.type, key.ecc.pri, DATA + pos[IDX_EXP] + (IS_SHORT_WEIERSTRASS(key.meta.type) ? 1 : 0), RDATA + 4) < 0) {
      ERR_MSG("ECDH failed\n");
      memzero(&key, sizeof(key));
      return -1;
    }

    RDATA[0] = 0x7C;
    RDATA[1] = PRIVATE_KEY_LENGTH[key.meta.type] + 2;
    RDATA[2] = TAG_RESPONSE;
    RDATA[3] = PRIVATE_KEY_LENGTH[key.meta.type];
    LL = PRIVATE_KEY_LENGTH[key.meta.type] + 4;

    memzero(&key, sizeof(key));
  }

  //
  // INVALID CASE
  //
  else {
    authenticate_reset();
    EXCEPT(SW_WRONG_DATA);
  }

  return 0;
}

static int piv_put_data(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);

  if (piv_do_write == -1) { // not in chaining write
    if (LC < 5) EXCEPT(SW_WRONG_LENGTH);
    const int size = LC - 5;
    if (DATA[0] != 0x5C) EXCEPT(SW_WRONG_DATA);
    // Part 1 Table 3 0x5FC1XX
    if (DATA[1] != 3 || DATA[2] != 0x5F || DATA[3] != 0xC1) EXCEPT(SW_FILE_NOT_FOUND);
    const char *path = get_object_path_by_tag(DATA[4]);
    const int max_len = get_capacity_by_tag(DATA[4]);
    if (path == NULL) EXCEPT(SW_FILE_NOT_FOUND);
    if (size > max_len) EXCEPT(SW_WRONG_LENGTH);
    DBG_MSG("write file %s, first chunk length %d\n", path, size);
    const int rc = write_file(path, DATA + 5, 0, size, 1);
    if (rc < 0) return -1;
    if ((CLA & 0x10) != 0 && size < max_len) {
      // enter chaining write mode
      piv_do_write = max_len - size;
      strcpy(piv_do_path, path);
    }
  } else {
    // piv_do_path should be valid
    if (piv_do_path[0] == '\0') return -1;
    // data length exceeded, terminate chaining write
    if (LC > piv_do_write) {
      piv_do_write = -1;
      piv_do_path[0] = '\0';
      EXCEPT(SW_WRONG_LENGTH);
    }
    piv_do_write -= LC;

    DBG_MSG("write file %s, continuous chunk length %d\n", piv_do_path, LC);
    const int rc = append_file(piv_do_path, DATA, LC);
    if (rc < 0) return -1;
    if ((CLA & 0x10) == 0) { // last chunk
      piv_do_write = -1;
      piv_do_path[0] = '\0';
    }
  }

  return 0;
}

static int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (LC < 5) {
    DBG_MSG("Wrong length\n");
    EXCEPT(SW_WRONG_LENGTH);
  }
  if (P1 != 0x00 || DATA[0] != 0xAC || DATA[2] != 0x80 || DATA[3] != 0x01) {
    DBG_MSG("Wrong P1/P2 or tags\n");
    EXCEPT(SW_WRONG_DATA);
  }

  const char *key_path = get_key_path(P2);
  if (key_path == NULL || P2 == 0x9B) {
    DBG_MSG("Invalid key ref\n");
    EXCEPT(SW_WRONG_P1P2);
  }
  ck_key_t key;
  if (ck_read_key(key_path, &key) < 0) return -1;

  key.meta.type = algo_id_to_key_type(DATA[4]);
  if (key.meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_WRONG_DATA);
  start_quick_blinking(0);
  if (ck_generate_key(&key) < 0) return -1;
  const int err = ck_parse_piv_policies(&key, &DATA[5], LC - 5);
  if (err != 0) {
    DBG_MSG("Wrong metadata\n");
    memzero(&key, sizeof(key));
    EXCEPT(SW_WRONG_DATA);
  }
  if (ck_write_key(key_path, &key) < 0) return -1;
  DBG_MSG("Generate key %s successful\n", key_path);
  DBG_KEY_META(&key.meta);

  RDATA[0] = 0x7F;
  RDATA[1] = 0x49;
  const int len = ck_encode_public_key(&key, &RDATA[2], true);
  memzero(&key, sizeof(key));
  if (len < 0) return -1;
  LL = len + 2;

  return 0;
}

static int piv_set_management_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0xFF || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (LC != 27) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x03 || DATA[1] != 0x9B || DATA[2] != 24) EXCEPT(SW_WRONG_DATA);
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (write_file(CARD_ADMIN_KEY_PATH, DATA + 3, 0, 24, 1) < 0) return -1;
  const uint8_t is_default = !memcmp(DATA + 3, DEFAULT_MGMT_KEY, 24);
  if (write_attr(CARD_ADMIN_KEY_PATH, TAG_PIN_KEY_DEFAULT, &is_default, sizeof(is_default)) < 0) return -1;
  return 0;
}

static int piv_reset(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  if (pin_get_retries(&pin) > 0 || pin_get_retries(&puk) > 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  piv_install(1);
  return 0;
}

static int piv_import_asymmetric_key(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  const char *key_path = get_key_path(P2);
  if (key_path == NULL || P2 == 0x9B) {
    DBG_MSG("Unknown key file\n");
    EXCEPT(SW_WRONG_P1P2);
  }
  ck_key_t key;
  if (ck_read_key(key_path, &key) < 0) return -1;

  key.meta.type = algo_id_to_key_type(P1);
  if (key.meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_WRONG_P1P2);

  const int err = ck_parse_piv(&key, DATA, LC);
  if (err == KEY_ERR_LENGTH) {
    DBG_MSG("Wrong length when importing\n");
    EXCEPT(SW_WRONG_LENGTH);
  }
  if (err == KEY_ERR_DATA) {
    DBG_MSG("Wrong data when importing\n");
    EXCEPT(SW_WRONG_DATA);
  }
  if (err < 0) {
    DBG_MSG("Error when importing\n");
    EXCEPT(SW_UNABLE_TO_PROCESS);
  }
  if (ck_write_key(key_path, &key) < 0) {
    memzero(&key, sizeof(key));
    return -1;
  }
  memzero(&key, sizeof(key));

  return 0;
}

static int piv_get_metadata(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  int pos = 0;
  switch (P2) {
    case 0x80:  // PIN
    case 0x81:  // PUK
    {
      const pin_t *p = P2 == 0x80 ? &pin : &puk;
      uint8_t default_value;
      if (read_attr(p->path, TAG_PIN_KEY_DEFAULT, &default_value, 1) < 0) return -1;
      const int default_retries = pin_get_default_retries(p);
      if (default_value < 0) return -1;
      const int retries = pin_get_retries(p);
      if (retries < 0) return -1;

      RDATA[pos++] = 0x01; // Algorithm
      RDATA[pos++] = 0x01;
      RDATA[pos++] = 0xFF;
      RDATA[pos++] = 0x05;
      RDATA[pos++] = 0x01;
      RDATA[pos++] = default_value;
      RDATA[pos++] = 0x06;
      RDATA[pos++] = 0x02;
      RDATA[pos++] = default_retries;
      RDATA[pos++] = retries;
      break;
    }
    case 0x9B:  // Management
    {
      uint8_t default_value;
      if (read_attr(CARD_ADMIN_KEY_PATH, TAG_PIN_KEY_DEFAULT, &default_value, 1) < 0) return -1;
      RDATA[pos++] = 0x01; // Algorithm
      RDATA[pos++] = 0x01;
      RDATA[pos++] = 0x03;
      RDATA[pos++] = 0x02; // Policy
      RDATA[pos++] = 0x02;
      RDATA[pos++] = 0x00;
      RDATA[pos++] = 0x01;
      RDATA[pos++] = 0x05;
      RDATA[pos++] = 0x01;
      RDATA[pos++] = default_value;
      break;
    }
    case 0x9A:  // Authentication
    case 0x9C:  // Signing
    case 0x9D:  // Key Management
    case 0x9E:  // Card Authentication
    case 0x82:  // Retired Key Management 1
    case 0x83:  // Retired Key Management 2
    {
      const char *key_path = get_key_path(P2);
      if (key_path == NULL) EXCEPT(SW_WRONG_P1P2);

      ck_key_t key;
      if (ck_read_key(key_path, &key) < 0) return -1;
      DBG_KEY_META(&key.meta);
      if (key.meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);

      RDATA[pos++] = 0x01; // Algorithm
      RDATA[pos++] = 0x01;
      RDATA[pos++] = key_type_to_algo_id(key.meta.type);
      RDATA[pos++] = 0x02; // Policy
      RDATA[pos++] = 0x02;
      RDATA[pos++] = key.meta.pin_policy;
      RDATA[pos++] = key.meta.touch_policy;
      RDATA[pos++] = 0x03; // Origin
      RDATA[pos++] = 0x01;
      RDATA[pos++] = key.meta.origin;
      RDATA[pos++] = 0x04; // Public
      const int len = ck_encode_public_key(&key, &RDATA[pos], true);
      if (len < 0) {
        memzero(&key, sizeof(key));
        return -1;
      }
      pos += len;
      memzero(&key, sizeof(key));
      break;
    }
    default:
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  }

  LL = pos;

  return 0;
}

static int piv_get_version(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  RDATA[0] = 0x05;
  RDATA[1] = 0x07;
  RDATA[2] = 0x00;
  LL = 3;
  return 0;
}

static int piv_get_serial(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  fill_sn(RDATA);
  LL = 4;
  return 0;
}

static int piv_algorithm_extension(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  if (P1 != 0x01 && P1 != 0x02) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  if (P1 == 0x01) {
    if (read_file(ALGORITHM_EXT_CONFIG_PATH, RDATA, 0, sizeof(alg_ext_cfg)) < 0) return -1;
    LL = sizeof(alg_ext_cfg);
  } else {
    if (LC != sizeof(alg_ext_cfg)) EXCEPT(SW_WRONG_LENGTH);
    if (DATA[0] != 0 && DATA[0] != 1) EXCEPT(SW_WRONG_DATA);
    // We trust the rest data because no dangerous result will be caused even if the IDs are not unique.
    if (write_file(ALGORITHM_EXT_CONFIG_PATH, DATA, 0, sizeof(alg_ext_cfg), 1) < 0) return -1;
    // Effective immediately
    memcpy(&alg_ext_cfg, DATA, sizeof(alg_ext_cfg));
  }

  return 0;
}

int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (!(CLA == 0x00 || (CLA == 0x10 && INS == PIV_INS_PUT_DATA))) EXCEPT(SW_CLA_NOT_SUPPORTED);

  if (INS != PIV_INS_PUT_DATA) piv_do_write = -1;
  if (INS != PIV_INS_GET_DATA_RESPONSE) piv_do_read = -1;

  int ret;
  switch (INS) {
  case PIV_INS_SELECT:
    ret = piv_select(capdu, rapdu);
    break;
  case PIV_INS_GET_DATA:
    ret = piv_get_data(capdu, rapdu);
    break;
  case PIV_INS_GET_DATA_RESPONSE:
    ret = piv_get_data_response(capdu, rapdu);
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
  case PIV_INS_GENERAL_AUTHENTICATE:
    ret = piv_general_authenticate(capdu, rapdu);
    stop_blinking();
    break;
  case PIV_INS_PUT_DATA:
    ret = piv_put_data(capdu, rapdu);
    break;
  case PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR:
    ret = piv_generate_asymmetric_key_pair(capdu, rapdu);
    stop_blinking();
    break;
  case PIV_INS_SET_MANAGEMENT_KEY:
    ret = piv_set_management_key(capdu, rapdu);
    break;
  case PIV_INS_RESET:
    ret = piv_reset(capdu, rapdu);
    break;
  case PIV_INS_IMPORT_ASYMMETRIC_KEY:
    ret = piv_import_asymmetric_key(capdu, rapdu);
    break;
  case PIV_INS_GET_VERSION:
    ret = piv_get_version(capdu, rapdu);
    break;
  case PIV_INS_GET_SERIAL:
    ret = piv_get_serial(capdu, rapdu);
    break;
  case PIV_INS_GET_METADATA:
    ret = piv_get_metadata(capdu, rapdu);
    break;
  case PIV_INS_ALGORITHM_EXTENSION:
    ret = piv_algorithm_extension(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }

  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}

// for testing without authentication
#ifdef TEST
void set_admin_status(const int status) { in_admin_status = status; }
#endif
