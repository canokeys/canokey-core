// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <aes.h>
#include <applet-scratch.h>
#include <common.h>
#include <crypto-util.h>
#include <device-config.h>
#include <device.h>
#include <ecc.h>
#include <key.h>
#include <memzero.h>
#include <ml-kem-768.h>
#include <pin.h>
#include <piv.h>
#include <pke.h>
#include <rand.h>
#include <rsa.h>

#include "piv-attestation.h"

// data object path
// clang-format off
#define MAX_DO_PATH_LEN             9
#define MAX_KEY_PATH_LEN            9
#define CHUID_PATH                  "piv-chu"  // card holder uid
#define CCC_PATH                    "piv-ccc"  // card capability container
#define PI_PATH                     "piv-pi"   // printed information
#define FINGER_PATH                 "piv-fig"  // card holder fingerprints
#define FACE_PATH                   "piv-face" // card holder facial image
#define SECURITY_PATH               "piv-sec"  // security object
#define KEY_HISTORY_PATH            "piv-kh"   // key history object
#define IRIS_PATH                   "piv-iris" // card holder iris images
#define PIV_DO_META_PATH            "piv-do"   // small data object attrs
// clang-format on

// key tags
// clang-format off
#define TAG_PIN_KEY_DEFAULT        0x81       // DO if pin or admin key is default
// clang-format on

// alg
// clang-format off
#define ALG_DEFAULT   0x00
#define ALG_AES_192   0x0A
#define ALG_RSA_2048  0x07
#define ALG_ECC_256   0x11
#define ALG_ECC_384   0x14
#define ALG_ED25519_DEFAULT   0xE0
#define ALG_RSA_3072_DEFAULT  0x05 // defined in NIST SP 800-78-5 (Initial Public Draft)
#define ALG_RSA_4096_DEFAULT  0x16
#define ALG_X25519_DEFAULT    0xE1
#define ALG_MLDSA65_DEFAULT   0xE2
#define ALG_MLKEM768_DEFAULT  0xE3
#define ALG_ED25519_RANDOMIZED 0xFF
#define ALG_SECP256K1_DEFAULT 0x53
#define ALG_SECP521R1_DEFAULT 0x15
#define ALG_SM2_DEFAULT       0x54

#define PIV_METADATA_DIRECTORY_VERSION       0x01
#define PIV_METADATA_DIRECTORY_ENTRY_SIZE    6
#define PIV_METADATA_DIRECTORY_MAX_ENTRIES   24
#define PIV_METADATA_DIRECTORY_HEADER_SIZE   5
#define PIV_METADATA_DIRECTORY_MAX_SIZE      \
  (PIV_METADATA_DIRECTORY_HEADER_SIZE + PIV_METADATA_DIRECTORY_MAX_ENTRIES * PIV_METADATA_DIRECTORY_ENTRY_SIZE)
#define PIV_METADATA_DIRECTORY_FLAG_KEY      0x01
#define PIV_METADATA_DIRECTORY_FLAG_CERT     0x02

enum PIV_STATE {
  PIV_STATE_GET_DATA,
  PIV_STATE_GET_DATA_RESPONSE,
  PIV_STATE_OTHER,
};
static enum PIV_STATE piv_state = PIV_STATE_OTHER;
// clang-format on

/*
 * PIV data object storage model
 *
 * Keep APDU-facing DO metadata in this ROM table, not as pre-created LittleFS
 * files. Optional objects are created lazily on PUT DATA, so unsupported or
 * empty cert/biometric/retired-cert objects do not burn a 512-byte LittleFS
 * metadata block each.
 *
 * LittleFS metadata blocks are 512 bytes on the target. Do not aggregate
 * several large DO attrs on a single file: attr payloads plus LittleFS metadata
 * tags must fit in that one block. Only the host-managed data objects that are
 * normally small live on PIV_DO_META_PATH attrs:
 *
 *   - ADMIN DATA, max 128 bytes.
 *   - PRINTED, only while it is <= 64 bytes. This covers the common 30-byte
 *     host-managed management-key reference:
 *     53 1c 88 1a 89 18 <24-byte management key>.
 *
 * The static assert below intentionally caps those attr payloads to half a
 * metadata block, leaving room for LittleFS tag overhead and future small
 * attrs. Larger PRINTED payloads fall back to PI_PATH. SECURITY and KEY
 * HISTORY are file-backed so they cannot crowd the small-DO metadata block.
 *
 * The card stores these DOs and enforces their read/write access rules only.
 * PIN-only mode and PUK blocking are host decisions. Management-key bytes and
 * PUK retry counters are changed only by their normal PIV commands; the
 * firmware does not infer either from ADMIN DATA/PRINTED contents.
 */
#define PIV_DO_TAG_DISCOVERY 0x0000007Eu
#define PIV_DO_TAG_BITGT 0x00007F61u
#define PIV_DO_TAG_C1(x) (0x005FC100u | (uint32_t)(x))
#define PIV_DO_TAG_FF(x) (0x005FFF00u | (uint32_t)(x))

#define PIV_DO_PRINTED_CAPACITY 245
#define PIV_DO_INLINE_PRINTED_MAX 64
#define PIV_DO_INLINE_ADMIN_DATA_MAX 128

_Static_assert(PIV_DO_INLINE_PRINTED_MAX + PIV_DO_INLINE_ADMIN_DATA_MAX <= 256,
               "piv-do attrs must fit in the reserved half of a 512-byte metadata block");

#define PIV_DO_F_GET_PIN 0x01
#define PIV_DO_F_PUT_ADMIN 0x02
#define PIV_DO_F_CERT 0x04
#define PIV_DO_F_READ_ONLY 0x08
#define PIV_DO_F_SYNTH 0x10
#define PIV_DO_F_INLINE 0x20
#define PIV_DO_F_PRESERVE_RESET 0x40
#define PIV_DO_F_SLOT_CERT 0x80

#define PIV_DO_ATTR_PRINTED 0x90
#define PIV_DO_ATTR_ADMIN_DATA 0x91
// Kept only so reset can delete stale attrs written by older layouts.
#define PIV_DO_ATTR_SECURITY 0x92
#define PIV_DO_ATTR_KEY_HISTORY 0x93

typedef struct {
  const char *path;  // NULL for synthesized or attr-only objects.
  uint16_t capacity; // Maximum stored payload size, not including the 5C tag-list header.
  uint8_t flags;     // Access/storage flags.
  uint8_t attr;      // LittleFS attr id when PIV_DO_F_INLINE is set.
} piv_do_desc_t;

// tags for general auth
// clang-format off
#define TAG_WITNESS   0x80
#define TAG_CHALLENGE 0x81
#define TAG_RESPONSE  0x82
#define TAG_EXP       0x85
#define IDX_WITNESS   (TAG_WITNESS   - 0x80)
#define IDX_CHALLENGE (TAG_CHALLENGE - 0x80)
#define IDX_RESPONSE  (TAG_RESPONSE  - 0x80)

/**
 * Build a 0x7C TLV wrapper in rdata.
 * For short lengths (< 128): header at rdata[0..3], data starts at rdata+4.
 * For extended lengths (>= 128): header at rdata[0..7], data starts at rdata+8.
 * Returns the total response length (header + data_len).
 */
static uint16_t piv_7c_wrap(uint8_t *rdata, uint8_t inner_tag, uint16_t data_len) {
  if (data_len < 128) {
    rdata[0] = 0x7C;
    rdata[1] = (uint8_t)(data_len + 2);
    rdata[2] = inner_tag;
    rdata[3] = (uint8_t)data_len;
    return data_len + 4;
  } else {
    rdata[0] = 0x7C;
    rdata[1] = 0x82;
    rdata[2] = HI(data_len + 4);
    rdata[3] = LO(data_len + 4);
    rdata[4] = inner_tag;
    rdata[5] = 0x82;
    rdata[6] = HI(data_len);
    rdata[7] = LO(data_len);
    return data_len + 8;
  }
}
#define IDX_EXP       (TAG_EXP       - 0x80)
// clang-format on

#define PIV_MAX_7C_RESPONSE_LENGTH (RSA_N_BIT_MAX / 8 + 8)

// offsets for auth
// clang-format off
#define OFFSET_AUTH_STATE     0
#define OFFSET_AUTH_CHALLENGE 1
#define LENGTH_CHALLENGE      16
#define LENGTH_AUTH_STATE     (1 + LENGTH_CHALLENGE)
// clang-format on

// states for auth
// clang-format off
#define AUTH_STATE_NONE     0
#define AUTH_STATE_EXTERNAL 1
#define AUTH_STATE_MUTUAL   2
// clang-format on

#define PIV_TOUCH(cached)                                                                                              \
  do {                                                                                                                 \
    const uint16_t touch_sw = piv_touch((cached));                                                                      \
    if (touch_sw != SW_NO_ERROR) EXCEPT(touch_sw);                                                                      \
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
static uint8_t piv_import_key_id;
static key_type_t piv_import_key_type;
static uint16_t piv_import_len;
static ck_piv_stream_t piv_import_stream;
static uint8_t piv_auth_active;
static uint8_t piv_auth_p1;
static uint8_t piv_auth_p2;
static uint16_t piv_auth_len;
static uint8_t piv_auth_mode;
static uint32_t last_touch = UINT32_MAX;
static piv_algorithm_extension_config_t alg_ext_cfg;
static uint8_t piv_pke_owned;
static uint8_t piv_pke_use;
#define piv_crypto_buffer applet_session_scratch.buffer
#define piv_mldsa_stream_state applet_session_scratch.piv_mldsa
#define piv_mlkem_scratch applet_session_scratch.piv_mlkem
#define piv_ga_stream_state applet_session_scratch.piv_ga_stream

enum {
  PIV_AUTH_MODE_CLASSIC,
  PIV_AUTH_MODE_MLDSA,
  PIV_AUTH_MODE_ED25519_RANDOMIZED,
};

enum {
  PIV_PKE_USE_NONE,
  PIV_PKE_USE_IMPORT,
  PIV_PKE_USE_AUTH,
  PIV_PKE_USE_RESPONSE,
};

static pin_t pin = {.min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-pin"};
static pin_t puk = {.min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-puk"};

static uint16_t piv_touch(bool cached) {
  if (is_nfc()) return SW_NO_ERROR;
  const uint32_t current_tick = device_get_tick();
  if (cached && current_tick > last_touch && current_tick - last_touch < 15000) return SW_NO_ERROR;
  switch (wait_for_user_presence(WAIT_ENTRY_CCID)) {
  case USER_PRESENCE_CANCEL:
  case USER_PRESENCE_TIMEOUT:
    return SW_ERROR_WHILE_RECEIVING;
  default:
    last_touch = device_get_tick();
    return SW_NO_ERROR;
  }
}

static bool piv_algorithm_extension_config_valid(const piv_algorithm_extension_config_t *cfg) {
  if (cfg->enabled > 1) return false;
  if (cfg->enabled == 0) return true;

  const uint8_t ids[] = {cfg->ed25519,   cfg->rsa3072,   cfg->rsa4096, cfg->x25519, cfg->secp256k1,
                         cfg->secp521r1, cfg->sm2,       cfg->mldsa65, cfg->mlkem768};
  for (size_t i = 0; i < sizeof(ids); ++i) {
    switch (ids[i]) {
    case ALG_DEFAULT:
    case ALG_AES_192:
    case ALG_RSA_2048:
    case ALG_ECC_256:
    case ALG_ECC_384:
    case ALG_ED25519_RANDOMIZED:
      return false;
    default:
      break;
    }
    for (size_t j = 0; j < i; ++j)
      if (ids[i] == ids[j]) return false;
  }
  return true;
}

static int piv_algorithm_extension_config_load(piv_algorithm_extension_config_t *cfg) {
  if (piv_platform_algorithm_extension_config_read(cfg) < 0) return -1;
  return piv_algorithm_extension_config_valid(cfg) ? 0 : -1;
}

static void authenticate_reset(void) {
  auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;
  memset(auth_ctx + OFFSET_AUTH_CHALLENGE, 0, LENGTH_CHALLENGE);
}

static int piv_remove_file_if_present(const char *path);

static char piv_hex_nibble(uint8_t x) { return x < 10 ? (char)('0' + x) : (char)('a' + x - 10); }

static int piv_is_regular_key_id(uint8_t id) {
  return id == 0x9A || id == 0x9C || id == 0x9D || id == 0x9E || (id >= 0x82 && id <= 0x95);
}

static int piv_is_asymmetric_key_id(uint8_t id) { return piv_is_regular_key_id(id) || id == 0xF9; }

static int piv_is_key_id(uint8_t id) { return piv_is_asymmetric_key_id(id) || id == 0x9B; }

static pin_policy_t piv_default_pin_policy(uint8_t id) {
  if (id == 0x9C) return PIN_POLICY_ALWAYS;
  if (id == 0x9E || id == 0x9B || id == 0xF9) return PIN_POLICY_NEVER;
  return PIN_POLICY_ONCE;
}

static key_usage_t piv_default_key_usage(uint8_t id) {
  if (id == 0xF9) return SIGN;
  if (id == 0x9B) return ENCRYPT;
  return KEY_USAGE_ANY;
}

static void piv_slot_path(char kind, uint8_t id, char path[MAX_KEY_PATH_LEN]) {
  path[0] = 'p';
  path[1] = 'i';
  path[2] = 'v';
  path[3] = '-';
  path[4] = kind;
  path[5] = piv_hex_nibble(id >> 4u);
  path[6] = piv_hex_nibble(id & 0x0Fu);
  path[7] = '\0';
}

static void piv_key_path(uint8_t id, char path[MAX_KEY_PATH_LEN]) { piv_slot_path('k', id, path); }

static void piv_cert_path(uint8_t id, char path[MAX_DO_PATH_LEN]) { piv_slot_path('c', id, path); }

static void piv_default_key(uint8_t id, ck_key_t *key) {
  ck_key_init_empty(key, KEY_TYPE_PKC_END, piv_default_key_usage(id), piv_default_pin_policy(id), TOUCH_POLICY_NEVER);
}

static int piv_read_key_or_default(uint8_t id, ck_key_t *key, char path[MAX_KEY_PATH_LEN]) {
  if (!piv_is_key_id(id)) return SW_WRONG_P1P2;
  piv_key_path(id, path);
  const int rc = ck_read_key(path, key);
  if (rc >= 0) return SW_NO_ERROR;
  if (id != 0x9B && rc == LFS_ERR_NOENT) {
    piv_default_key(id, key);
    return SW_NO_ERROR;
  }
  return -1;
}

static int piv_read_key_metadata_or_default(uint8_t id, key_meta_t *meta, char path[MAX_KEY_PATH_LEN]) {
  if (!piv_is_key_id(id)) return SW_WRONG_P1P2;
  piv_key_path(id, path);
  const int rc = ck_read_key_metadata(path, meta);
  if (rc >= 0) return SW_NO_ERROR;
  if (id != 0x9B && rc == LFS_ERR_NOENT) {
    ck_key_t key;
    piv_default_key(id, &key);
    *meta = key.meta;
    return SW_NO_ERROR;
  }
  return -1;
}

enum {
  PIV_DO_CODE_DISCOVERY = 0x80,
  PIV_DO_CODE_BITGT,
  PIV_DO_CODE_ADMIN_DATA,
};

static const uint8_t piv_do_codes[] = {
    PIV_DO_CODE_DISCOVERY, PIV_DO_CODE_BITGT, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0C, 0x21,
    PIV_DO_CODE_ADMIN_DATA,
};

static const piv_do_desc_t piv_do_table[] = {
    {NULL, 0, PIV_DO_F_SYNTH | PIV_DO_F_READ_ONLY, 0},
    {NULL, 0, PIV_DO_F_READ_ONLY, 0},
    {CHUID_PATH, 2916, PIV_DO_F_PUT_ADMIN, 0},
    {FINGER_PATH, 512, PIV_DO_F_GET_PIN | PIV_DO_F_PUT_ADMIN, 0},
    {SECURITY_PATH, 245, PIV_DO_F_PUT_ADMIN, 0},
    {CCC_PATH, 287, PIV_DO_F_PUT_ADMIN, 0},
    {FACE_PATH, 512, PIV_DO_F_GET_PIN | PIV_DO_F_PUT_ADMIN, 0},
    {PI_PATH, PIV_DO_PRINTED_CAPACITY, PIV_DO_F_GET_PIN | PIV_DO_F_PUT_ADMIN | PIV_DO_F_INLINE,
     PIV_DO_ATTR_PRINTED},
    {KEY_HISTORY_PATH, 32, PIV_DO_F_PUT_ADMIN, 0},
    {IRIS_PATH, 512, PIV_DO_F_GET_PIN | PIV_DO_F_PUT_ADMIN, 0},
    {NULL, PIV_DO_INLINE_ADMIN_DATA_MAX, PIV_DO_F_PUT_ADMIN | PIV_DO_F_INLINE, PIV_DO_ATTR_ADMIN_DATA},
};
_Static_assert(sizeof(piv_do_codes) == sizeof(piv_do_table) / sizeof(piv_do_table[0]),
               "Every PIV data object needs a tag code");

static const piv_do_desc_t piv_do_cert_desc = {
    NULL, PIV_CERT_OBJECT_MAX_SIZE, PIV_DO_F_PUT_ADMIN | PIV_DO_F_CERT | PIV_DO_F_SLOT_CERT, 0};

// Retired key-management certs follow the contiguous NIST tag range
// 5FC10D..5FC120 and map to slots 82..95.
static int piv_is_retired_cert_tag(uint32_t tag) { return tag >= PIV_DO_TAG_C1(0x0D) && tag <= PIV_DO_TAG_C1(0x20); }

static int piv_cert_tag_to_slot(uint32_t tag, uint8_t *slot) {
  switch (tag) {
  case PIV_DO_TAG_C1(0x01):
    *slot = 0x9E;
    return 0;
  case PIV_DO_TAG_C1(0x05):
    *slot = 0x9A;
    return 0;
  case PIV_DO_TAG_C1(0x0A):
    *slot = 0x9C;
    return 0;
  case PIV_DO_TAG_C1(0x0B):
    *slot = 0x9D;
    return 0;
  case PIV_DO_TAG_FF(0x01):
    *slot = 0xF9;
    return 0;
  default:
    if (!piv_is_retired_cert_tag(tag)) return -1;
    *slot = (uint8_t)(0x82u + tag - PIV_DO_TAG_C1(0x0D));
    return 0;
  }
}

static int piv_do_code_matches(uint8_t code, uint32_t tag) {
  if (code == PIV_DO_CODE_DISCOVERY) return tag == PIV_DO_TAG_DISCOVERY;
  if (code == PIV_DO_CODE_BITGT) return tag == PIV_DO_TAG_BITGT;
  if (code == PIV_DO_CODE_ADMIN_DATA) return tag == PIV_DO_TAG_FF(0x00);
  return tag == PIV_DO_TAG_C1(code);
}

static const piv_do_desc_t *piv_find_do(uint32_t tag) {
  uint8_t slot;
  if (piv_cert_tag_to_slot(tag, &slot) == 0) return &piv_do_cert_desc;
  for (size_t i = 0; i < sizeof(piv_do_table) / sizeof(piv_do_table[0]); ++i) {
    if (piv_do_code_matches(piv_do_codes[i], tag)) return &piv_do_table[i];
  }
  return NULL;
}

static int piv_do_get_path(const piv_do_desc_t *desc, uint32_t tag, char path[MAX_DO_PATH_LEN]) {
  if (desc->path != NULL) {
    strcpy(path, desc->path);
    return 1;
  }
  if ((desc->flags & PIV_DO_F_SLOT_CERT) != 0) {
    uint8_t slot;
    if (piv_cert_tag_to_slot(tag, &slot) < 0) return 0;
    piv_cert_path(slot, path);
    return 1;
  }
  path[0] = '\0';
  return 0;
}

// Returns the attr storage ceiling for DOs that are allowed to inline. A zero
// return means the object is file-backed even if it has a historical stale attr.
static uint16_t piv_do_inline_capacity(const piv_do_desc_t *desc) {
  switch (desc->attr) {
  case PIV_DO_ATTR_PRINTED:
    return PIV_DO_INLINE_PRINTED_MAX;
  case PIV_DO_ATTR_ADMIN_DATA:
    return PIV_DO_INLINE_ADMIN_DATA_MAX;
  default:
    return 0;
  }
}

static int piv_parse_data_object_tag(const CAPDU *capdu, uint32_t *tag, uint16_t *header_len) {
  if (LC < 2) return SW_WRONG_LENGTH;
  if (DATA[0] != 0x5C) return SW_WRONG_DATA;
  const uint8_t tag_len = DATA[1];
  if (tag_len == 0 || tag_len > 3 || (uint16_t)(2 + tag_len) > LC) return SW_WRONG_LENGTH;

  uint32_t parsed = 0;
  for (uint8_t i = 0; i < tag_len; ++i) {
    parsed = (parsed << 8u) | DATA[2 + i];
  }
  *tag = parsed;
  *header_len = 2 + tag_len;
  return SW_NO_ERROR;
}

static int piv_clear_attr_if_present(const char *path, uint8_t attr);
static int piv_remove_do_meta_if_empty(void);

static int piv_do_write_inline(const piv_do_desc_t *desc, const uint8_t *data, uint16_t len) {
  if (len == 0) {
    if (piv_clear_attr_if_present(PIV_DO_META_PATH, desc->attr) < 0) return -1;
    if (piv_remove_do_meta_if_empty() < 0) return -1;
  } else {
    if (write_file(PIV_DO_META_PATH, NULL, 0, 0, 0) < 0) return -1;
    if (write_attr(PIV_DO_META_PATH, desc->attr, data, len) < 0) return -1;
  }
  if (desc->path != NULL) {
    const int remove_rc = remove_file(desc->path);
    if (remove_rc < 0 && remove_rc != LFS_ERR_NOENT) return -1;
  }
  return 0;
}

static int piv_remove_file_if_present(const char *path) {
  const int rc = remove_file(path);
  return (rc == 0 || rc == LFS_ERR_NOENT) ? 0 : -1;
}

static int piv_clear_attr_if_present(const char *path, uint8_t attr) {
  const int rc = remove_attr(path, attr);
  return (rc == 0 || rc == LFS_ERR_NOENT || rc == LFS_ERR_NOATTR) ? 0 : -1;
}

static int piv_attr_present(const char *path, uint8_t attr) {
  uint8_t probe;
  const int rc = read_attr(path, attr, &probe, 0);
  if (rc >= 0) return 1;
  if (rc == LFS_ERR_NOENT || rc == LFS_ERR_NOATTR) return 0;
  return -1;
}

static int piv_remove_do_meta_if_empty(void) {
  const int printed = piv_attr_present(PIV_DO_META_PATH, PIV_DO_ATTR_PRINTED);
  if (printed != 0) return printed < 0 ? -1 : 0;
  const int admin_data = piv_attr_present(PIV_DO_META_PATH, PIV_DO_ATTR_ADMIN_DATA);
  if (admin_data != 0) return admin_data < 0 ? -1 : 0;
  return piv_remove_file_if_present(PIV_DO_META_PATH);
}

static int piv_clear_file_do_storage(void) {
  for (size_t i = 0; i < sizeof(piv_do_table) / sizeof(piv_do_table[0]); ++i) {
    if ((piv_do_table[i].flags & PIV_DO_F_PRESERVE_RESET) != 0) continue;
    if (piv_do_table[i].path != NULL && piv_remove_file_if_present(piv_do_table[i].path) < 0) return -1;
  }

  char cert_path[MAX_DO_PATH_LEN];
  char key_path[MAX_KEY_PATH_LEN];
  for (uint16_t id = 0; id <= UINT8_MAX; ++id) {
    if (!piv_is_regular_key_id((uint8_t)id)) continue;
    piv_cert_path((uint8_t)id, cert_path);
    if (piv_remove_file_if_present(cert_path) < 0) return -1;
    piv_key_path((uint8_t)id, key_path);
    if (piv_remove_file_if_present(key_path) < 0) return -1;
  }
  return 0;
}

static int piv_clear_inline_do_storage(void) {
  static const uint8_t attrs[] = {
      PIV_DO_ATTR_PRINTED,
      PIV_DO_ATTR_ADMIN_DATA,
      PIV_DO_ATTR_SECURITY,
      PIV_DO_ATTR_KEY_HISTORY,
  };
  char admin_key_path[MAX_KEY_PATH_LEN];
  piv_key_path(0x9B, admin_key_path);
  for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); ++i) {
    if (piv_clear_attr_if_present(PIV_DO_META_PATH, attrs[i]) < 0) return -1;
    if (piv_clear_attr_if_present(admin_key_path, attrs[i]) < 0) return -1;
  }
  return piv_remove_file_if_present(PIV_DO_META_PATH);
}

static bool piv_littlefs_state_present(void) {
  key_meta_t meta;
  uint8_t default_value;
  char admin_key_path[MAX_KEY_PATH_LEN];
  piv_key_path(0x9B, admin_key_path);
  return ck_read_key_metadata(admin_key_path, &meta) >= 0 &&
         read_attr(admin_key_path, TAG_PIN_KEY_DEFAULT, &default_value, sizeof(default_value)) ==
             sizeof(default_value) &&
         get_file_size(CHUID_PATH) >= 0 && get_file_size(CCC_PATH) >= 0 && pin_get_size(&pin) == 8 &&
         pin_get_retries(&pin) >= 0 && pin_get_default_retries(&pin) >= 0 &&
         read_attr(pin.path, TAG_PIN_KEY_DEFAULT, &default_value, sizeof(default_value)) == sizeof(default_value) &&
         pin_get_size(&puk) == 8 && pin_get_retries(&puk) >= 0 && pin_get_default_retries(&puk) >= 0 &&
         read_attr(puk.path, TAG_PIN_KEY_DEFAULT, &default_value, sizeof(default_value)) == sizeof(default_value);
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
  case ALG_AES_192:
    return AES192;
  default:
    break;
  }

  if (alg_ext_cfg.enabled == 0) return KEY_TYPE_PKC_END;
  if (id == alg_ext_cfg.ed25519) return ED25519;
  if (id == alg_ext_cfg.rsa3072) return RSA3072;
  if (id == alg_ext_cfg.rsa4096) return RSA4096;
  if (id == alg_ext_cfg.x25519) return X25519;
  if (id == alg_ext_cfg.secp256k1) return SECP256K1;
  if (id == alg_ext_cfg.secp521r1) return SECP521R1;
  if (id == alg_ext_cfg.sm2) return SM2;
  if (id == alg_ext_cfg.mldsa65) return MLDSA65;
  if (id == alg_ext_cfg.mlkem768) return MLKEM768;
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
  case MLDSA65:
    return alg_ext_cfg.mldsa65;
  case MLKEM768:
    return alg_ext_cfg.mlkem768;
  case SECP256K1:
    return alg_ext_cfg.secp256k1;
  case SECP521R1:
    return alg_ext_cfg.secp521r1;
  case SM2:
    return alg_ext_cfg.sm2;
  case RSA3072:
    return alg_ext_cfg.rsa3072;
  case RSA4096:
    return alg_ext_cfg.rsa4096;
  case AES192:
    return ALG_AES_192;
  case KEY_TYPE_PKC_END:
  default:
    return ALG_DEFAULT;
  }
}

static int piv_mlkem_public_read(void *ctx, uint32_t offset, uint8_t *out, uint16_t len) {
  piv_mlkem_scratch_t *scratch = (piv_mlkem_scratch_t *)ctx;
  const size_t prefix_len = scratch->public_key.prefix_len;
  size_t copied = 0;

  if (offset < prefix_len) {
    const size_t n = MIN((size_t)len, prefix_len - offset);
    memcpy(out, scratch->public_key.prefix + offset, n);
    copied += n;
    offset += (uint32_t)n;
  }
  if (copied < len) {
    const uint32_t public_offset = offset - (uint32_t)prefix_len;
    if (public_offset > MLKEM768_PUBLIC_KEY_BYTES || len - copied > MLKEM768_PUBLIC_KEY_BYTES - public_offset)
      return -1;
    memcpy(out + copied, scratch->public_key.public_key + public_offset, len - copied);
    copied = len;
  }
  return (int)copied;
}

static void piv_mlkem_public_close(void *ctx) { memzero(ctx, sizeof(piv_mlkem_scratch_t)); }

static int piv_mlkem_prepare_public(const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES], const uint8_t *prefix,
                                    size_t prefix_len) {
  static const uint8_t encoded_header[] = {0x82, 0x04, 0xA4, 0x86, 0x82, 0x04, 0xA0};
  piv_mlkem_scratch_t *scratch = &piv_mlkem_scratch;
  if (prefix_len + sizeof(encoded_header) > sizeof(scratch->public_key.prefix))
    return -1;

  apdu_response_source_clear();
  memzero(scratch, sizeof(*scratch));
  memcpy(scratch->public_key.prefix, prefix, prefix_len);
  memcpy(scratch->public_key.prefix + prefix_len, encoded_header, sizeof(encoded_header));
  scratch->public_key.prefix_len = prefix_len + sizeof(encoded_header);
  if (ml_kem_768_seed_to_public(scratch->public_key.public_key, seed) < 0) {
    memzero(scratch, sizeof(*scratch));
    return -1;
  }
  scratch->public_key.total_len = scratch->public_key.prefix_len + MLKEM768_PUBLIC_KEY_BYTES;
  apdu_response_source_set((uint32_t)scratch->public_key.total_len, SW_NO_ERROR, piv_mlkem_public_read,
                           piv_mlkem_public_close, scratch);
  return 0;
}

static int piv_pke_acquire(uint8_t use) {
  if (piv_pke_owned) return piv_pke_use == use ? 0 : -1;
  if (pke_buffer_acquire(PKE_BUFFER_OWNER_PIV) < 0) return -1;
  piv_pke_owned = 1;
  piv_pke_use = use;
  return 0;
}

static void piv_pke_release_all(void) {
  if (!piv_pke_owned) return;
  pke_buffer_clear();
  pke_buffer_release(PKE_BUFFER_OWNER_PIV);
  piv_pke_owned = 0;
  piv_pke_use = PIV_PKE_USE_NONE;
}

static void piv_pke_release(uint8_t use) {
  if (piv_pke_use == use) piv_pke_release_all();
}

static void piv_pke_source_close(void *ctx) {
  UNUSED(ctx);
  piv_pke_release(PIV_PKE_USE_RESPONSE);
}

static void piv_buffer_source_close(void *ctx) {
  uint8_t *data = (uint8_t *)ctx;
  if (data != NULL) memzero(data, PIV_MAX_7C_RESPONSE_LENGTH);
}

typedef int (*piv_data_read_t)(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len);

typedef struct {
  uint8_t header[8];
  uint8_t header_len;
  piv_data_read_t payload_read;
  void *payload_ctx;
  APDU_RESPONSE_SOURCE_CLOSE payload_close;
} piv_7c_stream_source_t;

static piv_7c_stream_source_t piv_7c_stream_source;

static int piv_7c_stream_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  piv_7c_stream_source_t *source = (piv_7c_stream_source_t *)ctx;
  size_t copied = 0;

  if (offset < source->header_len) {
    size_t n = MIN((size_t)len, (size_t)source->header_len - offset);
    memcpy(buf, source->header + offset, n);
    copied += n;
    offset += (uint32_t)n;
  }

  if (copied < len) {
    int ret = source->payload_read(source->payload_ctx, offset - source->header_len, buf + copied, len - copied);
    if (ret < 0) return ret;
    copied += (size_t)ret;
  }

  return (int)copied;
}

static void piv_7c_stream_source_close(void *ctx) {
  piv_7c_stream_source_t *source = (piv_7c_stream_source_t *)ctx;
  if (source->payload_close) source->payload_close(source->payload_ctx);
  memzero(source, sizeof(*source));
}

static void piv_mldsa_stream_begin(void) {
  apdu_response_source_clear();
  memzero(&piv_mldsa_stream_state, sizeof(piv_mldsa_stream_state));
}

static int __attribute__((noinline)) piv_mldsa_install_pending_key(piv_mldsa_stream_state_t *state) {
  ck_key_t key;
  char key_path[MAX_KEY_PATH_LEN];

  memzero(&key, sizeof(key));
  key.meta = state->pending_meta;
  memcpy(key.mldsa.seed, state->seed, sizeof(key.mldsa.seed));
  memcpy(key.mldsa.tr, state->tr, sizeof(key.mldsa.tr));
  piv_key_path(state->pending_key_id, key_path);
  const int ret = ck_write_key(key_path, &key);
  memzero(&key, sizeof(key));
  if (ret < 0) return -1;
  state->install_pending = false;
  return 0;
}

static int piv_mldsa_fill_public_stage(piv_mldsa_stream_state_t *state) {
  const bool first_stage = state->crypto.keygen.phase == 0;
  state->stage_len = 0;
  state->stage_off = 0;
  if (first_stage)
    memcpy(state->crypto.keygen.seed, state->seed, sizeof(state->crypto.keygen.seed));
  const int ret = ml_dsa_65_keygen_streaming(state->stage, sizeof(state->stage), &state->crypto.keygen, NULL);
  if (ret <= 0) return -1;
  state->stage_len = (size_t)ret;

  if (state->install_pending) {
    if (first_stage) shake256_init(&state->public_hash);
    shake_update(&state->public_hash, state->stage, state->stage_len);
    if (state->crypto.keygen.phase == 0) {
      shake_finalize(&state->public_hash);
      shake_squeeze(&state->public_hash, state->tr, sizeof(state->tr));
    }
  }
  return 0;
}

static int piv_mldsa_fill_signature_stage(piv_mldsa_stream_state_t *state) {
  state->stage_len = 0;
  state->stage_off = 0;
  if (state->crypto.sign.phase == 0)
    memcpy(state->crypto.sign.seed, state->seed, sizeof(state->crypto.sign.seed));
  const int ret = ml_dsa_65_sign_seed_mu_streaming(state->stage, sizeof(state->stage), &state->crypto.sign, state->mu);
  if (ret <= 0) return -1;
  state->stage_len = (size_t)ret;
  return 0;
}

static int piv_mldsa_stream_read_generated(piv_mldsa_stream_state_t *state, uint8_t *out, size_t max_len,
                                           size_t *written) {
  size_t copied = 0;

  while (copied < max_len && state->kind != PIV_MLDSA_STREAM_NONE) {
    if (state->stage_off == state->stage_len) {
      if ((state->kind == PIV_MLDSA_STREAM_PK && state->crypto.keygen.phase == 0 && state->stage_len != 0) ||
          (state->kind == PIV_MLDSA_STREAM_SIG && state->crypto.sign.phase == 0 && state->stage_len != 0)) {
        state->kind = PIV_MLDSA_STREAM_NONE;
        break;
      }
      const int ret = state->kind == PIV_MLDSA_STREAM_PK ? piv_mldsa_fill_public_stage(state)
                                                         : piv_mldsa_fill_signature_stage(state);
      if (ret < 0) return -1;
    }

    const size_t n = MIN(state->stage_len - state->stage_off, max_len - copied);
    memcpy(out + copied, state->stage + state->stage_off, n);
    state->stage_off += n;
    copied += n;
  }

  *written = copied;
  return 0;
}

static int piv_mldsa_stream_read(void *ctx, uint32_t offset, uint8_t *out, uint16_t len) {
  piv_mldsa_stream_state_t *state = (piv_mldsa_stream_state_t *)ctx;
  size_t copied = 0;

  if (offset != state->emitted) return -1;
  while (copied < len) {
    if (state->prefix_off < state->prefix_len) {
      const size_t n = MIN(state->prefix_len - state->prefix_off, (size_t)len - copied);
      memcpy(out + copied, state->prefix + state->prefix_off, n);
      state->prefix_off += n;
      copied += n;
      continue;
    }

    if (state->kind != PIV_MLDSA_STREAM_NONE) {
      size_t n = 0;
      if (piv_mldsa_stream_read_generated(state, out + copied, (size_t)len - copied, &n) < 0) return -1;
      copied += n;
      if (n != 0) continue;
    }
    break;
  }

  if (copied != len) return -1;
  state->emitted += copied;
  if (state->install_pending && state->emitted == state->total_len && piv_mldsa_install_pending_key(state) < 0)
    return -1;
  return (int)copied;
}

static void piv_mldsa_stream_close(void *ctx) {
  piv_mldsa_stream_state_t *state = (piv_mldsa_stream_state_t *)ctx;
  memzero(state, sizeof(*state));
}

static void piv_mldsa_stream_activate(void) {
  apdu_response_source_set((uint32_t)piv_mldsa_stream_state.total_len, SW_NO_ERROR, piv_mldsa_stream_read,
                           piv_mldsa_stream_close, &piv_mldsa_stream_state);
}

static int piv_mldsa_prepare_public(const ck_key_t *key, const uint8_t *prefix, size_t prefix_len,
                                    uint8_t pending_key_id) {
  piv_mldsa_stream_state_t *state = &piv_mldsa_stream_state;
  if (prefix_len + 7 > sizeof(state->prefix)) return -1;

  piv_mldsa_stream_begin();
  memcpy(state->prefix, prefix, prefix_len);
  state->prefix[prefix_len++] = 0x82;
  state->prefix[prefix_len++] = HI(4 + MLDSA_PK_BYTES);
  state->prefix[prefix_len++] = LO(4 + MLDSA_PK_BYTES);
  state->prefix[prefix_len++] = 0x86;
  state->prefix[prefix_len++] = 0x82;
  state->prefix[prefix_len++] = HI(MLDSA_PK_BYTES);
  state->prefix[prefix_len++] = LO(MLDSA_PK_BYTES);
  state->prefix_len = prefix_len;
  state->kind = PIV_MLDSA_STREAM_PK;
  memcpy(state->seed, key->mldsa.seed, sizeof(state->seed));
  state->total_len = state->prefix_len + MLDSA_PK_BYTES;

  if (pending_key_id != 0) {
    state->pending_meta = key->meta;
    state->pending_key_id = pending_key_id;
    state->install_pending = true;
  }
  if (state->install_pending && piv_mldsa_fill_public_stage(state) < 0) {
    piv_mldsa_stream_close(state);
    return -1;
  }
  return 0;
}

static int piv_mldsa_prepare_signature(const ck_key_t *key, const uint8_t mu[MLDSA_CRHBYTES]) {
  piv_mldsa_stream_state_t *state = &piv_mldsa_stream_state;
  static const uint8_t signature_prefix[] = {0x7C, 0x82, 0x0C, 0xF1, 0x82, 0x82, 0x0C, 0xED};

  memcpy(state->prefix, signature_prefix, sizeof(signature_prefix));
  state->prefix_len = sizeof(signature_prefix);
  state->kind = PIV_MLDSA_STREAM_SIG;
  memcpy(state->seed, key->mldsa.seed, sizeof(state->seed));
  memcpy(state->tr, key->mldsa.tr, sizeof(state->tr));
  memcpy(state->mu, mu, sizeof(state->mu));
  state->total_len = state->prefix_len + MLDSA_SIG_BYTES;

  return 0;
}

static int piv_capdu_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  const CAPDU *capdu = (const CAPDU *)ctx;

  if (offset > capdu->lc || len > capdu->lc - offset) return -1;
  memcpy(buf, capdu->data + offset, len);
  return len;
}

static int piv_pke_buffer_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  UNUSED(ctx);
  return pke_buffer_read(offset, buf, len) < 0 ? -1 : len;
}

static int piv_read_u8(piv_data_read_t read, void *ctx, size_t off, uint8_t *out) { return read(ctx, off, out, 1); }

static int piv_read_tlv_len(piv_data_read_t read, void *ctx, size_t *off, uint16_t total_len, uint16_t *out) {
  uint8_t b;
  if (*off >= total_len || piv_read_u8(read, ctx, (*off)++, &b) < 0) return -1;
  if ((b & 0x80) == 0) {
    *out = b;
    return 0;
  }

  const uint8_t len_size = b & 0x7F;
  if (len_size == 0 || len_size > 2 || *off + len_size > total_len) return -1;
  uint16_t len = 0;
  for (uint8_t i = 0; i < len_size; ++i) {
    if (piv_read_u8(read, ctx, (*off)++, &b) < 0) return -1;
    len = (len << 8u) | b;
  }
  *out = len;
  return 0;
}

static uint16_t piv_parse_general_authenticate(uint16_t auth_len, piv_data_read_t read, void *ctx, uint16_t pos[6],
                                               uint16_t len[6]) {
  uint8_t b;
  if (auth_len < 2 || piv_read_u8(read, ctx, 0, &b) < 0) return SW_WRONG_LENGTH;
  if (b != 0x7C) return SW_WRONG_DATA;

  size_t off = 1;
  uint16_t value_len;
  if (piv_read_tlv_len(read, ctx, &off, auth_len, &value_len) < 0 || off + value_len != auth_len)
    return SW_WRONG_LENGTH;

  const size_t value_end = off + value_len;
  while (off < value_end) {
    uint8_t tag;
    if (piv_read_u8(read, ctx, off++, &tag) < 0 || (tag != 0x80 && tag != 0x81 && tag != 0x82 && tag != 0x85))
      return SW_WRONG_DATA;

    uint16_t data_len;
    if (piv_read_tlv_len(read, ctx, &off, auth_len, &data_len) < 0 || off + data_len > value_end)
      return SW_WRONG_LENGTH;
    len[tag - 0x80] = data_len;
    pos[tag - 0x80] = off;
    off += data_len;
    DBG_MSG("Tag %02X, pos: %d, len: %d\n", tag, pos[tag - 0x80], len[tag - 0x80]);
  }

  return off == value_end ? SW_NO_ERROR : SW_WRONG_LENGTH;
}

enum {
  PIV_GA_STREAM_OUTER_TAG,
  PIV_GA_STREAM_OUTER_LEN,
  PIV_GA_STREAM_RESPONSE_TAG,
  PIV_GA_STREAM_RESPONSE_LEN,
  PIV_GA_STREAM_CHALLENGE_TAG,
  PIV_GA_STREAM_CHALLENGE_LEN,
  PIV_GA_STREAM_MESSAGE,
  PIV_GA_STREAM_DONE,
};

static int piv_ga_stream_length_feed(piv_ga_stream_state_t *state, uint8_t byte, uint16_t *length) {
  if (state->length_count == 0) {
    if ((byte & 0x80u) == 0) {
      *length = byte;
      return 1;
    }
    state->length_count = byte & 0x7Fu;
    if (state->length_count == 0 || state->length_count > 2) return -1;
    state->length_seen = 0;
    state->length_value = 0;
    return 0;
  }

  state->length_value = (uint16_t)((state->length_value << 8u) | byte);
  if (++state->length_seen != state->length_count) return 0;
  *length = state->length_value;
  state->length_count = 0;
  state->length_seen = 0;
  state->length_value = 0;
  return 1;
}

static int piv_ga_stream_take_inner_byte(piv_ga_stream_state_t *state) {
  if (state->outer_remaining == 0) return -1;
  state->outer_remaining--;
  return 0;
}

static uint16_t piv_ga_stream_update(piv_ga_stream_state_t *state, uint8_t mode, const uint8_t *data,
                                     size_t data_len, bool final) {
  size_t offset = 0;

  while (offset < data_len) {
    uint16_t length;
    int ret;
    switch (state->phase) {
    case PIV_GA_STREAM_OUTER_TAG:
      if (data[offset++] != 0x7C) return SW_WRONG_DATA;
      state->phase = PIV_GA_STREAM_OUTER_LEN;
      break;
    case PIV_GA_STREAM_OUTER_LEN:
      ret = piv_ga_stream_length_feed(state, data[offset++], &length);
      if (ret < 0) return SW_WRONG_LENGTH;
      if (ret > 0) {
        state->outer_remaining = length;
        state->phase = PIV_GA_STREAM_RESPONSE_TAG;
      }
      break;
    case PIV_GA_STREAM_RESPONSE_TAG:
      if (piv_ga_stream_take_inner_byte(state) < 0) return SW_WRONG_LENGTH;
      if (data[offset++] != TAG_RESPONSE) return SW_WRONG_DATA;
      state->phase = PIV_GA_STREAM_RESPONSE_LEN;
      break;
    case PIV_GA_STREAM_RESPONSE_LEN:
      if (piv_ga_stream_take_inner_byte(state) < 0) return SW_WRONG_LENGTH;
      ret = piv_ga_stream_length_feed(state, data[offset++], &length);
      if (ret < 0) return SW_WRONG_LENGTH;
      if (ret > 0) {
        if (length != 0) return SW_WRONG_DATA;
        state->phase = PIV_GA_STREAM_CHALLENGE_TAG;
      }
      break;
    case PIV_GA_STREAM_CHALLENGE_TAG:
      if (piv_ga_stream_take_inner_byte(state) < 0) return SW_WRONG_LENGTH;
      if (data[offset++] != TAG_CHALLENGE) return SW_WRONG_DATA;
      state->phase = PIV_GA_STREAM_CHALLENGE_LEN;
      break;
    case PIV_GA_STREAM_CHALLENGE_LEN:
      if (piv_ga_stream_take_inner_byte(state) < 0) return SW_WRONG_LENGTH;
      ret = piv_ga_stream_length_feed(state, data[offset++], &length);
      if (ret < 0) return SW_WRONG_LENGTH;
      if (ret > 0) {
        state->message_len = length;
        if (state->outer_remaining != length) return SW_WRONG_LENGTH;
        state->phase = length == 0 ? PIV_GA_STREAM_DONE : PIV_GA_STREAM_MESSAGE;
      }
      break;
    case PIV_GA_STREAM_MESSAGE: {
      const size_t count = MIN(data_len - offset, (size_t)state->outer_remaining);
      if (count == 0) return SW_WRONG_LENGTH;
      if (mode == PIV_AUTH_MODE_MLDSA)
        shake_update(&state->crypto.mldsa, data + offset, count);
      else if (ed25519_randomized_sign_update(&state->crypto.ed25519, data + offset, count) < 0)
        return SW_UNABLE_TO_PROCESS;
      offset += count;
      state->outer_remaining -= (uint16_t)count;
      state->message_received += (uint16_t)count;
      if (state->outer_remaining == 0) state->phase = PIV_GA_STREAM_DONE;
      break;
    }
    case PIV_GA_STREAM_DONE:
    default:
      return SW_WRONG_DATA;
    }
  }

  if (final)
    return state->phase == PIV_GA_STREAM_DONE && state->message_received == state->message_len ? SW_NO_ERROR
                                                                                              : SW_WRONG_LENGTH;
  return state->phase == PIV_GA_STREAM_DONE ? SW_WRONG_LENGTH : SW_NO_ERROR;
}

static int piv_set_7c_response(uint8_t inner_tag, const uint8_t *data, uint16_t data_len, uint8_t *rdata,
                               uint16_t *out_len) {
  const uint16_t header_len = data_len < 128 ? 4 : 8;
  const uint16_t total_len = data_len + header_len;

  if (total_len > APDU_COMMAND_BUFFER_SIZE) {
    piv_7c_stream_source.header_len = (uint8_t)header_len;
    if (data_len < 128) {
      piv_7c_stream_source.header[0] = 0x7C;
      piv_7c_stream_source.header[1] = data_len + 2;
      piv_7c_stream_source.header[2] = inner_tag;
      piv_7c_stream_source.header[3] = data_len;
    } else {
      piv_7c_stream_source.header[0] = 0x7C;
      piv_7c_stream_source.header[1] = 0x82;
      piv_7c_stream_source.header[2] = HI(data_len + 4);
      piv_7c_stream_source.header[3] = LO(data_len + 4);
      piv_7c_stream_source.header[4] = inner_tag;
      piv_7c_stream_source.header[5] = 0x82;
      piv_7c_stream_source.header[6] = HI(data_len);
      piv_7c_stream_source.header[7] = LO(data_len);
    }
    piv_7c_stream_source.payload_read = apdu_response_source_read_memory;
    piv_7c_stream_source.payload_ctx = (void *)data;
    piv_7c_stream_source.payload_close = piv_buffer_source_close;
    apdu_response_source_set(total_len, SW_NO_ERROR, piv_7c_stream_source_read, piv_7c_stream_source_close,
                             &piv_7c_stream_source);
    *out_len = 0;
    return 0;
  }

  if (data_len < 128) {
    rdata[0] = 0x7C;
    rdata[1] = data_len + 2;
    rdata[2] = inner_tag;
    rdata[3] = data_len;
    memmove(rdata + 4, data, data_len);
  } else {
    rdata[0] = 0x7C;
    rdata[1] = 0x82;
    rdata[2] = HI(data_len + 4);
    rdata[3] = LO(data_len + 4);
    rdata[4] = inner_tag;
    rdata[5] = 0x82;
    rdata[6] = HI(data_len);
    rdata[7] = LO(data_len);
    memmove(rdata + 8, data, data_len);
  }
  *out_len = total_len;
  return 0;
}

static int piv_set_public_key_response(ck_key_t *key, const uint8_t *prefix, uint8_t prefix_len, uint8_t *rdata,
                                       uint16_t *out_len) {
  const int encoded_len = ck_encoded_public_key_length(key->meta.type, true);
  if (encoded_len < 0) return -1;
  const uint32_t total_len = prefix_len + (uint32_t)encoded_len;

  if (IS_MLDSA(key->meta.type)) {
    if (piv_mldsa_prepare_public(key, prefix, prefix_len, 0) < 0) return -1;
    piv_mldsa_stream_activate();
    *out_len = 0;
    return 0;
  }

  if (IS_MLKEM(key->meta.type)) {
    if (piv_mlkem_prepare_public(key->mlkem.seed, prefix, prefix_len) < 0) return -1;
    *out_len = 0;
    return 0;
  }

  if (total_len > APDU_COMMAND_BUFFER_SIZE) {
    uint8_t *response = piv_crypto_buffer;

    if (total_len > sizeof(piv_crypto_buffer) || total_len > pke_buffer_size()) return -1;
    memcpy(response, prefix, prefix_len);
    if (ck_encode_public_key(key, response + prefix_len, true) != encoded_len) return -1;
    apdu_response_source_clear();
    if (piv_pke_acquire(PIV_PKE_USE_RESPONSE) < 0) return -1;
    if (pke_buffer_write(0, response, total_len) < 0) {
      piv_pke_release(PIV_PKE_USE_RESPONSE);
      return -1;
    }
    apdu_response_source_set(total_len, SW_NO_ERROR, apdu_response_source_read_pke, piv_pke_source_close, NULL);
    *out_len = 0;
    return 0;
  }

  memcpy(rdata, prefix, prefix_len);
  if (ck_encode_public_key(key, rdata + prefix_len, true) != encoded_len) return -1;
  *out_len = (uint16_t)total_len;
  return 0;
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

static int piv_ga_stream_begin(uint8_t p2, uint8_t mode) {
  char key_path[MAX_KEY_PATH_LEN];
  ck_key_t key;
  const int meta_sw = piv_read_key_metadata_or_default(p2, &key.meta, key_path);
  if (meta_sw != SW_NO_ERROR) return meta_sw;
  if (key.meta.type == KEY_TYPE_PKC_END) return SW_CONDITIONS_NOT_SATISFIED;
  if ((mode == PIV_AUTH_MODE_MLDSA && !IS_MLDSA(key.meta.type)) ||
      (mode == PIV_AUTH_MODE_ED25519_RANDOMIZED && key.meta.type != ED25519))
    return SW_WRONG_P1P2;

  authenticate_reset();
#ifndef FUZZ
  if (piv_security_status_check(p2, &key.meta) != 0) return SW_SECURITY_STATUS_NOT_SATISFIED;
#endif
  if (key.meta.touch_policy == TOUCH_POLICY_CACHED || key.meta.touch_policy == TOUCH_POLICY_ALWAYS) {
    const uint16_t touch_sw = piv_touch(key.meta.touch_policy == TOUCH_POLICY_CACHED);
    if (touch_sw != SW_NO_ERROR) return touch_sw;
  }

  if (ck_read_key(key_path, &key) < 0) return -1;
  memzero(&piv_ga_stream_state, sizeof(piv_ga_stream_state));
  if (mode == PIV_AUTH_MODE_MLDSA) {
    static const uint8_t empty_context_header[] = {0x00, 0x00};
    shake256_init(&piv_ga_stream_state.crypto.mldsa);
    shake_update(&piv_ga_stream_state.crypto.mldsa, key.mldsa.tr, sizeof(key.mldsa.tr));
    shake_update(&piv_ga_stream_state.crypto.mldsa, empty_context_header, sizeof(empty_context_header));
  } else if (ed25519_randomized_sign_init(&piv_ga_stream_state.crypto.ed25519, &key.ecc) < 0) {
    memzero(&key, sizeof(key));
    return -1;
  }
  memzero(&key, sizeof(key));
  piv_auth_mode = mode;
  return SW_NO_ERROR;
}

static void piv_import_reset(void) {
  piv_pke_release(PIV_PKE_USE_IMPORT);
  piv_import_key_id = 0;
  piv_import_key_type = KEY_TYPE_PKC_END;
  piv_import_len = 0;
  memzero(&piv_import_stream, sizeof(piv_import_stream));
}

static void piv_auth_reset(void) {
  piv_pke_release(PIV_PKE_USE_AUTH);
  if (piv_auth_mode == PIV_AUTH_MODE_ED25519_RANDOMIZED)
    ed25519_randomized_sign_clear(&piv_ga_stream_state.crypto.ed25519);
  else if (piv_auth_mode == PIV_AUTH_MODE_MLDSA)
    memzero(&piv_ga_stream_state, sizeof(piv_ga_stream_state));
  piv_auth_active = 0;
  piv_auth_p1 = 0;
  piv_auth_p2 = 0;
  piv_auth_len = 0;
  piv_auth_mode = PIV_AUTH_MODE_CLASSIC;
}

static void piv_abort_chained_state(void) {
  piv_do_write = -1;
  piv_do_read = -1;
  piv_import_reset();
  piv_auth_reset();
  apdu_response_source_clear();
  piv_state = PIV_STATE_OTHER;
}

static void piv_algorithm_extension_config_set_default(void) {
  alg_ext_cfg.enabled = 1;
  alg_ext_cfg.ed25519 = ALG_ED25519_DEFAULT;
  alg_ext_cfg.rsa3072 = ALG_RSA_3072_DEFAULT;
  alg_ext_cfg.rsa4096 = ALG_RSA_4096_DEFAULT;
  alg_ext_cfg.x25519 = ALG_X25519_DEFAULT;
  alg_ext_cfg.secp256k1 = ALG_SECP256K1_DEFAULT;
  alg_ext_cfg.secp521r1 = ALG_SECP521R1_DEFAULT;
  alg_ext_cfg.sm2 = ALG_SM2_DEFAULT;
  alg_ext_cfg.mldsa65 = ALG_MLDSA65_DEFAULT;
  alg_ext_cfg.mlkem768 = ALG_MLKEM768_DEFAULT;
}

void piv_poweroff(void) {
  piv_state = PIV_STATE_OTHER;
  in_admin_status = 0;
  pin_is_consumed = 0;
  pin.is_validated = 0;
  puk.is_validated = 0;
  piv_do_write = -1;
  piv_do_read = -1;
  piv_do_path[0] = '\0';
  piv_import_reset();
  piv_auth_reset();
}

int piv_install(const uint8_t reset) {
  piv_poweroff();
  piv_algorithm_extension_config_t preserved_alg_ext_cfg;
  const bool has_alg_ext_cfg = piv_algorithm_extension_config_load(&preserved_alg_ext_cfg) == 0;
  // Platform alg-ext config is the install completion marker. If it is missing
  // or invalid, rebuild PIV state.
  if (!reset && has_alg_ext_cfg && piv_littlefs_state_present()) {
    alg_ext_cfg = preserved_alg_ext_cfg;
    return 0;
  }
  if (piv_clear_file_do_storage() < 0) return -1;

  // Default objects. Optional DO files are created lazily on PUT DATA so empty
  // retired cert and biometric objects do not consume LittleFS metadata blocks.
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

  // AES-192 admin key
  ck_key_t admin_key;
  ck_key_init_empty(&admin_key, AES192, ENCRYPT, PIN_POLICY_NEVER, TOUCH_POLICY_NEVER);
  admin_key.meta.origin = KEY_ORIGIN_GENERATED;
  memcpy(admin_key.data, DEFAULT_MGMT_KEY, 24);
  char admin_key_path[MAX_KEY_PATH_LEN];
  piv_key_path(0x9B, admin_key_path);
  if (ck_write_key(admin_key_path, &admin_key) < 0) return -1;
  if (piv_clear_inline_do_storage() < 0) return -1;
  const uint8_t tmp = 0x01;
  if (write_attr(admin_key_path, TAG_PIN_KEY_DEFAULT, &tmp, sizeof(tmp)) < 0) return -1;

  // PIN data
  if (pin_create(&pin, DEFAULT_PIN, 8, 3) < 0) return -1;
  if (write_attr(pin.path, TAG_PIN_KEY_DEFAULT, &tmp, sizeof(tmp)) < 0) return -1;
  if (pin_create(&puk, DEFAULT_PUK, 8, 3) < 0) return -1;
  if (write_attr(puk.path, TAG_PIN_KEY_DEFAULT, &tmp, sizeof(tmp)) < 0) return -1;

  // Algorithm extensions must remain the last persistent write because
  // successful readback is used as the initialized marker. Preserve valid
  // platform config across a PIV reset so admin-selected algorithm IDs survive
  // provisioning tools that reset the applet before use.
  if (has_alg_ext_cfg) {
    alg_ext_cfg = preserved_alg_ext_cfg;
  } else {
    piv_algorithm_extension_config_set_default();
  }
  if (piv_platform_algorithm_extension_config_write(&alg_ext_cfg) < 0) return -1;

  return 0;
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
  uint32_t tag;
  uint16_t header_len;
  const int tag_sw = piv_parse_data_object_tag(capdu, &tag, &header_len);
  if (tag_sw != SW_NO_ERROR) EXCEPT(tag_sw);
  if (header_len != LC) EXCEPT(SW_WRONG_LENGTH);

  const piv_do_desc_t *desc = piv_find_do(tag);
  if (desc == NULL) EXCEPT(SW_FILE_NOT_FOUND);

  if ((desc->flags & PIV_DO_F_GET_PIN) != 0 && !pin.is_validated) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

  if (tag == PIV_DO_TAG_DISCOVERY) {
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
    return 0;
  }

  if ((desc->flags & PIV_DO_F_INLINE) != 0) {
    const int attr_len = read_attr(PIV_DO_META_PATH, desc->attr, RDATA, desc->capacity);
    if (attr_len > 0) {
      LL = attr_len;
      return 0;
    }
    if (attr_len < 0 && desc->path == NULL) EXCEPT(SW_FILE_NOT_FOUND);
  }

  char path[MAX_DO_PATH_LEN];
  if (!piv_do_get_path(desc, tag, path)) EXCEPT(SW_FILE_NOT_FOUND);
  const int size = get_file_size(path);
  if (size == LFS_ERR_NOENT || size == 0) EXCEPT(SW_FILE_NOT_FOUND);
  if (size < 0) return -1;
  return piv_get_large_data(capdu, rapdu, path, size);
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
    EXCEPT(pin_get_retry_sw((uint8_t)retries));
  }
  if (LC != 8) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  const int err = pin_verify(&pin, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(pin_get_retry_sw(ctr));
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
  if (err == PIN_AUTH_FAIL) EXCEPT(pin_get_retry_sw(ctr));
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
  if (err == PIN_AUTH_FAIL) EXCEPT(pin_get_retry_sw(ctr));
  err = pin_update(&pin, DATA + 8, 8);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static int piv_set_pin_retries(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  if (P1 == 0 || P1 > PIN_MAX_RETRIES || P2 == 0 || P2 > PIN_MAX_RETRIES) EXCEPT(SW_WRONG_P1P2);
  if (!in_admin_status || !pin.is_validated) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

  // A retry reset rewrites credentials. Clear volatile authorization first so
  // an interrupted persistent write cannot leave the old session authorized.
  in_admin_status = 0;
  pin.is_validated = 0;
  puk.is_validated = 0;
  pin_is_consumed = 0;

  if (pin_create(&pin, DEFAULT_PIN, 8, P1) < 0) return -1;
  if (pin_create(&puk, DEFAULT_PUK, 8, P2) < 0) return -1;

  const uint8_t is_default = 1;
  if (write_attr(pin.path, TAG_PIN_KEY_DEFAULT, &is_default, sizeof(is_default)) < 0) return -1;
  if (write_attr(puk.path, TAG_PIN_KEY_DEFAULT, &is_default, sizeof(is_default)) < 0) return -1;

  return 0;
}

__attribute__((noinline)) static int piv_general_authenticate_mlkem_dispatch(
    const CAPDU *capdu, RAPDU *rapdu, uint16_t auth_len, piv_data_read_t read, void *ctx, const char *key_path,
    const key_meta_t *meta) {
  uint16_t pos[6] = {0}, len[6] = {0};
  const uint16_t parse_sw = piv_parse_general_authenticate(auth_len, read, ctx, pos, len);
  if (parse_sw != SW_NO_ERROR) EXCEPT(parse_sw);
  if (algo_id_to_key_type(P1) != MLKEM768) EXCEPT(SW_WRONG_P1P2);
  if (pos[IDX_WITNESS] != 0 || pos[IDX_CHALLENGE] == 0 || len[IDX_CHALLENGE] != MLKEM768_CIPHERTEXT_BYTES ||
      pos[IDX_RESPONSE] == 0 || len[IDX_RESPONSE] != 0)
    EXCEPT(SW_WRONG_DATA);
  authenticate_reset();
#ifndef FUZZ
  if (piv_security_status_check(P2, meta) != 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (meta->touch_policy == TOUCH_POLICY_CACHED || meta->touch_policy == TOUCH_POLICY_ALWAYS)
    PIV_TOUCH(meta->touch_policy == TOUCH_POLICY_CACHED);

  uint8_t *ciphertext = piv_mlkem_scratch.decaps.ciphertext;
  if (read(ctx, pos[IDX_CHALLENGE], ciphertext, MLKEM768_CIPHERTEXT_BYTES) != MLKEM768_CIPHERTEXT_BYTES) {
    memzero(&piv_mlkem_scratch, sizeof(piv_mlkem_scratch));
    return -1;
  }
  if (read_file(key_path, piv_mlkem_scratch.decaps.seed, 0, MLKEM768_KEYGEN_SEED_BYTES) !=
      MLKEM768_KEYGEN_SEED_BYTES) {
    memzero(&piv_mlkem_scratch, sizeof(piv_mlkem_scratch));
    return -1;
  }
  piv_pke_release(PIV_PKE_USE_AUTH);
  start_quick_blinking(0);
  const int decaps_ret = ml_kem_768_decaps_seed(RDATA + 4, ciphertext, piv_mlkem_scratch.decaps.seed,
                                                piv_mlkem_scratch.decaps.public_key);
  memzero(&piv_mlkem_scratch, sizeof(piv_mlkem_scratch));
  if (decaps_ret < 0) return -1;
  LL = piv_7c_wrap(RDATA, TAG_RESPONSE, MLKEM768_SHARED_KEY_BYTES);
  return 0;
}

__attribute__((noinline)) static int piv_general_authenticate_dispatch_classic(
    const CAPDU *capdu, RAPDU *rapdu, uint16_t auth_len, piv_data_read_t read, void *ctx) {
  if (auth_len == 0) EXCEPT(SW_WRONG_LENGTH);
  char key_path[MAX_KEY_PATH_LEN];
  if (!piv_is_key_id(P2)) {
    DBG_MSG("Invalid key ref\n");
    EXCEPT(SW_WRONG_P1P2);
  }
  piv_key_path(P2, key_path);

  uint16_t pos[6] = {0}, len[6] = {0};
  const uint16_t parse_sw = piv_parse_general_authenticate(auth_len, read, ctx, pos, len);
  if (parse_sw != SW_NO_ERROR) EXCEPT(parse_sw);

  ck_key_t key;
  if (P2 == 0x9B) { // Card admin
    if (P1 != ALG_DEFAULT && P1 != ALG_AES_192) {
      DBG_MSG("Invalid P1/P2 for card admin key\n");
      EXCEPT(SW_WRONG_P1P2);
    }
  }
  const int meta_sw = piv_read_key_metadata_or_default(P2, &key.meta, key_path);
  if (meta_sw == SW_WRONG_P1P2) EXCEPT(meta_sw);
  if (meta_sw < 0) return -1;
  DBG_KEY_META(&key.meta);

  // empty slot after reset
  if (key.meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  if (algo_id_to_key_type(P1) != key.meta.type) {
    DBG_MSG("The value of P1 mismatches the key specified by P2\n");
    EXCEPT(SW_WRONG_P1P2);
  }

  // User presence test
  if (key.meta.touch_policy == TOUCH_POLICY_CACHED || key.meta.touch_policy == TOUCH_POLICY_ALWAYS)
    PIV_TOUCH(key.meta.touch_policy == TOUCH_POLICY_CACHED);

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

    if (len[IDX_CHALLENGE] > sizeof(piv_crypto_buffer)) EXCEPT(SW_WRONG_LENGTH);
    if (read(ctx, pos[IDX_CHALLENGE], piv_crypto_buffer, len[IDX_CHALLENGE]) != len[IDX_CHALLENGE]) return -1;

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    start_quick_blinking(0);

    if (IS_RSA(key.meta.type)) {
      const uint16_t sig_len = SIGNATURE_LENGTH[key.meta.type];
      // The input has been padded
      DBG_MSG("e: ");
      PRINT_HEX(key.rsa.e, E_LENGTH);
      DBG_MSG("p: ");
      PRINT_HEX(key.rsa.p, PRIVATE_KEY_LENGTH[key.meta.type]);
      DBG_MSG("q: ");
      PRINT_HEX(key.rsa.q, PRIVATE_KEY_LENGTH[key.meta.type]);
      if (rsa_private(&key.rsa, piv_crypto_buffer, piv_crypto_buffer) < 0) {
        ERR_MSG("Sign failed\n");
        memzero(&key, sizeof(key));
        return -1;
      }
      uint16_t response_len;
      if (piv_set_7c_response(TAG_RESPONSE, piv_crypto_buffer, sig_len, RDATA, &response_len) < 0) {
        memzero(&key, sizeof(key));
        memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
        return -1;
      }
      LL = response_len;

      memzero(&key, sizeof(key));
      if (response_len != 0) memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
    } else if (IS_ECC(key.meta.type)) {
      size_t input_len;
      if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
        input_len = PRIVATE_KEY_LENGTH[key.meta.type];
        memmove(piv_crypto_buffer + (input_len - len[IDX_CHALLENGE]), piv_crypto_buffer, len[IDX_CHALLENGE]);
        memzero(piv_crypto_buffer, input_len - len[IDX_CHALLENGE]);
      } else if (key.meta.type == ED25519) {
        input_len = len[IDX_CHALLENGE];
      } else
        EXCEPT(SW_WRONG_DATA);
      int sig_len = ck_sign(&key, piv_crypto_buffer, input_len, piv_crypto_buffer);
      if (sig_len < 0) {
        ERR_MSG("Sign failed\n");
        memzero(&key, sizeof(key));
        memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
        return -1;
      }

      if (IS_SHORT_WEIERSTRASS(key.meta.type)) {
        sig_len = (int)ecdsa_sig2ansi(PRIVATE_KEY_LENGTH[key.meta.type], piv_crypto_buffer, piv_crypto_buffer);
      }

      uint16_t response_len;
      if (piv_set_7c_response(TAG_RESPONSE, piv_crypto_buffer, sig_len, RDATA, &response_len) < 0) {
        memzero(&key, sizeof(key));
        memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
        return -1;
      }
      LL = response_len;

      memzero(&key, sizeof(key));
      if (response_len != 0) memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
    } else
      return -1;
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

    LL = piv_7c_wrap(RDATA, TAG_CHALLENGE, AES_BLOCK_SIZE);
    random_buffer(RDATA + 4, AES_BLOCK_SIZE);

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    if (aes192_enc(RDATA + 4, auth_ctx + OFFSET_AUTH_CHALLENGE, key.data) < 0) {
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
    uint8_t response[AES_BLOCK_SIZE];

    DBG_MSG("Case 3\n");
    if (len[IDX_RESPONSE] != AES_BLOCK_SIZE ||
        read(ctx, pos[IDX_RESPONSE], response, sizeof(response)) != (int)sizeof(response))
      return -1;
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL || P2 != 0x9B || AES_BLOCK_SIZE != len[IDX_RESPONSE] ||
        memcmp_s(auth_ctx + OFFSET_AUTH_CHALLENGE, response, AES_BLOCK_SIZE) != 0) {
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
    random_buffer(auth_ctx + OFFSET_AUTH_CHALLENGE, AES_BLOCK_SIZE);

    LL = piv_7c_wrap(RDATA, TAG_WITNESS, AES_BLOCK_SIZE);

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    if (aes192_enc(auth_ctx + OFFSET_AUTH_CHALLENGE, RDATA + 4, key.data) < 0) {
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
    uint8_t witness[AES_BLOCK_SIZE];
    uint8_t challenge[AES_BLOCK_SIZE];

    DBG_MSG("Case 5\n");
    if (len[IDX_WITNESS] != AES_BLOCK_SIZE || len[IDX_CHALLENGE] != AES_BLOCK_SIZE ||
        read(ctx, pos[IDX_WITNESS], witness, sizeof(witness)) != (int)sizeof(witness) ||
        read(ctx, pos[IDX_CHALLENGE], challenge, sizeof(challenge)) != (int)sizeof(challenge))
      return -1;
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL || P2 != 0x9B || AES_BLOCK_SIZE != len[IDX_WITNESS] ||
        memcmp_s(auth_ctx + OFFSET_AUTH_CHALLENGE, witness, AES_BLOCK_SIZE) != 0) {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    LL = piv_7c_wrap(RDATA, TAG_RESPONSE, AES_BLOCK_SIZE);

    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    if (aes192_enc(challenge, RDATA + 4, key.data) < 0) {
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
    if (len[IDX_EXP] > sizeof(piv_crypto_buffer) ||
        read(ctx, pos[IDX_EXP], piv_crypto_buffer, len[IDX_EXP]) != len[IDX_EXP])
      return -1;
    if (ck_read_key(key_path, &key) < 0) return -1;
    DBG_KEY_META(&key.meta);

    start_quick_blinking(0);

    if (ecdh(key.meta.type, key.ecc.pri, piv_crypto_buffer + (IS_SHORT_WEIERSTRASS(key.meta.type) ? 1 : 0), RDATA + 4) <
        0) {
      ERR_MSG("ECDH failed\n");
      memzero(&key, sizeof(key));
      memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
      return -1;
    }

    LL = piv_7c_wrap(RDATA, TAG_RESPONSE, PRIVATE_KEY_LENGTH[key.meta.type]);

    memzero(&key, sizeof(key));
    memzero(piv_crypto_buffer, sizeof(piv_crypto_buffer));
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

static int piv_general_authenticate_dispatch(const CAPDU *capdu, RAPDU *rapdu, uint16_t auth_len, piv_data_read_t read,
                                             void *ctx) {
  if (algo_id_to_key_type(P1) != MLKEM768)
    return piv_general_authenticate_dispatch_classic(capdu, rapdu, auth_len, read, ctx);
  if (auth_len == 0) EXCEPT(SW_WRONG_LENGTH);

  char key_path[MAX_KEY_PATH_LEN];
  key_meta_t meta;
  const int meta_sw = piv_read_key_metadata_or_default(P2, &meta, key_path);
  if (meta_sw == SW_WRONG_P1P2) EXCEPT(meta_sw);
  if (meta_sw < 0) return -1;
  if (meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  if (!IS_MLKEM(meta.type)) EXCEPT(SW_WRONG_P1P2);
  return piv_general_authenticate_mlkem_dispatch(capdu, rapdu, auth_len, read, ctx, key_path, &meta);
}

static int piv_general_authenticate_stream(const CAPDU *capdu, RAPDU *rapdu, uint8_t requested_mode) {
  const bool final = (CLA & 0x10) == 0;

  if (!piv_auth_active) {
    if (requested_mode == PIV_AUTH_MODE_ED25519_RANDOMIZED && alg_ext_cfg.enabled == 0) EXCEPT(SW_WRONG_P1P2);
    piv_auth_active = 1;
    piv_auth_p1 = P1;
    piv_auth_p2 = P2;
    const int begin_sw = piv_ga_stream_begin(P2, requested_mode);
    if (begin_sw != SW_NO_ERROR) {
      piv_auth_reset();
      if (begin_sw < 0) return -1;
      EXCEPT((uint16_t)begin_sw);
    }
  } else if (piv_auth_p1 != P1 || piv_auth_p2 != P2 || piv_auth_mode != requested_mode) {
    piv_auth_reset();
    EXCEPT(SW_WRONG_DATA);
  }

  const uint16_t parse_sw = piv_ga_stream_update(&piv_ga_stream_state, piv_auth_mode, DATA, LC, final);
  if (parse_sw != SW_NO_ERROR) {
    piv_auth_reset();
    EXCEPT(parse_sw);
  }
  if (!final) return 0;

  if (piv_auth_mode == PIV_AUTH_MODE_ED25519_RANDOMIZED) {
    uint8_t signature[SIGNATURE_LENGTH[ED25519]];
    start_quick_blinking(0);
    if (ed25519_randomized_sign_final(&piv_ga_stream_state.crypto.ed25519, signature) < 0) {
      piv_auth_reset();
      return -1;
    }
    LL = piv_7c_wrap(RDATA, TAG_RESPONSE, sizeof(signature));
    memcpy(RDATA + 4, signature, sizeof(signature));
    memzero(signature, sizeof(signature));
    piv_auth_mode = PIV_AUTH_MODE_CLASSIC;
    piv_auth_reset();
    return 0;
  }

  uint8_t mu[MLDSA_CRHBYTES];
  shake_finalize(&piv_ga_stream_state.crypto.mldsa);
  shake_squeeze(&piv_ga_stream_state.crypto.mldsa, mu, sizeof(mu));
  char key_path[MAX_KEY_PATH_LEN];
  ck_key_t key;
  piv_key_path(P2, key_path);
  if (ck_read_key(key_path, &key) < 0) {
    memzero(mu, sizeof(mu));
    piv_auth_reset();
    return -1;
  }
  start_quick_blinking(0);
  piv_mldsa_stream_begin();
  const int sign_ret = piv_mldsa_prepare_signature(&key, mu);
  memzero(&key, sizeof(key));
  memzero(mu, sizeof(mu));
  if (sign_ret < 0) {
    piv_auth_mode = PIV_AUTH_MODE_CLASSIC;
    piv_mldsa_stream_close(&piv_mldsa_stream_state);
    piv_auth_reset();
    return -1;
  }
  piv_mldsa_stream_activate();
  piv_auth_mode = PIV_AUTH_MODE_CLASSIC;
  piv_auth_reset();
  LL = 0;
  return 0;
}

static int piv_general_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  uint8_t stream_mode = PIV_AUTH_MODE_CLASSIC;
  if (P1 == ALG_ED25519_RANDOMIZED)
    stream_mode = PIV_AUTH_MODE_ED25519_RANDOMIZED;
  else if (algo_id_to_key_type(P1) == MLDSA65)
    stream_mode = PIV_AUTH_MODE_MLDSA;
  if (stream_mode != PIV_AUTH_MODE_CLASSIC || (piv_auth_active && piv_auth_mode != PIV_AUTH_MODE_CLASSIC))
    return piv_general_authenticate_stream(capdu, rapdu, stream_mode);

  if ((CLA & 0x10) == 0 && !piv_auth_active)
    return piv_general_authenticate_dispatch(capdu, rapdu, LC, piv_capdu_read, (void *)capdu);

  if (!piv_auth_active) {
    piv_auth_active = 1;
    piv_auth_p1 = P1;
    piv_auth_p2 = P2;
    piv_auth_len = 0;
  } else if (piv_auth_p1 != P1 || piv_auth_p2 != P2) {
    piv_auth_reset();
    EXCEPT(SW_WRONG_DATA);
  }

  if ((uint32_t)piv_auth_len + LC > pke_buffer_size()) {
    piv_auth_reset();
    EXCEPT(SW_WRONG_LENGTH);
  }
  if (piv_pke_acquire(PIV_PKE_USE_AUTH) < 0 || pke_buffer_write(piv_auth_len, DATA, LC) < 0) {
    piv_auth_reset();
    return -1;
  }
  piv_auth_len += LC;

  if ((CLA & 0x10) != 0) return 0;

  const int ret = piv_general_authenticate_dispatch(capdu, rapdu, piv_auth_len, piv_pke_buffer_read, NULL);
  piv_auth_reset();
  return ret;
}

static int piv_put_data(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);

  if (piv_do_write == -1) { // not in chaining write
    uint32_t tag;
    uint16_t header_len;
    const int tag_sw = piv_parse_data_object_tag(capdu, &tag, &header_len);
    if (tag_sw != SW_NO_ERROR) EXCEPT(tag_sw);

    const piv_do_desc_t *desc = piv_find_do(tag);
    if (desc == NULL || (desc->flags & (PIV_DO_F_READ_ONLY | PIV_DO_F_PUT_ADMIN)) != PIV_DO_F_PUT_ADMIN)
      EXCEPT(SW_FILE_NOT_FOUND);

    const uint16_t size = LC - header_len;
    if (size > desc->capacity) EXCEPT(SW_WRONG_LENGTH);
    const uint8_t *payload = DATA + header_len;

    /*
     * Inline-capable DOs use attr storage only below their metadata-safe
     * ceiling. PRINTED can legally be up to 245 bytes, but host-managed
     * management-key references are normally small; larger PRINTED data is
     * stored as a file after deleting any stale attr copy.
     */
    if ((desc->flags & PIV_DO_F_INLINE) != 0 && size <= piv_do_inline_capacity(desc)) {
      if ((CLA & 0x10) != 0) EXCEPT(SW_WRONG_LENGTH);
      if (piv_do_write_inline(desc, payload, size) < 0) return -1;
      return 0;
    }

    if ((desc->flags & PIV_DO_F_INLINE) != 0 && desc->path == NULL) {
      EXCEPT(SW_WRONG_LENGTH);
    }

    if ((desc->flags & PIV_DO_F_INLINE) != 0 && piv_clear_attr_if_present(PIV_DO_META_PATH, desc->attr) < 0) {
      return -1;
    }
    if ((desc->flags & PIV_DO_F_INLINE) != 0 && piv_remove_do_meta_if_empty() < 0) return -1;

    char path[MAX_DO_PATH_LEN];
    if (!piv_do_get_path(desc, tag, path)) EXCEPT(SW_FILE_NOT_FOUND);
    if ((CLA & 0x10) == 0 && (desc->flags & PIV_DO_F_CERT) != 0 && size == 2 && payload[0] == 0x53 &&
        payload[1] == 0x00) {
      DBG_MSG("delete certificate file %s\n", path);
      if (piv_remove_file_if_present(path) < 0) return -1;
      return 0;
    }
    DBG_MSG("write file %s, first chunk length %d\n", path, size);
    const int rc = write_file(path, payload, 0, size, 1);
    if (rc < 0) return -1;
    if ((CLA & 0x10) != 0 && size < desc->capacity) {
      // enter chaining write mode
      piv_do_write = desc->capacity - size;
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

// Keep ck_key_t-sized locals out of the central APDU dispatcher's stack frame.
__attribute__((noinline)) static int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
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

  char key_path[MAX_KEY_PATH_LEN];
  if (!piv_is_asymmetric_key_id(P2)) {
    DBG_MSG("Invalid key ref\n");
    EXCEPT(SW_WRONG_P1P2);
  }
  piv_key_path(P2, key_path);
  ck_key_t key;
  const int read_sw = piv_read_key_or_default(P2, &key, key_path);
  if (read_sw == SW_WRONG_P1P2) EXCEPT(read_sw);
  if (read_sw < 0) return -1;

  key.meta.type = algo_id_to_key_type(DATA[4]);
  if (key.meta.type == KEY_TYPE_PKC_END) EXCEPT(SW_WRONG_DATA);
  if (P2 == 0xF9 && key.meta.type != SECP256R1) EXCEPT(SW_WRONG_DATA);
  const int err = ck_parse_piv_policies(&key, &DATA[5], LC - 5);
  if (err != 0) {
    DBG_MSG("Wrong metadata\n");
    memzero(&key, sizeof(key));
    EXCEPT(SW_WRONG_DATA);
  }
  start_quick_blinking(0);

  const uint8_t prefix[] = {0x7F, 0x49};
  if (IS_MLDSA(key.meta.type)) {
    key.meta.origin = KEY_ORIGIN_GENERATED;
    random_buffer(key.mldsa.seed, sizeof(key.mldsa.seed));
    if (piv_mldsa_prepare_public(&key, prefix, sizeof(prefix), P2) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    piv_mldsa_stream_activate();
    memzero(&key, sizeof(key));
    LL = 0;
    return 0;
  }

  if (ck_generate_key(&key) < 0) return -1;
  if (ck_write_key(key_path, &key) < 0) return -1;
  DBG_MSG("Generate key %s successful\n", key_path);
  DBG_KEY_META(&key.meta);

  const int len = ck_encoded_public_key_length(key.meta.type, true);
  uint16_t response_len = 0;
  if (len < 0 || piv_set_public_key_response(&key, prefix, sizeof(prefix), RDATA, &response_len) < 0) {
    memzero(&key, sizeof(key));
    return -1;
  }
  memzero(&key, sizeof(key));
  LL = apdu_response_source_active() ? 0 : response_len;

  return 0;
}

static int piv_set_management_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0xFF || (P2 != 0xFF && P2 != 0xFE)) EXCEPT(SW_WRONG_P1P2);
  if (LC != 27) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != ALG_AES_192 || DATA[1] != 0x9B || DATA[2] != 24) EXCEPT(SW_WRONG_DATA);
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  char admin_key_path[MAX_KEY_PATH_LEN];
  piv_key_path(0x9B, admin_key_path);
  key_meta_t meta;
  if (ck_read_key_metadata(admin_key_path, &meta) < 0) return -1;
  meta.touch_policy = P2 == 0xFE ? TOUCH_POLICY_ALWAYS : TOUCH_POLICY_NEVER;
  if (write_file(admin_key_path, DATA + 3, 0, 24, 1) < 0) return -1;
  if (ck_write_key_metadata(admin_key_path, &meta) < 0) return -1;
  const uint8_t is_default = !memcmp(DATA + 3, DEFAULT_MGMT_KEY, 24);
  if (write_attr(admin_key_path, TAG_PIN_KEY_DEFAULT, &is_default, sizeof(is_default)) < 0) return -1;
  return 0;
}

static int piv_reset(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  if (pin_get_retries(&pin) > 0 || pin_get_retries(&puk) > 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  return piv_install(1);
}

__attribute__((noinline)) static int piv_import_asymmetric_key(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  char key_path[MAX_KEY_PATH_LEN];
  if (!piv_is_asymmetric_key_id(P2)) {
    DBG_MSG("Unknown key file\n");
    EXCEPT(SW_WRONG_P1P2);
  }
  piv_key_path(P2, key_path);

  const key_type_t key_type = algo_id_to_key_type(P1);
  if (key_type == KEY_TYPE_PKC_END) EXCEPT(SW_WRONG_P1P2);
  if (P2 == 0xF9 && key_type != SECP256R1) EXCEPT(SW_WRONG_P1P2);

  ck_key_t key;
  uint16_t error_sw = SW_NO_ERROR;
  int write_err;

  if (piv_import_key_id == 0) {
    const int meta_sw = piv_read_key_metadata_or_default(P2, &key.meta, key_path);
    if (meta_sw == SW_WRONG_P1P2) EXCEPT(meta_sw);
    if (meta_sw < 0) return -1;
    key.meta.type = key_type;
    ck_parse_piv_stream_init(&piv_import_stream, &key);
    piv_import_key_id = P2;
    piv_import_key_type = key_type;
    piv_import_len = 0;
  } else if (piv_import_key_id != P2 || piv_import_key_type != key_type) {
    error_sw = SW_WRONG_DATA;
    goto fail;
  } else {
    if (pke_buffer_read(0, &key, sizeof(key)) < 0) {
      piv_import_reset();
      return -1;
    }
  }

  if ((uint32_t)piv_import_len + LC > CK_KEY_IMPORT_MAX_LENGTH) {
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  }
  const bool final = (CLA & 0x10) == 0;
  if (final) piv_pke_release(PIV_PKE_USE_IMPORT);
  const int err = ck_parse_piv_stream_update(&piv_import_stream, &key, DATA, LC, final);
  if (err == KEY_ERR_LENGTH) {
    DBG_MSG("Wrong length when importing\n");
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  }
  if (err == KEY_ERR_DATA) {
    DBG_MSG("Wrong data when importing\n");
    error_sw = SW_WRONG_DATA;
    goto fail;
  }
  if (err < 0) {
    DBG_MSG("Error when importing\n");
    error_sw = SW_UNABLE_TO_PROCESS;
    goto fail;
  }
  piv_import_len += LC;
  if ((CLA & 0x10) != 0) {
    if (piv_pke_acquire(PIV_PKE_USE_IMPORT) < 0 || pke_buffer_write(0, &key, sizeof(key)) < 0) {
      goto fail_proc;
    }
    memzero(&key, sizeof(key));
    return 0;
  }

  if (err != 1) {
    error_sw = SW_WRONG_LENGTH;
    goto fail;
  }
  write_err = ck_write_key(key_path, &key);
  memzero(&key, sizeof(key));
  piv_import_reset();
  if (write_err < 0) return -1;

  return 0;

fail:
  memzero(&key, sizeof(key));
  piv_import_reset();
  EXCEPT(error_sw);

fail_proc:
  memzero(&key, sizeof(key));
  piv_import_reset();
  return -1;
}

static int piv_move_delete_key(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  char source_path[MAX_KEY_PATH_LEN];
  if (!piv_is_regular_key_id(P2)) EXCEPT(SW_WRONG_P1P2);
  piv_key_path(P2, source_path);

  if (P1 == 0xFF) {
    if (piv_remove_file_if_present(source_path) < 0) return -1;
    return 0;
  }

  char target_path[MAX_KEY_PATH_LEN];
  if (!piv_is_regular_key_id(P1)) EXCEPT(SW_WRONG_P1P2);
  piv_key_path(P1, target_path);

  key_meta_t meta;
  const int source_rc = ck_read_key_metadata(source_path, &meta);
  if (source_rc == LFS_ERR_NOENT || (source_rc >= 0 && meta.type == KEY_TYPE_PKC_END))
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (source_rc < 0) return -1;

  const int target_rc = ck_read_key_metadata(target_path, &meta);
  if (target_rc >= 0 && meta.type != KEY_TYPE_PKC_END) EXCEPT(SW_WRONG_DATA);
  if (target_rc < 0 && target_rc != LFS_ERR_NOENT) return -1;

  if (fs_rename(source_path, target_path) < 0) return -1;
  return 0;
}

static int piv_attest(const CAPDU *capdu, RAPDU *rapdu) {
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  char target_path[MAX_KEY_PATH_LEN];
  if (!piv_is_asymmetric_key_id(P1)) EXCEPT(SW_WRONG_P1P2);
  piv_key_path(P1, target_path);

  char attestation_key_path[MAX_KEY_PATH_LEN];
  piv_key_path(0xF9, attestation_key_path);
  const int sw = piv_attestation_generate(P1, target_path, attestation_key_path);
  if (sw < 0) return -1;
  if (sw != SW_NO_ERROR) EXCEPT(sw);
  LL = 0;
  return 0;
}

_Static_assert(PIV_METADATA_DIRECTORY_MAX_SIZE <= APDU_BUFFER_SIZE,
               "PIV metadata directory must fit in one APDU response");

static int piv_metadata_directory_add_slot(uint8_t slot, uint8_t *data, uint16_t *pos) {
  uint8_t flags = 0;
  key_meta_t meta;
  char key_path[MAX_KEY_PATH_LEN];
  piv_key_path(slot, key_path);
  const int key_rc = ck_read_key_metadata(key_path, &meta);
  if (key_rc >= 0 && meta.type != KEY_TYPE_PKC_END) {
    flags |= PIV_METADATA_DIRECTORY_FLAG_KEY;
  } else if (key_rc < 0 && key_rc != LFS_ERR_NOENT) {
    return -1;
  }

  char cert_path[MAX_DO_PATH_LEN];
  piv_cert_path(slot, cert_path);
  const int cert_size = get_file_size(cert_path);
  if (cert_size > 0) {
    flags |= PIV_METADATA_DIRECTORY_FLAG_CERT;
  } else if (cert_size < 0 && cert_size != LFS_ERR_NOENT) {
    return -1;
  }

  if (flags == 0) return 0;
  data[(*pos)++] = slot;
  data[(*pos)++] = flags;
  if ((flags & PIV_METADATA_DIRECTORY_FLAG_KEY) != 0) {
    data[(*pos)++] = key_type_to_algo_id(meta.type);
    data[(*pos)++] = meta.origin;
    data[(*pos)++] = meta.pin_policy;
    data[(*pos)++] = meta.touch_policy;
  } else {
    memset(data + *pos, 0, PIV_METADATA_DIRECTORY_ENTRY_SIZE - 2);
    *pos += PIV_METADATA_DIRECTORY_ENTRY_SIZE - 2;
  }
  return 0;
}

static int piv_get_metadata_directory(const CAPDU *capdu, RAPDU *rapdu) {
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  RDATA[0] = 0x01;
  RDATA[1] = 0x01;
  RDATA[2] = PIV_METADATA_DIRECTORY_VERSION;
  RDATA[3] = 0x02;
  RDATA[4] = 0; // Single-byte length of the entry payload, up to 24 * 6 bytes.
  uint16_t pos = PIV_METADATA_DIRECTORY_HEADER_SIZE;

  static const uint8_t primary_slots[] = {0x9A, 0x9C, 0x9D, 0x9E};
  for (size_t i = 0; i < sizeof(primary_slots); ++i) {
    if (piv_metadata_directory_add_slot(primary_slots[i], RDATA, &pos) < 0) return -1;
  }
  for (uint8_t slot = 0x82; slot <= 0x95; ++slot) {
    if (piv_metadata_directory_add_slot(slot, RDATA, &pos) < 0) return -1;
  }

  RDATA[4] = (uint8_t)(pos - PIV_METADATA_DIRECTORY_HEADER_SIZE);
  LL = pos;
  return 0;
}

__attribute__((noinline)) static int piv_get_metadata(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 == 0x01) return piv_get_metadata_directory(capdu, rapdu);
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);

  int pos = 0;
  switch (P2) {
  case 0x80: // PIN
  case 0x81: // PUK
  {
    const pin_t *p = P2 == 0x80 ? &pin : &puk;
    uint8_t default_value;
    if (read_attr(p->path, TAG_PIN_KEY_DEFAULT, &default_value, 1) < 0) return -1;
    const int default_retries = pin_get_default_retries(p);
    if (default_value < 0) return -1;
    const int retries = pin_get_retries(p);
    if (retries < 0) return -1;

    static const uint8_t pin_meta_prefix[] = {0x01, 0x01, 0xFF, 0x05, 0x01};
    static const uint8_t pin_meta_mid[] = {0x06, 0x02};
    memcpy(RDATA + pos, pin_meta_prefix, sizeof(pin_meta_prefix));
    pos += sizeof(pin_meta_prefix);
    RDATA[pos++] = default_value;
    memcpy(RDATA + pos, pin_meta_mid, sizeof(pin_meta_mid));
    pos += sizeof(pin_meta_mid);
    RDATA[pos++] = default_retries;
    RDATA[pos++] = retries;
    break;
  }
  case 0x9B: // Management
  {
    uint8_t default_value;
    key_meta_t meta;
    char admin_key_path[MAX_KEY_PATH_LEN];
    piv_key_path(0x9B, admin_key_path);
    if (read_attr(admin_key_path, TAG_PIN_KEY_DEFAULT, &default_value, 1) < 0) return -1;
    if (ck_read_key_metadata(admin_key_path, &meta) < 0) return -1;
    static const uint8_t mgmt_meta_prefix[] = {0x01, 0x01, ALG_AES_192, 0x02, 0x02, 0x00};
    memcpy(RDATA + pos, mgmt_meta_prefix, sizeof(mgmt_meta_prefix));
    pos += sizeof(mgmt_meta_prefix);
    RDATA[pos++] = meta.touch_policy;
    RDATA[pos++] = 0x05;
    RDATA[pos++] = 0x01;
    RDATA[pos++] = default_value;
    break;
  }
  case 0x9A: // Authentication
  case 0x9C: // Signing
  case 0x9D: // Key Management
  case 0x9E: // Card Authentication
  default: {
    char key_path[MAX_KEY_PATH_LEN];
    if (!piv_is_asymmetric_key_id(P2)) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    piv_key_path(P2, key_path);

    ck_key_t key;
    const int read_sw = piv_read_key_or_default(P2, &key, key_path);
    if (read_sw == SW_WRONG_P1P2) EXCEPT(read_sw);
    if (read_sw < 0) return -1;
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
    uint8_t prefix[16];
    memcpy(prefix, RDATA, pos);
    prefix[pos] = 0x04; // Public
    const int encoded_len = ck_encoded_public_key_length(key.meta.type, true);
    if (encoded_len < 0 || pos + 1 > (int)sizeof(prefix)) {
      memzero(&key, sizeof(key));
      EXCEPT(SW_WRONG_LENGTH);
    }
    if (pos + 1 + encoded_len > APDU_COMMAND_BUFFER_SIZE) {
      uint16_t response_len = 0;
      const int ret = piv_set_public_key_response(&key, prefix, pos + 1, RDATA, &response_len);
      memzero(&key, sizeof(key));
      if (ret < 0) return -1;
      LL = apdu_response_source_active() ? 0 : response_len;
      return 0;
    }
    RDATA[pos++] = 0x04;
    const int len = ck_encode_public_key(&key, &RDATA[pos], true);
    if (len < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    pos += len;
    memzero(&key, sizeof(key));
    break;
  }
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
  device_config_fill_serial(RDATA);
  LL = 4;
  return 0;
}

static int piv_algorithm_extension(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x01 && P1 != 0x02) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  if (P1 == 0x01) {
    memcpy(RDATA, &alg_ext_cfg, sizeof(alg_ext_cfg));
    LL = sizeof(alg_ext_cfg);
  } else {
#ifndef FUZZ
    if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
    if (LC != sizeof(alg_ext_cfg)) EXCEPT(SW_WRONG_LENGTH);
    piv_algorithm_extension_config_t cfg;
    memcpy(&cfg, DATA, sizeof(cfg));
    if (!piv_algorithm_extension_config_valid(&cfg)) EXCEPT(SW_WRONG_DATA);
    if (piv_platform_algorithm_extension_config_write(&cfg) < 0) return -1;
    // Effective immediately
    alg_ext_cfg = cfg;
  }

  return 0;
}

int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (!(CLA == 0x00 || (CLA == 0x10 && (INS == PIV_INS_PUT_DATA || INS == PIV_INS_IMPORT_ASYMMETRIC_KEY ||
                                        INS == PIV_INS_GENERAL_AUTHENTICATE)))) {
    piv_abort_chained_state();
    EXCEPT(SW_CLA_NOT_SUPPORTED);
  }

  if (INS != PIV_INS_PUT_DATA) piv_do_write = -1;
  if (INS != PIV_INS_GET_DATA_RESPONSE) piv_do_read = -1;
  if (INS != PIV_INS_IMPORT_ASYMMETRIC_KEY) piv_import_reset();
  if (INS != PIV_INS_GENERAL_AUTHENTICATE) piv_auth_reset();

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
  case PIV_INS_SET_PIN_RETRIES:
    ret = piv_set_pin_retries(capdu, rapdu);
    break;
  case PIV_INS_RESET:
    ret = piv_reset(capdu, rapdu);
    break;
  case PIV_INS_IMPORT_ASYMMETRIC_KEY:
    ret = piv_import_asymmetric_key(capdu, rapdu);
    break;
  case PIV_INS_MOVE_DELETE_KEY:
    ret = piv_move_delete_key(capdu, rapdu);
    break;
  case PIV_INS_GET_VERSION:
    ret = piv_get_version(capdu, rapdu);
    break;
  case PIV_INS_GET_SERIAL:
    ret = piv_get_serial(capdu, rapdu);
    break;
  case PIV_INS_ATTEST:
    ret = piv_attest(capdu, rapdu);
    break;
  case PIV_INS_GET_METADATA:
    ret = piv_get_metadata(capdu, rapdu);
    break;
  case PIV_INS_ALGORITHM_EXTENSION:
    ret = piv_algorithm_extension(capdu, rapdu);
    break;
  default:
    piv_abort_chained_state();
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }

  if (ret < 0) {
    piv_abort_chained_state();
    EXCEPT(SW_UNABLE_TO_PROCESS);
  }
  if (SW != SW_NO_ERROR && (SW & 0xFF00u) != 0x6100u) piv_abort_chained_state();
  return 0;
}

int piv_process_apdu_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu) {
  uint8_t applet_get_response = 0;

  if (capdu->extended) {
    piv_abort_chained_state();
    LL = 0;
    SW = SW_WRONG_LENGTH;
    return 0;
  }

  if (INS == PIV_INS_GET_DATA) {
    piv_state = PIV_STATE_GET_DATA;
    applet_get_response = 1;
  } else if ((piv_state == PIV_STATE_GET_DATA || piv_state == PIV_STATE_GET_DATA_RESPONSE) && INS == 0xC0) {
    piv_state = PIV_STATE_GET_DATA_RESPONSE;
    applet_get_response = 1;
  } else {
    piv_state = PIV_STATE_OTHER;
  }

  return apdu_process_streaming_message(rapdu_chaining, capdu, rapdu,
                                        apdu_is_get_response(capdu) && !applet_get_response, APDU_BUFFER_SIZE,
                                        piv_process_apdu);
}

// for testing without authentication
#ifdef TEST
void set_admin_status(const int status) { in_admin_status = status; }
#endif
