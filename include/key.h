#ifndef CANOKEY_CORE_KEY_H
#define CANOKEY_CORE_KEY_H

#include <algo.h>
#include <common.h>
#include <ecc.h>
#include <ml-dsa-65.h>
#include <ml-kem-768.h>
#include <rsa.h>
#include <stdbool.h>

#define KEY_ERR_LENGTH (-1)
#define KEY_ERR_DATA (-2)
#define KEY_ERR_PROC (-3)

#define CK_KEY_IMPORT_MAX_LENGTH 2048

typedef struct {
  uint16_t total_len;
  uint16_t processed;
  uint16_t template_end;
  uint16_t comp_len[6];
  uint16_t data_len;
  uint16_t comp_off;
  uint8_t phase;
  uint8_t comp_idx;
  uint8_t rsa;
  tlv_len_stream_t tlv_len;
} ck_openpgp_stream_t;

typedef struct {
  uint16_t processed;
  uint16_t comp_len;
  uint16_t comp_off;
  uint8_t phase;
  uint8_t comp_idx;
  uint8_t policy_tag;
  uint8_t rsa;
  uint8_t mldsa;
  uint8_t mlkem;
  tlv_len_stream_t tlv_len;
} ck_piv_stream_t;

// Usage values are flags and may be combined for protocol-defined unrestricted keys.
typedef enum {
  SIGN = 0x01,
  ENCRYPT = 0x02,
  KEY_AGREEMENT = 0x04,
  KEY_USAGE_ANY = SIGN | ENCRYPT | KEY_AGREEMENT,
} key_usage_t;

typedef enum {
  KEY_ORIGIN_NOT_PRESENT = 0x00,
  KEY_ORIGIN_GENERATED = 0x01,
  KEY_ORIGIN_IMPORTED = 0x02,
} key_origin_t;

typedef enum {
  PIN_POLICY_DEFAULT = 0x00,
  PIN_POLICY_NEVER = 0x01,
  PIN_POLICY_ONCE = 0x02,
  PIN_POLICY_ALWAYS = 0x03,
} pin_policy_t;

typedef enum {
  TOUCH_POLICY_DEFAULT = 0x00,   // disabled in both OpenPGP and PIV
  TOUCH_POLICY_NEVER = 0x01,     // not used in OpenPGP; the same as default in PIV
  TOUCH_POLICY_ALWAYS = 0x02,    // not used in OpenPGP; enabled in PIV without cache
  TOUCH_POLICY_CACHED = 0x03,    // enabled in OpenPGP; enabled in PIV with cache
  TOUCH_POLICY_PERMANENT = 0x04, // permanently enabled in OpenPGP; not used in PIV
} touch_policy_t;

typedef struct {
  key_type_t type;
  key_origin_t origin;
  key_usage_t usage;
  pin_policy_t pin_policy;
  touch_policy_t touch_policy;
} key_meta_t;

typedef struct {
  uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES];
} mlkem768_private_key_t;

typedef struct {
  key_meta_t meta;
  union {
    rsa_key_t rsa;
    ecc_key_t ecc;
    mldsa65_private_key_t mldsa;
    mlkem768_private_key_t mlkem;
    uint8_t data[0];
  };
} ck_key_t;

_Static_assert(sizeof(mldsa65_private_key_t) == MLDSA_SEEDBYTES + MLDSA_TRBYTES,
               "ML-DSA persistent private material must be seed || tr");
_Static_assert(sizeof(mldsa65_private_key_t) <= sizeof(rsa_key_t),
               "ML-DSA private material must not enlarge ck_key_t");
_Static_assert(sizeof(mlkem768_private_key_t) == MLKEM768_KEYGEN_SEED_BYTES,
               "ML-KEM persistent private material must contain only d || z");
_Static_assert(sizeof(mlkem768_private_key_t) <= sizeof(rsa_key_t),
               "ML-KEM private material must not enlarge ck_key_t");

void ck_key_init_empty(ck_key_t *key, key_type_t type, key_usage_t usage, pin_policy_t pin_policy,
                       touch_policy_t touch_policy);

#define CK_OPENPGP_ALGO_ATTR_COUNT (SECP521R1 + 1)
#define CK_OPENPGP_ALGO_ATTR_SIZE 12
extern const uint8_t CK_OPENPGP_ALGO_ATTR[CK_OPENPGP_ALGO_ATTR_COUNT][CK_OPENPGP_ALGO_ATTR_SIZE];

int ck_curve_oid(key_type_t type, const uint8_t **oid, uint8_t *oid_len);

/**
 * Encode public key
 *
 * @param key            key type
 * @param buf            buffer
 * @param include_length encode the length or not
 * @return encoded length
 */
int ck_encode_public_key(ck_key_t *key, uint8_t *buf, bool include_length);
int ck_encoded_public_key_length(key_type_t type, bool include_length);

/**
 * Parse the key imported to PIV in chained chunks.
 *
 * Initialize @c st with @ref ck_parse_piv_stream_init, then feed each
 * APDU chunk via @ref ck_parse_piv_stream_update.  origin is set to
 * KEY_ORIGIN_IMPORTED on success.
 */
void ck_parse_piv_stream_init(ck_piv_stream_t *st, ck_key_t *key);
int ck_parse_piv_stream_update(ck_piv_stream_t *st, ck_key_t *key, const uint8_t *buf, size_t buf_len, bool final);

int ck_parse_piv_policies(ck_key_t *key, const uint8_t *buf, size_t buf_len);

void ck_parse_openpgp_stream_init(ck_openpgp_stream_t *st, ck_key_t *key, size_t total_len);
int ck_parse_openpgp_stream_update(ck_openpgp_stream_t *st, ck_key_t *key, const uint8_t *buf, size_t buf_len,
                                   bool final);

int ck_read_key_metadata(const char *path, key_meta_t *meta);

int ck_write_key_metadata(const char *path, const key_meta_t *meta);

int ck_read_key(const char *path, ck_key_t *key);

int ck_write_key(const char *path, const ck_key_t *key);

int ck_generate_key(ck_key_t *key);

int ck_sign(const ck_key_t *key, const uint8_t *input, size_t input_len, uint8_t *sig);

#endif // CANOKEY_CORE_KEY_H
