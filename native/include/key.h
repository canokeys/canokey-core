#ifndef CANOKEY_CORE_KEY_H
#define CANOKEY_CORE_KEY_H

#include <algo.h>
#include <common.h>
#include <ecc.h>
#include <ml-dsa-65.h>
#include <ml-kem-768.h>
#include <rsa.h>
#include <stdbool.h>

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

#endif // CANOKEY_CORE_KEY_H
