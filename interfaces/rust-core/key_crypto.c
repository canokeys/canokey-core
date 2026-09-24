// SPDX-License-Identifier: Apache-2.0
// Primitive adapter. KeyMaterial is a borrowed native ABI view in the shared
// Rust session workspace, never a persisted native C struct.
#include "crypto_ops.h"
#include <ecc.h>
#include <rsa.h>
#include <sm3.h>
#include <memzero.h>
#include <stddef.h>
#include <string.h>
enum {
  RSA_MIN_BITS = 2048,
  RSA_BITS_STEP = 1024,
  PKCS1_V15_OVERHEAD = 11,
  ECC_SCRATCH_OFFSET = (sizeof(ecc_key_t) + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1),
  ECC_SCRATCH_BYTES = CK_KEY_BYTES - ECC_SCRATCH_OFFSET,
};
_Static_assert(sizeof(ecc_key_t) == MAX_EC_PRIVATE_KEY + MAX_EC_PUBLIC_KEY &&
                   offsetof(ecc_key_t, pub) == MAX_EC_PRIVATE_KEY,
               "ECC workspace ABI");
_Static_assert(sizeof(rsa_key_t) == CK_KEY_METADATA_BYTES + CK_KEY_BYTES &&
                   offsetof(rsa_key_t, e) == CK_KEY_METADATA_BYTES &&
                   offsetof(rsa_key_t, p) == CK_KEY_METADATA_BYTES + CK_RSA_EXPONENT_BYTES &&
                   offsetof(rsa_key_t, q) == offsetof(rsa_key_t, p) + CK_RSA_LIMB_BYTES &&
                   offsetof(rsa_key_t, dp) == offsetof(rsa_key_t, q) + CK_RSA_LIMB_BYTES &&
                   offsetof(rsa_key_t, dq) == offsetof(rsa_key_t, dp) + CK_RSA_LIMB_BYTES &&
                   offsetof(rsa_key_t, qinv) == offsetof(rsa_key_t, dq) + CK_RSA_LIMB_BYTES,
               "Rust KeyMaterial ABI");
#if !defined(RUST_CORE_CTAP) || defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
static int rsa_operation(uint8_t op, uint8_t alg, rsa_key_t *key, const uint8_t *in, size_t n, uint8_t *out) {
  key->nbits = (uint16_t)(RSA_MIN_BITS + RSA_BITS_STEP * (alg - RSA2048));
  int result = -1;
  size_t width = key->nbits / 8;
  switch (op) {
  case CK_KEY_GENERATE:
    result = rsa_generate_key(key, key->nbits);
    break;
  case CK_KEY_VALIDATE:
    result = rsa_check_crt_with_scratch(key, out, CK_RSA_OUTPUT_BYTES);
    break;
  case CK_KEY_PUBLIC:
    if (rsa_get_public_key(key, out) == 0) result = (int)width;
    break;
  case CK_KEY_RSA_RAW:
    if (n == width && rsa_private(key, in, out) == 0) result = (int)width;
    break;
  case CK_KEY_RSA_PKCS1_SIGN:
    if (n <= width - PKCS1_V15_OVERHEAD && rsa_sign_pkcs_v15(key, in, n, out) == 0) result = (int)width;
    break;
  case CK_KEY_RSA_PKCS1_DECIPHER: {
    size_t len = 0;
    uint8_t invalid = 0;
    if (n == width && rsa_decrypt_pkcs_v15(key, in, &len, out, &invalid) == 0 && !invalid) result = (int)len;
    break;
  }
  default:
    break;
  }
  return result;
}
#endif
// Keep the SM3 context out of the ordinary ECC signing call's stack frame.
static __attribute__((noinline)) int sm2_message_digest(ecc_key_t *key, const uint8_t *input,
                                                       size_t length, uint8_t *out) {
  if (ecc_complete_key(SM2, key) < 0 || sm2_z(SM2_ID_DEFAULT, key, out) < 0) return -1;
  sm3_ctx_t hash;
  sm3_init(&hash);
  sm3_update(&hash, out, SM3_DIGEST_LENGTH);
  sm3_update(&hash, input, length);
  sm3_final(&hash, out);
  memzero(&hash, sizeof(hash));
  return SM3_DIGEST_LENGTH;
}

static __attribute__((noinline)) int ecc_operation(uint8_t op, uint8_t alg, rsa_key_t *material, const uint8_t *in,
                                                   size_t n, uint8_t *out) {
  uint8_t *key = (uint8_t *)material + offsetof(rsa_key_t, e);
  ecc_key_t *ec = (ecc_key_t *)(void *)key;
  int result = -1;
  switch (op) {
  case CK_KEY_GENERATE:
    if (ecc_generate(alg, ec) == 0) {
      result = 0;
    }
    break;
  case CK_KEY_VALIDATE:
    if (ecc_verify_private_key(alg, ec) && ecc_complete_key(alg, ec) == 0) result = 0;
    break;
  case CK_KEY_PUBLIC:
    if (ecc_complete_key(alg, ec) == 0) {
      memcpy(out, ec->pub, PUBLIC_KEY_LENGTH[alg]);
      if (alg == X25519) swap_big_number_endian(out);
      result = (int)PUBLIC_KEY_LENGTH[alg];
    }
    break;
  case CK_KEY_EC_SIGN:
    if (IS_SHORT_WEIERSTRASS(alg) && n == PRIVATE_KEY_LENGTH[alg]) {
      // ECC uses only bytes [0,198); borrow the unused RSA-capacity tail.
      if (K__short_weierstrass_sign_with_scratch(alg, ec, in, n, out, key + ECC_SCRATCH_OFFSET, ECC_SCRATCH_BYTES) == 0)
        result = (int)SIGNATURE_LENGTH[alg];
    } else if (alg == ED25519 && ecc_complete_key(alg, ec) == 0 && ecc_sign(alg, ec, in, n, out) == 0)
      result = (int)SIGNATURE_LENGTH[alg];
    break;
  case CK_KEY_SM2_MESSAGE_DIGEST:
    if (alg == SM2) result = sm2_message_digest(ec, in, n, out);
    break;
  case CK_KEY_SM2_EXCHANGE:
#ifdef RUST_CORE_PIV
    if (alg == SM2) result = ck_sm2_exchange(ec, in, n, out);
#endif
    break;
  case CK_KEY_AGREE:
    if (alg != ED25519 && n == PUBLIC_KEY_LENGTH[alg] && ecdh(alg, ec->pri, in, out) == 0)
      result = (int)PRIVATE_KEY_LENGTH[alg];
    break;
  default:
    break;
  }
  return result;
}

int32_t ck_platform_key(uint8_t op, uint8_t alg, rsa_key_t *material, const uint8_t *in, size_t n, uint8_t *out,
                        size_t capacity) {
  if (alg > SM2 || capacity < CK_RSA_OUTPUT_BYTES) return -1;
#ifdef RUST_CORE_STACK_REPORT
  extern void ck_stack_context(uint8_t, uint8_t);
  ck_stack_context(op, alg);
#endif
  if (IS_RSA(alg)) {
#if !defined(RUST_CORE_CTAP) || defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
    return rsa_operation(op, alg, material, in, n, out);
#else
    // The independent CTAP profile has no RSA protocol operations.
    return -1;
#endif
  }
  return ecc_operation(op, alg, material, in, n, out);
}

#include <aes.h>
int32_t ck_platform_aes192(const uint8_t *key, const uint8_t *input, uint8_t *out) {
  return aes192_enc(input, out, key);
}

// Fixed-size P-256 signing avoids reserving the RSA workspace while a streamed
// CTAP response retains its small framing bytes in the shared session scratch.
int32_t ck_platform_p256_sign(const uint8_t scalar[32], const uint8_t digest[32], uint8_t out[64]) {
  ecc_key_t key = {0};
  memcpy(key.pri, scalar, 32);
  int r = ecc_sign(SECP256R1, &key, digest, 32, out);
  memzero(&key, sizeof(key));
  return r < 0 ? -1 : 0;
}
