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
#if defined(RUST_CORE_CTAP) || defined(RUST_CORE_PIV)
// Keep the SM3 context out of the ordinary ECC signing call's stack frame.
__attribute__((noinline)) int32_t ck_sm2_message_digest(ecc_key_t *key, const uint8_t *input, size_t length,
                                                        uint8_t *out) {
  if (ck_ecc_complete_key(SM2, key) < 0 || sm2_z(SM2_ID_DEFAULT, key, out) < 0) return -1;
  sm3_ctx_t hash;
  sm3_init(&hash);
  sm3_update(&hash, out, SM3_DIGEST_LENGTH);
  sm3_update(&hash, input, length);
  sm3_final(&hash, out);
  memzero(&hash, sizeof(hash));
  return SM3_DIGEST_LENGTH;
}

#endif

// Isolate message-signing scratch from Weierstrass operations under LTO.
static __attribute__((noinline)) int ed25519_message_sign(ecc_key_t *key, const uint8_t *input, size_t length,
                                                          uint8_t *out) {
  if (ck_ecc_complete_key(ED25519, key) != 0 || ecc_sign(ED25519, key, input, length, out) != 0) {
    return -1;
  }
  return (int)SIGNATURE_LENGTH[ED25519];
}

// Native ECC borrows the aligned payload of the shared RSA-capacity workspace.
static ecc_key_t *ecc_view(rsa_key_t *material) {
  return (ecc_key_t *)(void *)((uint8_t *)material + CK_KEY_METADATA_BYTES);
}

int32_t ck_key_ec_generate(uint8_t alg, rsa_key_t *material) { return ecc_generate(alg, ecc_view(material)); }

int32_t ck_key_ec_validate(uint8_t alg, rsa_key_t *material) {
  ecc_key_t *key = ecc_view(material);
  return ecc_verify_private_key(alg, key) ? ck_ecc_complete_key(alg, key) : -1;
}

int32_t ck_key_ec_public(uint8_t alg, rsa_key_t *material, uint8_t *out) {
  ecc_key_t *key = ecc_view(material);
  if (ck_ecc_complete_key(alg, key) != 0) return -1;
  memcpy(out, key->pub, PUBLIC_KEY_LENGTH[alg]);
#if defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
  if (alg == X25519) swap_big_number_endian(out);
#endif
  return (int32_t)PUBLIC_KEY_LENGTH[alg];
}

int32_t ck_key_ec_sign(uint8_t alg, rsa_key_t *material, const uint8_t *input, size_t n, uint8_t *out,
                       size_t capacity) {
  if (capacity < SIGNATURE_LENGTH[alg]) return -1;
  ecc_key_t *key = ecc_view(material);
  if (alg == ED25519) return ed25519_message_sign(key, input, n, out);
  if (!IS_SHORT_WEIERSTRASS(alg) || n != PRIVATE_KEY_LENGTH[alg]) return -1;
  uint8_t *scratch = (uint8_t *)key + ECC_SCRATCH_OFFSET;
  if (K__short_weierstrass_sign_with_scratch(alg, key, input, n, out, scratch, ECC_SCRATCH_BYTES) != 0) return -1;
  return (int32_t)SIGNATURE_LENGTH[alg];
}

int32_t ck_key_ec_agree(uint8_t alg, rsa_key_t *material, const uint8_t *input, size_t n, uint8_t *out) {
  if (alg == ED25519 || n != PUBLIC_KEY_LENGTH[alg] || ecdh(alg, ecc_view(material)->pri, input, out) != 0) return -1;
  return (int32_t)PRIVATE_KEY_LENGTH[alg];
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
