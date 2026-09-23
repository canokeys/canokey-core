// SPDX-License-Identifier: Apache-2.0
// Primitive adapter. KeyMaterial is a borrowed native ABI view in the shared
// Rust session workspace, never a persisted native C struct.
#include <ecc.h>
#include <rsa.h>
#include <memzero.h>
#include <stddef.h>
#include <string.h>
_Static_assert(sizeof(ecc_key_t) == 198 && offsetof(ecc_key_t, pub) == 66, "ECC workspace ABI");
_Static_assert(sizeof(rsa_key_t) == 1288 && offsetof(rsa_key_t, e) == 4 && offsetof(rsa_key_t, p) == 8 &&
                   offsetof(rsa_key_t, q) == 264 && offsetof(rsa_key_t, dp) == 520 && offsetof(rsa_key_t, dq) == 776 &&
                   offsetof(rsa_key_t, qinv) == 1032,
               "Rust KeyMaterial ABI");
static int rsa_operation(uint8_t op, uint8_t alg, rsa_key_t *key, const uint8_t *in, size_t n, uint8_t *out) {
  key->nbits = (uint16_t)(2048 + 1024 * (alg - 5));
  int result = -1;
  size_t width = key->nbits / 8;
  switch (op) {
  case 0:
    result = rsa_generate_key(key, key->nbits);
    break;
  case 1:
    result = rsa_check_crt_with_scratch(key, out, 512);
    break;
  case 2:
    if (rsa_get_public_key(key, out) == 0) result = (int)width;
    break;
  case 3:
    if (n <= width - 11 && rsa_sign_pkcs_v15(key, in, n, out) == 0) result = (int)width;
    break;
  case 4: {
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
static __attribute__((noinline)) int ecc_operation(uint8_t op, uint8_t alg, rsa_key_t *material, const uint8_t *in,
                                                   size_t n, uint8_t *out) {
  uint8_t *key = (uint8_t *)material + offsetof(rsa_key_t, e);
  ecc_key_t *ec = (ecc_key_t *)(void *)key;
  int result = -1;
  switch (op) {
  case 0:
    if (ecc_generate(alg, ec) == 0) {
      result = 0;
    }
    break;
  case 1:
    if (ecc_verify_private_key(alg, ec) && ecc_complete_key(alg, ec) == 0) result = 0;
    break;
  case 2:
    if (ecc_complete_key(alg, ec) == 0) {
      memcpy(out, ec->pub, PUBLIC_KEY_LENGTH[alg]);
      if (alg == X25519) swap_big_number_endian(out);
      result = (int)PUBLIC_KEY_LENGTH[alg];
    }
    break;
  case 6:
    if (IS_SHORT_WEIERSTRASS(alg)) {
      // ECC uses only bytes [0,198); borrow the unused RSA-capacity tail.
      if (K__short_weierstrass_sign_with_scratch(alg, ec, in, n, out, key + 200, 1084) == 0)
        result = (int)SIGNATURE_LENGTH[alg];
    } else if (alg == ED25519 && ecc_complete_key(alg, ec) == 0 && ecc_sign(alg, ec, in, n, out) == 0)
      result = (int)SIGNATURE_LENGTH[alg];
    break;
  case 5:
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
  if (alg > 8 || capacity < 512) return -1;
#ifdef RUST_CORE_STACK_REPORT
  extern void ck_stack_context(uint8_t, uint8_t);
  ck_stack_context(op, alg);
#endif
  if (IS_RSA(alg)) return rsa_operation(op, alg, material, in, n, out);
  return ecc_operation(op, alg, material, in, n, out);
}
