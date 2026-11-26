// SPDX-License-Identifier: Apache-2.0
// Imported native crypto ABI, owned by canokey-native-crypto.
#ifndef CK_RUST_CRYPTO_OPS_H
#define CK_RUST_CRYPTO_OPS_H
#include <stddef.h>
#include <stdint.h>
#include "port_abi.h"
#include <ecc.h>
#include <rsa.h>

// The CTAP-only adapter must not keep X25519 through the generic, out-of-line
// ECC public-key dispatcher. Keep the same primitive and validation semantics.
static inline int ck_ecc_complete_key(key_type_t alg, ecc_key_t *key) {
#if defined(RUST_CORE_CTAP) && !defined(RUST_CORE_OPENPGP) && !defined(RUST_CORE_PIV)
  if (IS_SHORT_WEIERSTRASS(alg)) return K__short_weierstrass_complete_key(alg, key);
  if (alg != ED25519) return -1;
  K__ed25519_publickey(key->pri, key->pub);
  return 0;
#else
  return ecc_complete_key(alg, key);
#endif
}

/* Buffers are borrowed for the call. Material/scratch use the native workspace
 * layout checked by the adapters; persisted keys are encoded by Rust. */
/* The caller selects a supported ECC algorithm and supplies sufficient output. */
int32_t ck_key_ec_generate(uint8_t alg, rsa_key_t *material);
int32_t ck_key_ec_validate(uint8_t alg, rsa_key_t *material);
int32_t ck_key_ec_public(uint8_t alg, rsa_key_t *material, uint8_t *output);
int32_t ck_key_ec_sign(uint8_t alg, rsa_key_t *material, const uint8_t *input, size_t length, uint8_t *output,
                       size_t capacity);
int32_t ck_key_ec_agree(uint8_t alg, rsa_key_t *material, const uint8_t *input, size_t length, uint8_t *output);
int32_t ck_sm2_message_digest(ecc_key_t *key, const uint8_t *input, size_t length, uint8_t *output);
int32_t ck_platform_aes192(const uint8_t *key, const uint8_t *input, uint8_t *output);
/* The caller owns the lifecycle and validates all lengths and offsets. */
void ck_stream_abort(void *scratch, uint8_t alg, uint8_t signature);
const uint8_t *ck_stream_output(const void *scratch, uint8_t alg, uint8_t signature);
int32_t ck_stream_refill(void *scratch, uint8_t alg, size_t remaining);
int32_t ck_stream_public_init(uint8_t alg, void *scratch, const uint8_t *input);
int32_t ck_stream_sign_init(uint8_t alg, void *scratch, const uint8_t *input);
int32_t ck_stream_sm2_identity(void *scratch, const uint8_t *input, size_t n);
int32_t ck_stream_sign_update(void *scratch, uint8_t alg, const uint8_t *input, size_t n);
int32_t ck_stream_sign_final(void *scratch, uint8_t alg, size_t total);
void ck_stream_decapsulate_init(void *scratch, const uint8_t *input);
void ck_stream_decapsulate_update(void *scratch, size_t offset, const uint8_t *input, size_t n);
int32_t ck_stream_decapsulate_final(void *scratch, uint8_t alg, uint8_t *out);
/* Incremental SHA-256. State is an aligned CK_HASH_STATE_BYTES reservation.
 * Return zero on success; final rejects capacities below 32 before mutation.
 * Final and abort erase state. Abort also releases host PSA resources. */
int32_t ck_digest_init(void *state);
int32_t ck_digest_update(void *state, const uint8_t *input, size_t length);
int32_t ck_digest_final(void *state, uint8_t *output, size_t capacity);
int32_t ck_digest_abort(void *state);
/* Internal primitive adapter shared by key_crypto.c and piv_crypto.c. */
int32_t ck_sm2_exchange(ecc_key_t *key, const uint8_t *input, size_t length, uint8_t *output);
int32_t ck_platform_p256_sign(const uint8_t scalar[32], const uint8_t digest[32], uint8_t out[64]);
#endif
