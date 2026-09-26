// SPDX-License-Identifier: Apache-2.0
#ifndef CK_RUST_CRYPTO_OPS_H
#define CK_RUST_CRYPTO_OPS_H
#include <stddef.h>
#include <stdint.h>
#include <ecc.h>
#include <rsa.h>

// Distinct primitive failure; the Rust applet chooses the protocol status.
#define CK_KEY_INVALID_PADDING (-2)

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

// Native workspace ABI mirrored by ports/crypto.rs::key_layout and state types.
enum ck_crypto_workspace {
  CK_KEY_METADATA_BYTES = 4,
  CK_RSA_EXPONENT_BYTES = 4,
  CK_RSA_LIMB_BYTES = 256,
  CK_RSA_LIMBS = 5,
  CK_KEY_BYTES = CK_RSA_EXPONENT_BYTES + CK_RSA_LIMBS * CK_RSA_LIMB_BYTES,
  CK_RSA_OUTPUT_BYTES = 512,
  CK_CRYPTO_SCRATCH_BYTES = 2400,
  CK_HASH_STATE_BYTES = 256,
};
// Stable ABI, mirrored by the enums in rust/core/src/ports/crypto.rs.
enum ck_key_operation {
  CK_KEY_GENERATE = 0,
  CK_KEY_VALIDATE = 1,
  CK_KEY_PUBLIC = 2,
  CK_KEY_RSA_PKCS1_SIGN = 3,
  CK_KEY_RSA_PKCS1_DECIPHER = 4,
  CK_KEY_AGREE = 5,
  CK_KEY_EC_SIGN = 6,
  CK_KEY_RSA_RAW = 7,
  CK_KEY_SM2_EXCHANGE = 8,
  CK_KEY_SM2_MESSAGE_DIGEST = 9,
};
enum ck_stream_operation {
  CK_STREAM_PUBLIC_INIT = 0,
  CK_STREAM_READ = 1,
  CK_STREAM_SIGN_INIT = 2,
  CK_STREAM_SIGN_UPDATE = 3,
  CK_STREAM_SIGN_FINAL = 4,
  CK_STREAM_ABORT = 5,
  CK_STREAM_DECAPSULATE_INIT = 6,
  CK_STREAM_DECAPSULATE_UPDATE = 7,
  CK_STREAM_DECAPSULATE_FINAL = 8,
  CK_STREAM_SM2_IDENTITY = 9,
};
enum ck_digest_operation {
  CK_DIGEST_INIT = 0,
  CK_DIGEST_UPDATE = 1,
  CK_DIGEST_FINAL = 2,
  CK_DIGEST_ABORT = 3,
};
// Fixed SM2 exchange packet, mirrored by ports/crypto.rs::sm2_packet.
enum ck_sm2_packet {
  CK_SM2_PEER_STATIC = 32,
  CK_SM2_PEER_EPHEMERAL = 96,
  CK_SM2_OWN_ID = 160,
  CK_SM2_PEER_ID = 193,
  CK_SM2_ROLE = 226,
  CK_SM2_OUTPUT_LENGTH = 227,
  CK_SM2_SIZE = 228,
};

/* Buffers are borrowed for the call. Material/scratch use the native workspace
 * layout checked by the adapters; persisted keys are encoded by Rust. */
int32_t ck_platform_key(uint8_t op, uint8_t alg, rsa_key_t *material, const uint8_t *input, size_t length,
                        uint8_t *output, size_t capacity);
int32_t ck_platform_aes192(const uint8_t *key, const uint8_t *input, uint8_t *output);
int32_t ck_platform_stream(uint8_t op, uint8_t alg, void *scratch, const uint8_t *input, size_t length,
                               uint8_t *output, size_t capacity);
int32_t ck_platform_digest(uint8_t op, void *state, const uint8_t *input, size_t length, uint8_t *output,
                           size_t capacity);
/* Internal primitive adapter shared by key_crypto.c and piv_crypto.c. */
int32_t ck_sm2_exchange(ecc_key_t *key, const uint8_t *input, size_t length, uint8_t *output);
#endif

int32_t ck_platform_p256_sign(const uint8_t scalar[32], const uint8_t digest[32], uint8_t out[64]);
