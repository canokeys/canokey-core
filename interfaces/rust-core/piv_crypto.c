// SPDX-License-Identifier: Apache-2.0
// Primitive streaming adapters only. Rust owns APDU parsing, authorization and storage.
#include "crypto_ops.h"
#include <ml-dsa-65.h>
#include <ml-kem-768.h>
#include <sha3.h>
#include <ecc.h>
#include <sm3.h>
#include <sm2_ke.h>
#include <memzero.h>
#include <string.h>
#include <stdint.h>
enum {
  MLDSA_STAGE_BYTES = 1312, // Bounded chunk reused for keygen and signing output.
  ED25519_SEED_BYTES = 32,
  EC_SIGNATURE_BYTES = 64,
  SM2_SCALAR_BYTES = 32,
  SM2_ID_MAX_BYTES = 32,
  SM2_MAX_OUTPUT_BYTES = 128,
};
enum stream_kind { STREAM_PUBLIC = 1, STREAM_SIGNING = 2, STREAM_SIGNATURE = 3, STREAM_DECAPSULATING = 4 };
// Stored inside Rust CryptoScratch, not on the stack. The union is valid for
// only one algorithm/operation at a time; INIT establishes it and ABORT clears it.
// On reads, emitted counts total output and position/length bound the current
// chunk. During ML-KEM decapsulation, position instead counts ciphertext input.
typedef struct {
  uint32_t kind, alg, emitted, position, length;
  union {
#ifdef RUST_CORE_PIV
    struct {
      uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES], ciphertext[MLKEM768_CIPHERTEXT_BYTES],
          public_key[MLKEM768_PUBLIC_KEY_BYTES];
    } kem;
#endif
    struct {
      union {
        mldsa_keygen_state_t keygen;
        mldsa_sign_state_t sign;
      } state;
      uint8_t stage[MLDSA_STAGE_BYTES];
      SHA3_CTX_T hash;
      uint8_t mu[MLDSA_CRHBYTES];
    } dsa;
    struct {
      ecc_key_t key;
      sm3_ctx_t hash;
      uint8_t signature[EC_SIGNATURE_BYTES];
    } sm2;
    struct {
      ed25519_randomized_sign_state_t state;
      uint8_t signature[EC_SIGNATURE_BYTES];
    } ed;
  } data;
} stream_t;
_Static_assert(sizeof(stream_t) <= CK_CRYPTO_SCRATCH_BYTES, "Shared Rust crypto scratch size");
// Advance the ML-DSA generator only after its previous stage bytes were read.
// This preserves one-pass output without retaining a full public key/signature.
static int refill(stream_t *s) {
  int n = s->kind == STREAM_PUBLIC ? ml_dsa_65_keygen_streaming(s->data.dsa.stage, sizeof(s->data.dsa.stage),
                                                                &s->data.dsa.state.keygen, NULL)
                                   : ml_dsa_65_sign_seed_mu_streaming(s->data.dsa.stage, sizeof(s->data.dsa.stage),
                                                                      &s->data.dsa.state.sign, s->data.dsa.mu);
  if (n <= 0) return -1;
  s->position = 0;
  s->length = (uint32_t)n;
  return 0;
}
// Keep algorithm-specific temporaries out of the PQ dispatch call path.
static __attribute__((noinline)) int ed_init(stream_t *s, const uint8_t *seed) {
  ecc_key_t key = {0};
  memcpy(key.pri, seed, ED25519_SEED_BYTES);
  int r = ck_ecc_complete_key(ED25519, &key);
  if (r == 0) r = ed25519_randomized_sign_init(&s->data.ed.state, &key);
  memzero(&key, sizeof(key));
  return r;
}
static __attribute__((noinline)) int sm2_identity(stream_t *s, const uint8_t *input, size_t n) {
  uint8_t id[1 + SM2_ID_MAX_BYTES], z[SM3_DIGEST_LENGTH];
  id[0] = (uint8_t)n;
  memcpy(id + 1, input, n);
  int r = sm2_z(n ? id : SM2_ID_DEFAULT, &s->data.sm2.key, z);
  if (r == 0) sm3_update(&s->data.sm2.hash, z, SM3_DIGEST_LENGTH);
  memzero(z, sizeof(z));
  return r;
}
static __attribute__((noinline)) int sm2_finish(stream_t *s) {
  uint8_t digest[SM3_DIGEST_LENGTH];
  sm3_final(&s->data.sm2.hash, digest);
  int r = ecc_sign(SM2, &s->data.sm2.key, digest, sizeof(digest), s->data.sm2.signature);
  memzero(digest, sizeof(digest));
  if (r < 0) return -1;
  s->length = EC_SIGNATURE_BYTES;
  return EC_SIGNATURE_BYTES;
}
int32_t ck_platform_stream(uint8_t op, uint8_t alg, void *scratch, const uint8_t *input, size_t n, uint8_t *out,
                               size_t capacity) {
  stream_t *s = scratch;
  if (op == CK_STREAM_ABORT) {
    if (s->alg == MLDSA65) {
      if (s->kind == STREAM_PUBLIC)
        ml_dsa_65_keygen_streaming_abort(&s->data.dsa.state.keygen);
      else if (s->kind == STREAM_SIGNING || s->kind == STREAM_SIGNATURE)
        ml_dsa_65_sign_streaming_abort(&s->data.dsa.state.sign);
    }
    if (s->alg == ED25519) ed25519_randomized_sign_clear(&s->data.ed.state);
    memzero(s, sizeof(*s));
    return 0;
  }
  if (op == CK_STREAM_PUBLIC_INIT || op == CK_STREAM_SIGN_INIT || op == CK_STREAM_DECAPSULATE_INIT) {
    memzero(s, sizeof(*s));
    s->alg = alg;
  }
  if (op == CK_STREAM_PUBLIC_INIT) {
    s->kind = STREAM_PUBLIC;
    // Only PIV exposes ML-KEM public keys and decapsulation.
#ifdef RUST_CORE_PIV
    if (alg == MLKEM768 && n == MLKEM768_KEYGEN_SEED_BYTES) {
      memcpy(s->data.kem.seed, input, sizeof(s->data.kem.seed));
      if (ml_kem_768_seed_to_public(s->data.kem.public_key, s->data.kem.seed) < 0) return -1;
      s->length = MLKEM768_PUBLIC_KEY_BYTES;
      return MLKEM768_PUBLIC_KEY_BYTES;
    }
#endif
    if (alg == MLDSA65 && n == MLDSA_SEEDBYTES) {
      memcpy(s->data.dsa.state.keygen.seed, input, MLDSA_SEEDBYTES);
      if (refill(s) < 0) return -1;
      return MLDSA_PK_BYTES;
    }
    return -1;
  }
  if (op == CK_STREAM_SIGN_INIT) {
    s->kind = STREAM_SIGNING;
    if (alg == SM2 && n == SM2_SCALAR_BYTES) {
      memcpy(s->data.sm2.key.pri, input, SM2_SCALAR_BYTES);
      if (ck_ecc_complete_key(SM2, &s->data.sm2.key) < 0) return -1;
      sm3_init(&s->data.sm2.hash);
      return 0;
    }
    if (alg == MLDSA65 && n == MLDSA_SEEDBYTES) {
      memcpy(s->data.dsa.state.sign.seed, input, MLDSA_SEEDBYTES);
      if (ml_dsa_65_seed_to_tr(s->data.dsa.mu, input) < 0) return -1;
      shake256_init(&s->data.dsa.hash);
      shake_update(&s->data.dsa.hash, s->data.dsa.mu, MLDSA_CRHBYTES);
      const uint8_t prefix[2] = {0, 0};
      shake_update(&s->data.dsa.hash, prefix, 2);
      return 0;
    }
    if (alg == ED25519 && n == ED25519_SEED_BYTES) {
      return ed_init(s, input);
    }
    return -1;
  }
  if (op == CK_STREAM_SM2_IDENTITY) {
    if (s->kind != STREAM_SIGNING || s->alg != SM2 || n > SM2_ID_MAX_BYTES) return -1;
    return sm2_identity(s, input, n);
  }
  if (op == CK_STREAM_SIGN_UPDATE) {
    if (s->kind != STREAM_SIGNING) return -1;
    if (s->alg == SM2) {
      sm3_update(&s->data.sm2.hash, input, n);
      return 0;
    }
    if (s->alg == MLDSA65) {
      shake_update(&s->data.dsa.hash, input, n);
      return 0;
    }
    if (s->alg == ED25519) return ed25519_randomized_sign_update(&s->data.ed.state, input, n);
    return -1;
  }
  if (op == CK_STREAM_SIGN_FINAL) {
    if (s->kind != STREAM_SIGNING) return -1;
    s->kind = STREAM_SIGNATURE;
    if (s->alg == SM2) {
      return sm2_finish(s);
    }
    if (s->alg == MLDSA65) {
      shake_finalize(&s->data.dsa.hash);
      shake_squeeze(&s->data.dsa.hash, s->data.dsa.mu, MLDSA_CRHBYTES);
      if (refill(s) < 0) return -1;
      return MLDSA_SIG_BYTES;
    }
    if (s->alg == ED25519) {
      if (ed25519_randomized_sign_final(&s->data.ed.state, s->data.ed.signature) < 0) return -1;
      s->length = EC_SIGNATURE_BYTES;
      return EC_SIGNATURE_BYTES;
    }
    return -1;
  }
#ifdef RUST_CORE_PIV
  if (op == CK_STREAM_DECAPSULATE_INIT) {
    if (alg != MLKEM768 || n != MLKEM768_KEYGEN_SEED_BYTES) return -1;
    s->kind = STREAM_DECAPSULATING;
    memcpy(s->data.kem.seed, input, sizeof(s->data.kem.seed));
    return 0;
  }
  if (op == CK_STREAM_DECAPSULATE_UPDATE) {
    if (s->kind != STREAM_DECAPSULATING || n > MLKEM768_CIPHERTEXT_BYTES - s->position) return -1;
    memcpy(s->data.kem.ciphertext + s->position, input, n);
    s->position += n;
    return 0;
  }
  if (op == CK_STREAM_DECAPSULATE_FINAL) {
    if (s->kind != STREAM_DECAPSULATING || s->position != MLKEM768_CIPHERTEXT_BYTES ||
        capacity < MLKEM768_SHARED_KEY_BYTES)
      return -1;
    return ml_kem_768_decaps_seed(out, s->data.kem.ciphertext, s->data.kem.seed, s->data.kem.public_key) < 0
               ? -1
               : MLKEM768_SHARED_KEY_BYTES;
  }
#endif
  if (op == CK_STREAM_READ) {
    if (s->kind != STREAM_PUBLIC && s->kind != STREAM_SIGNATURE) return -1;
    size_t written = 0;
    uint32_t total = s->kind == STREAM_PUBLIC
                         ? MLDSA_PK_BYTES
                         : (s->alg == ED25519 || s->alg == SM2 ? EC_SIGNATURE_BYTES : MLDSA_SIG_BYTES);
#ifdef RUST_CORE_PIV
    if (s->alg == MLKEM768) total = MLKEM768_PUBLIC_KEY_BYTES;
#endif
    if (capacity > total - s->emitted) return -1;
    while (written < capacity) {
      if (s->position == s->length) {
        if (s->alg != MLDSA65 || refill(s) < 0) return -1;
      }
      size_t count = s->length - s->position;
      if (count > capacity - written) count = capacity - written;
      const uint8_t *source = s->alg == ED25519 ? s->data.ed.signature
                              : s->alg == SM2     ? s->data.sm2.signature
                                                  : s->data.dsa.stage;
#ifdef RUST_CORE_PIV
      if (s->alg == MLKEM768) source = s->data.kem.public_key;
#endif
      memcpy(out + written, source + s->position, count);
      s->position += count;
      written += count;
      s->emitted += count;
    }
    return (int32_t)written;
  }
  return -1;
}

// Fixed primitive packet: ephemeral scalar, two peer points, two length-prefixed
// identities, role, output length. APDU validation remains in Rust.
int32_t ck_sm2_exchange(ecc_key_t *key, const uint8_t *in, size_t n, uint8_t *out) {
  if (n != CK_SM2_SIZE || in[CK_SM2_OWN_ID] > SM2_ID_MAX_BYTES || in[CK_SM2_PEER_ID] > SM2_ID_MAX_BYTES ||
      in[CK_SM2_ROLE] > 1 || in[CK_SM2_OUTPUT_LENGTH] == 0 || in[CK_SM2_OUTPUT_LENGTH] > SM2_MAX_OUTPUT_BYTES)
    return -1;
  ecc_key_t ephemeral = {0};
  memcpy(ephemeral.pri, in, SM2_SCALAR_BYTES);
  int r = ck_ecc_complete_key(SM2, key);
  if (r == 0) r = ck_ecc_complete_key(SM2, &ephemeral);
  if (r == 0)
    r = sm2_key_exchange((sm2_ke_role_t)in[CK_SM2_ROLE], in + CK_SM2_OWN_ID, in + CK_SM2_PEER_ID, key, &ephemeral,
                         in + CK_SM2_PEER_STATIC, in + CK_SM2_PEER_EPHEMERAL, out, in[CK_SM2_OUTPUT_LENGTH]);
  memzero(&ephemeral, sizeof(ephemeral));
  return r < 0 ? -1 : in[CK_SM2_OUTPUT_LENGTH];
}
