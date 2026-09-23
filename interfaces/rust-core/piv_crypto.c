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
enum stream_kind { STREAM_PUBLIC = 1, STREAM_SIGNING = 2, STREAM_SIGNATURE = 3, STREAM_DECAPSULATING = 4 };
typedef struct {
  uint32_t kind, alg, emitted, position, length;
  union {
    struct {
      uint8_t seed[64], ciphertext[1088], public_key[1184];
    } kem;
    struct {
      union {
        mldsa_keygen_state_t keygen;
        mldsa_sign_state_t sign;
      } state;
      uint8_t stage[1312];
      SHA3_CTX_T hash;
      uint8_t mu[64];
    } dsa;
    struct {
      ecc_key_t key;
      sm3_ctx_t hash;
      uint8_t signature[64];
    } sm2;
    struct {
      ed25519_randomized_sign_state_t state;
      uint8_t signature[64];
    } ed;
  } data;
} stream_t;
_Static_assert(sizeof(stream_t) <= 2400, "Shared Rust crypto scratch size");
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
  memcpy(key.pri, seed, 32);
  int r = ecc_complete_key(ED25519, &key);
  if (r == 0) r = ed25519_randomized_sign_init(&s->data.ed.state, &key);
  memzero(&key, sizeof(key));
  return r;
}
static __attribute__((noinline)) int sm2_identity(stream_t *s, const uint8_t *input, size_t n) {
  uint8_t id[33], z[32];
  id[0] = (uint8_t)n;
  memcpy(id + 1, input, n);
  int r = sm2_z(n ? id : SM2_ID_DEFAULT, &s->data.sm2.key, z);
  if (r == 0) sm3_update(&s->data.sm2.hash, z, 32);
  memzero(z, 32);
  return r;
}
static __attribute__((noinline)) int sm2_finish(stream_t *s) {
  uint8_t digest[32];
  sm3_final(&s->data.sm2.hash, digest);
  int r = ecc_sign(SM2, &s->data.sm2.key, digest, 32, s->data.sm2.signature);
  memzero(digest, 32);
  if (r < 0) return -1;
  s->length = 64;
  return 64;
}
int32_t ck_platform_piv_stream(uint8_t op, uint8_t alg, void *scratch, const uint8_t *input, size_t n, uint8_t *out,
                               size_t capacity) {
  stream_t *s = scratch;
  if (op == CK_STREAM_ABORT) {
    if (s->alg == 11) {
      if (s->kind == STREAM_PUBLIC)
        ml_dsa_65_keygen_streaming_abort(&s->data.dsa.state.keygen);
      else if (s->kind == STREAM_SIGNING || s->kind == STREAM_SIGNATURE)
        ml_dsa_65_sign_streaming_abort(&s->data.dsa.state.sign);
    }
    if (s->alg == 3) ed25519_randomized_sign_clear(&s->data.ed.state);
    memzero(s, sizeof(*s));
    return 0;
  }
  if (op == CK_STREAM_PUBLIC_INIT || op == CK_STREAM_SIGN_INIT || op == CK_STREAM_DECAPSULATE_INIT) {
    memzero(s, sizeof(*s));
    s->alg = alg;
  }
  if (op == CK_STREAM_PUBLIC_INIT) {
    s->kind = STREAM_PUBLIC;
    if (alg == 10 && n == 64) {
      memcpy(s->data.kem.seed, input, 64);
      if (ml_kem_768_seed_to_public(s->data.kem.public_key, s->data.kem.seed) < 0) return -1;
      s->length = 1184;
      return 1184;
    }
    if (alg == 11 && n == 32) {
      memcpy(s->data.dsa.state.keygen.seed, input, 32);
      if (refill(s) < 0) return -1;
      return MLDSA_PK_BYTES;
    }
    return -1;
  }
  if (op == CK_STREAM_SIGN_INIT) {
    s->kind = STREAM_SIGNING;
    if (alg == 9 && n == 32) {
      memcpy(s->data.sm2.key.pri, input, 32);
      if (ecc_complete_key(SM2, &s->data.sm2.key) < 0) return -1;
      sm3_init(&s->data.sm2.hash);
      return 0;
    }
    if (alg == 11 && n == 32) {
      memcpy(s->data.dsa.state.sign.seed, input, 32);
      if (ml_dsa_65_seed_to_tr(s->data.dsa.mu, input) < 0) return -1;
      shake256_init(&s->data.dsa.hash);
      shake_update(&s->data.dsa.hash, s->data.dsa.mu, 64);
      const uint8_t prefix[2] = {0, 0};
      shake_update(&s->data.dsa.hash, prefix, 2);
      return 0;
    }
    if (alg == 3 && n == 32) {
      return ed_init(s, input);
    }
    return -1;
  }
  if (op == CK_STREAM_SM2_IDENTITY) {
    if (s->kind != STREAM_SIGNING || s->alg != 9 || n > 32) return -1;
    return sm2_identity(s, input, n);
  }
  if (op == CK_STREAM_SIGN_UPDATE) {
    if (s->kind != STREAM_SIGNING) return -1;
    if (s->alg == 9) {
      sm3_update(&s->data.sm2.hash, input, n);
      return 0;
    }
    if (s->alg == 11) {
      shake_update(&s->data.dsa.hash, input, n);
      return 0;
    }
    if (s->alg == 3) return ed25519_randomized_sign_update(&s->data.ed.state, input, n);
    return -1;
  }
  if (op == CK_STREAM_SIGN_FINAL) {
    if (s->kind != STREAM_SIGNING) return -1;
    s->kind = STREAM_SIGNATURE;
    if (s->alg == 9) {
      return sm2_finish(s);
    }
    if (s->alg == 11) {
      shake_finalize(&s->data.dsa.hash);
      shake_squeeze(&s->data.dsa.hash, s->data.dsa.mu, 64);
      if (refill(s) < 0) return -1;
      return MLDSA_SIG_BYTES;
    }
    if (s->alg == 3) {
      if (ed25519_randomized_sign_final(&s->data.ed.state, s->data.ed.signature) < 0) return -1;
      s->length = 64;
      return 64;
    }
    return -1;
  }
  if (op == CK_STREAM_DECAPSULATE_INIT) {
    if (alg != 10 || n != 64) return -1;
    s->kind = STREAM_DECAPSULATING;
    memcpy(s->data.kem.seed, input, 64);
    return 0;
  }
  if (op == CK_STREAM_DECAPSULATE_UPDATE) {
    if (s->kind != STREAM_DECAPSULATING || n > 1088 - s->position) return -1;
    memcpy(s->data.kem.ciphertext + s->position, input, n);
    s->position += n;
    return 0;
  }
  if (op == CK_STREAM_DECAPSULATE_FINAL) {
    if (s->kind != STREAM_DECAPSULATING || s->position != 1088 || capacity < 32) return -1;
    return ml_kem_768_decaps_seed(out, s->data.kem.ciphertext, s->data.kem.seed, s->data.kem.public_key) < 0 ? -1 : 32;
  }
  if (op == CK_STREAM_READ) {
    if (s->kind != STREAM_PUBLIC && s->kind != STREAM_SIGNATURE) return -1;
    size_t written = 0;
    uint32_t total =
        s->kind == STREAM_PUBLIC ? (s->alg == 10 ? 1184 : MLDSA_PK_BYTES) : (s->alg == 3 || s->alg == 9 ? 64 : MLDSA_SIG_BYTES);
    if (capacity > total - s->emitted) return -1;
    while (written < capacity) {
      if (s->position == s->length) {
        if (s->alg != 11 || refill(s) < 0) return -1;
      }
      size_t count = s->length - s->position;
      if (count > capacity - written) count = capacity - written;
      const uint8_t *source = s->alg == 10  ? s->data.kem.public_key
                              : s->alg == 3 ? s->data.ed.signature
                              : s->alg == 9 ? s->data.sm2.signature
                                            : s->data.dsa.stage;
      memcpy(out + written, source + s->position, count);
      s->position += count;
      written += count;
      s->emitted += count;
    }
    return (int32_t)written;
  }
  return -1;
}

#include <sha.h>
_Static_assert(sizeof(sha256_ctx_t) <= 256, "Rust digest state ABI");
int32_t ck_platform_digest(uint8_t op, void *state, const uint8_t *input, size_t n, uint8_t *out, size_t capacity) {
  sha256_ctx_t *ctx = state;
  switch (op) {
  case CK_DIGEST_INIT:
    memzero(state, 256);
    sha256_init(ctx);
    return 0;
  case CK_DIGEST_UPDATE:
    sha256_update(ctx, input, n);
    return 0;
  case CK_DIGEST_FINAL:
    if (capacity < 32) return -1;
    sha256_final(ctx, out);
    memzero(state, 256);
    return 0;
  case CK_DIGEST_ABORT:
#ifdef USE_MBEDCRYPTO
    psa_hash_abort(&ctx->op);
#endif
    memzero(state, 256);
    return 0;
  default:
    return -1;
  }
}

// Fixed primitive packet: ephemeral scalar, two peer points, two length-prefixed
// identities, role, output length. APDU validation remains in Rust.
int32_t ck_sm2_exchange(ecc_key_t *key, const uint8_t *in, size_t n, uint8_t *out) {
  if (n != 228 || in[160] > 32 || in[193] > 32 || in[226] > 1 || in[227] == 0 || in[227] > 128) return -1;
  ecc_key_t ephemeral = {0};
  memcpy(ephemeral.pri, in, 32);
  int r = ecc_complete_key(SM2, key);
  if (r == 0) r = ecc_complete_key(SM2, &ephemeral);
  if (r == 0)
    r = sm2_key_exchange((sm2_ke_role_t)in[226], in + 160, in + 193, key, &ephemeral, in + 32, in + 96, out, in[227]);
  memzero(&ephemeral, sizeof(ephemeral));
  return r < 0 ? -1 : in[227];
}
