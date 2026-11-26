// SPDX-License-Identifier: Apache-2.0
// Primitive streaming adapters only. Rust owns APDU parsing, authorization and storage.
#include "crypto_ops.h"
#include <ml-dsa-65.h>
#include <ml-dsa-44.h>
#include <mldsa-stream-cache.h>
#include <ml-kem-768.h>
#include <ml-kem-512.h>
#include <sha3.h>
#include <ecc.h>
#include <sm3.h>
#include <sm2_ke.h>
#include <memzero.h>
#include <string.h>
#include <stdint.h>
enum {
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
        struct {
          uint8_t seed[MLDSA_SEEDBYTES];
          SHA3_CTX_T hash;
          uint8_t tail[CK_MLDSA65_PREP_TAIL];
        } absorb;
        mldsa44_sign_state_t sign;
      } state;
      uint8_t stage[CK_MLDSA_STAGE_BYTES];
    } dsa;
    uint8_t public_key[MLDSA_PK_BYTES];
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
_Static_assert(offsetof(stream_t, data.dsa.state.absorb.tail) >=
                   offsetof(stream_t, data.dsa.state.sign.core.seed) + MLDSA_SEEDBYTES,
               "The prepared fragment survives initialization of phase and seed");
_Static_assert(_Alignof(stream_t) <= 8, "Rust CryptoScratch alignment");
static int is_dsa(uint32_t alg) { return alg == MLDSA65 || alg == MLDSA44; }
static uint32_t dsa_public_bytes(uint32_t alg) { return alg == MLDSA44 ? MLDSA44_PUBLIC_KEY_BYTES : MLDSA_PK_BYTES; }
static uint32_t dsa_signature_bytes(uint32_t alg) { return alg == MLDSA44 ? MLDSA44_SIGNATURE_BYTES : MLDSA_SIG_BYTES; }
#ifdef RUST_CORE_PIV
static int is_kem(uint32_t alg) { return alg == MLKEM768 || alg == MLKEM512; }
static uint32_t kem_public_bytes(uint32_t alg) {
  return alg == MLKEM512 ? MLKEM512_PUBLIC_KEY_BYTES : MLKEM768_PUBLIC_KEY_BYTES;
}
static uint32_t kem_ciphertext_bytes(uint32_t alg) {
  return alg == MLKEM512 ? MLKEM512_CIPHERTEXT_BYTES : MLKEM768_CIPHERTEXT_BYTES;
}
#endif
/* Portable backends may derive from seed on demand. CIU supplies the paired
 * overrides that fill the stage during tr generation and consume it at sign. */
__attribute__((weak)) int ck_mldsa_prepare(bool small, uint8_t *stage, uint8_t *tr, const uint8_t *seed) {
  (void)stage;
  return small ? ml_dsa_44_seed_to_tr(tr, seed) : ml_dsa_65_seed_to_tr(tr, seed);
}
__attribute__((weak)) int ck_mldsa_sign_chunk(bool small, uint8_t *stage, mldsa44_sign_state_t *state,
                                              const uint8_t *mu) {
  return small ? ml_dsa_44_sign_seed_mu_streaming(stage, CK_MLDSA_STAGE_BYTES, state, mu)
               : ml_dsa_65_sign_seed_mu_streaming(stage, CK_MLDSA_STAGE_BYTES, &state->core, mu);
}
__attribute__((weak)) int ck_mldsa_prepare65_tail(uint8_t *stage, uint8_t *tr, const uint8_t *seed, uint8_t *tail) {
  (void)tail;
  return ck_mldsa_prepare(false, stage, tr, seed);
}
__attribute__((weak)) int ck_mldsa_sign_first65(uint8_t *stage, mldsa44_sign_state_t *state, const uint8_t *mu,
                                                uint8_t *tail) {
  memzero(tail, CK_MLDSA65_PREP_TAIL);
  return ck_mldsa_sign_chunk(false, stage, state, mu);
}
static int refill(stream_t *s, const uint8_t *mu) {
  const uint8_t phase = s->data.dsa.state.sign.core.phase;
  const uint32_t total = dsa_signature_bytes(s->alg);
  if (!is_dsa(s->alg) || s->emitted >= total || (s->emitted != 0 && phase == 0)) return -1;
  int n = mu && s->alg == MLDSA65
              ? ck_mldsa_sign_first65(s->data.dsa.stage, &s->data.dsa.state.sign, mu, s->data.dsa.state.absorb.tail)
              : ck_mldsa_sign_chunk(s->alg == MLDSA44, s->data.dsa.stage, &s->data.dsa.state.sign, mu);
  if (n <= 0 || (size_t)n > sizeof(s->data.dsa.stage)) return -1;
  if ((uint32_t)n > total - s->emitted) return -1;
  const int last = s->emitted + (uint32_t)n == total;
  const uint8_t next = s->data.dsa.state.sign.core.phase;
  if (last != (next == 0)) return -1;
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
void ck_stream_abort(void *scratch) {
  stream_t *s = scratch;
  if (is_dsa(s->alg) && s->kind == STREAM_SIGNATURE) {
    if (s->alg == MLDSA44)
      ml_dsa_44_sign_streaming_abort(&s->data.dsa.state.sign);
    else
      ml_dsa_65_sign_streaming_abort(&s->data.dsa.state.sign.core);
  }
  if (s->alg == ED25519) ed25519_randomized_sign_clear(&s->data.ed.state);
  memzero(s, sizeof(*s));
}
int32_t ck_stream_read(void *scratch, uint8_t *out, size_t capacity) {
  stream_t *s = scratch;
  if (s->kind != STREAM_PUBLIC && s->kind != STREAM_SIGNATURE) return -1;
  size_t written = 0;
  uint32_t total;
  if (is_dsa(s->alg))
    total = s->kind == STREAM_PUBLIC ? dsa_public_bytes(s->alg) : dsa_signature_bytes(s->alg);
  else if (s->kind == STREAM_SIGNATURE && (s->alg == ED25519 || s->alg == SM2))
    total = EC_SIGNATURE_BYTES;
#ifdef RUST_CORE_PIV
  else if (s->kind == STREAM_PUBLIC && is_kem(s->alg))
    total = kem_public_bytes(s->alg);
#endif
  else
    return -1;
  if (s->emitted > total || capacity > total - s->emitted) return -1;
  while (written < capacity) {
    if (s->position == s->length) {
      if (s->kind != STREAM_SIGNATURE || !is_dsa(s->alg) || refill(s, NULL) < 0) return -1;
    }
    size_t count = s->length - s->position;
    if (count > capacity - written) count = capacity - written;
    const uint8_t *source = s->kind == STREAM_PUBLIC ? s->data.public_key
                            : s->alg == ED25519      ? s->data.ed.signature
                            : s->alg == SM2          ? s->data.sm2.signature
                                                     : s->data.dsa.stage;
#ifdef RUST_CORE_PIV
    if (is_kem(s->alg)) source = s->data.kem.public_key;
#endif
    memcpy(out + written, source + s->position, count);
    s->position += count;
    written += count;
    s->emitted += count;
  }
  return (int32_t)written;
}
int32_t ck_stream_public_init(uint8_t alg, void *scratch, const uint8_t *input, size_t n) {
  stream_t *s = scratch;
  memzero(s, sizeof(*s));
  s->alg = alg;
  s->kind = STREAM_PUBLIC;
  // Only PIV exposes ML-KEM public keys and decapsulation.
#ifdef RUST_CORE_PIV
  if (is_kem(alg) && n == MLKEM768_KEYGEN_SEED_BYTES) {
    memcpy(s->data.kem.seed, input, sizeof(s->data.kem.seed));
    int r = alg == MLKEM512 ? ml_kem_512_seed_to_public(s->data.kem.public_key, s->data.kem.seed)
                            : ml_kem_768_seed_to_public(s->data.kem.public_key, s->data.kem.seed);
    if (r < 0) return -1;
    s->length = kem_public_bytes(alg);
    return (int32_t)s->length;
  }
#endif
  if (is_dsa(alg) && n == MLDSA_SEEDBYTES) {
    mldsa_keygen_state_t state = {0};
    memcpy(state.seed, input, sizeof(state.seed));
    const size_t total = dsa_public_bytes(alg);
    do {
      const size_t remaining = total - s->length;
      uint8_t *dest = s->data.public_key + s->length;
      const int chunk = alg == MLDSA44 ? ml_dsa_44_keygen_streaming(dest, remaining, &state, NULL)
                                       : ml_dsa_65_keygen_streaming(dest, remaining, &state, NULL);
      /* Phase zero emits rho and four t1 rows for both parameter sets.
       * Only 65 has a second chunk, containing its last two rows. */
      const size_t expected = s->length == 0 ? MLDSA44_PUBLIC_KEY_BYTES : remaining;
      const unsigned next_phase = expected < remaining;
      if (chunk != (int)expected || state.phase != next_phase) break;
      s->length += expected;
    } while (state.phase != 0 && s->length < total);
    const bool complete = s->length == total && state.phase == 0;
    ml_dsa_65_keygen_streaming_abort(&state);
    if (!complete) {
      ck_stream_abort(s);
      return -1;
    }
    return (int32_t)total;
  }
  return -1;
}
int32_t ck_stream_rewind_public(void *scratch) {
  stream_t *s = scratch;
  if (s->kind != STREAM_PUBLIC || !is_dsa(s->alg) || s->emitted != dsa_public_bytes(s->alg)) return -1;
  s->position = s->emitted = 0;
  return 0;
}
int32_t ck_stream_sign_init(uint8_t alg, void *scratch, const uint8_t *input, size_t n) {
  stream_t *s = scratch;
  memzero(s, sizeof(*s));
  s->alg = alg;
  s->kind = STREAM_SIGNING;
  if (alg == SM2 && n == SM2_SCALAR_BYTES) {
    memcpy(s->data.sm2.key.pri, input, SM2_SCALAR_BYTES);
    if (ck_ecc_complete_key(SM2, &s->data.sm2.key) < 0) return -1;
    sm3_init(&s->data.sm2.hash);
    return 0;
  }
  if (is_dsa(alg) && n == MLDSA_SEEDBYTES) {
    uint8_t tr[MLDSA_CRHBYTES];
    int r = alg == MLDSA65 ? ck_mldsa_prepare65_tail(s->data.dsa.stage, tr, input, s->data.dsa.state.absorb.tail)
                           : ck_mldsa_prepare(true, s->data.dsa.stage, tr, input);
    if (r < 0) {
      ck_stream_abort(s);
      return -1;
    }
    memcpy(s->data.dsa.state.absorb.seed, input, MLDSA_SEEDBYTES);
    SHA3_CTX_T *hash = &s->data.dsa.state.absorb.hash;
    shake256_init(hash);
    shake_update(hash, tr, sizeof(tr));
    const uint8_t prefix[2] = {0, 0};
    shake_update(hash, prefix, sizeof(prefix));
    return 0;
  }
  if (alg == ED25519 && n == ED25519_SEED_BYTES) {
    return ed_init(s, input);
  }
  return -1;
}
int32_t ck_stream_sm2_identity(void *scratch, const uint8_t *input, size_t n) {
  stream_t *s = scratch;
  if (s->kind != STREAM_SIGNING || s->alg != SM2 || n > SM2_ID_MAX_BYTES) return -1;
  return sm2_identity(s, input, n);
}
int32_t ck_stream_sign_update(void *scratch, const uint8_t *input, size_t n) {
  stream_t *s = scratch;
  if (s->kind != STREAM_SIGNING) return -1;
  if (s->alg == SM2) {
    sm3_update(&s->data.sm2.hash, input, n);
    return 0;
  }
  if (is_dsa(s->alg)) {
    shake_update(&s->data.dsa.state.absorb.hash, input, n);
    return 0;
  }
  if (s->alg == ED25519) return ed25519_randomized_sign_update(&s->data.ed.state, input, n);
  return -1;
}
int32_t ck_stream_sign_final(void *scratch) {
  stream_t *s = scratch;
  if (s->kind != STREAM_SIGNING) return -1;
  s->kind = STREAM_SIGNATURE;
  if (s->alg == SM2) {
    return sm2_finish(s);
  }
  if (is_dsa(s->alg)) {
    uint8_t mu[MLDSA_CRHBYTES], seed[MLDSA_SEEDBYTES];
    shake_finalize(&s->data.dsa.state.absorb.hash);
    shake_squeeze(&s->data.dsa.state.absorb.hash, mu, sizeof(mu));
    memcpy(seed, s->data.dsa.state.absorb.seed, sizeof(seed));
    /* INIT cleared the union. Only seed and hash precede the prepared
     * fragment, which survives until the first signing call consumes it. */
    memzero(&s->data.dsa.state, offsetof(stream_t, data.dsa.state.absorb.tail) - offsetof(stream_t, data.dsa.state));
    memcpy(s->data.dsa.state.sign.core.seed, seed, sizeof(seed));
    memzero(seed, sizeof(seed));
    int r = refill(s, mu);
    memzero(mu, sizeof(mu));
    if (r < 0) {
      ck_stream_abort(s);
      return -1;
    }
    return (int32_t)dsa_signature_bytes(s->alg);
  }
  if (s->alg == ED25519) {
    if (ed25519_randomized_sign_final(&s->data.ed.state, s->data.ed.signature) < 0) return -1;
    s->length = EC_SIGNATURE_BYTES;
    return EC_SIGNATURE_BYTES;
  }
  return -1;
}
int32_t ck_stream_decapsulate_init(uint8_t alg, void *scratch, const uint8_t *input, size_t n) {
  stream_t *s = scratch;
  memzero(s, sizeof(*s));
  s->alg = alg;
#ifdef RUST_CORE_PIV
  if (!is_kem(alg) || n != MLKEM768_KEYGEN_SEED_BYTES) return -1;
  s->kind = STREAM_DECAPSULATING;
  memcpy(s->data.kem.seed, input, sizeof(s->data.kem.seed));
  return 0;
#else
  (void)input; (void)n;
  return -1;
#endif
}
int32_t ck_stream_decapsulate_update(void *scratch, const uint8_t *input, size_t n) {
  stream_t *s = scratch;
#ifdef RUST_CORE_PIV
  if (s->kind != STREAM_DECAPSULATING || !is_kem(s->alg) ||
      s->position > kem_ciphertext_bytes(s->alg) || n > kem_ciphertext_bytes(s->alg) - s->position)
    return -1;
  memcpy(s->data.kem.ciphertext + s->position, input, n);
  s->position += n;
  return 0;
#else
  (void)s; (void)input; (void)n;
  return -1;
#endif
}
int32_t ck_stream_decapsulate_final(void *scratch, uint8_t *out, size_t capacity) {
  stream_t *s = scratch;
#ifdef RUST_CORE_PIV
  if (s->kind != STREAM_DECAPSULATING || !is_kem(s->alg) || s->position != kem_ciphertext_bytes(s->alg) ||
      capacity < MLKEM768_SHARED_KEY_BYTES)
    return -1;
  int r = s->alg == MLKEM512
              ? ml_kem_512_decaps_seed(out, s->data.kem.ciphertext, s->data.kem.seed, s->data.kem.public_key)
              : ml_kem_768_decaps_seed(out, s->data.kem.ciphertext, s->data.kem.seed, s->data.kem.public_key);
  return r < 0 ? -1 : MLKEM768_SHARED_KEY_BYTES;
#else
  (void)s; (void)out; (void)capacity;
  return -1;
#endif
}
int32_t ck_platform_stream(uint8_t op, uint8_t alg, void *scratch, const uint8_t *input, size_t n, uint8_t *out,
                               size_t capacity) {
  switch (op) {
  case CK_STREAM_ABORT: ck_stream_abort(scratch); return 0;
  case CK_STREAM_READ: return ck_stream_read(scratch, out, capacity);
  case CK_STREAM_PUBLIC_INIT: return ck_stream_public_init(alg, scratch, input, n);
  case CK_STREAM_SIGN_INIT: return ck_stream_sign_init(alg, scratch, input, n);
  case CK_STREAM_SM2_IDENTITY: return ck_stream_sm2_identity(scratch, input, n);
  case CK_STREAM_SIGN_UPDATE: return ck_stream_sign_update(scratch, input, n);
  case CK_STREAM_SIGN_FINAL: return ck_stream_sign_final(scratch);
  case CK_STREAM_DECAPSULATE_INIT: return ck_stream_decapsulate_init(alg, scratch, input, n);
  case CK_STREAM_DECAPSULATE_UPDATE: return ck_stream_decapsulate_update(scratch, input, n);
  case CK_STREAM_DECAPSULATE_FINAL: return ck_stream_decapsulate_final(scratch, out, capacity);
  default: return -1;
  }
}

// Fixed primitive packet: ephemeral scalar, two peer points, two length-prefixed
// identities, role, output length. APDU validation remains in Rust.
// Keep the ephemeral key and ROM exchange scratch out of other ECC operations
// when LTO combines the primitive adapters.
__attribute__((noinline)) int32_t ck_sm2_exchange(ecc_key_t *key, const uint8_t *in, size_t n, uint8_t *out) {
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
