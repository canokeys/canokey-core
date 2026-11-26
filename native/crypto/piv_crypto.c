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
// One active primitive occupies the union at the start of Rust's workspace.
typedef union {
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
} stream_data_t;
_Static_assert(sizeof(stream_data_t) <= CK_STREAM_DATA_BYTES, "Shared Rust crypto scratch size");
_Static_assert(offsetof(stream_data_t, dsa.state.absorb.tail) >=
                   offsetof(stream_data_t, dsa.state.sign.core.seed) + MLDSA_SEEDBYTES,
               "The prepared fragment survives initialization of phase and seed");
_Static_assert(_Alignof(stream_data_t) <= CK_STREAM_DATA_ALIGN, "Rust CryptoScratch alignment");
static int is_dsa(uint8_t alg) { return alg == MLDSA44 || alg == MLDSA65; }
#ifdef RUST_CORE_PIV
static int is_kem(uint8_t alg) { return alg == MLKEM512 || alg == MLKEM768; }
#endif
/* Portable providers expose the public key as a four-row chunk and an optional two-row tail. */
__attribute__((weak)) int ck_mldsa_public(bool small, uint8_t *out, const uint8_t *seed) {
  mldsa_keygen_state_t state = {0};
  memcpy(state.seed, seed, sizeof(state.seed));
  const size_t first = MLDSA44_PUBLIC_KEY_BYTES;
  int n = small ? ml_dsa_44_keygen_streaming(out, first, &state, NULL)
                : ml_dsa_65_keygen_streaming(out, MLDSA_PK_BYTES, &state, NULL);
  bool complete = n == (int)first && state.phase == (small ? 0 : 1);
  if (complete && !small) {
    const size_t tail = MLDSA_PK_BYTES - first;
    n = ml_dsa_65_keygen_streaming(out + first, tail, &state, NULL);
    complete = n == (int)tail && state.phase == 0;
  }
  ml_dsa_65_keygen_streaming_abort(&state);
  return complete ? 0 : -1;
}
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
// The provider signals the final chunk by returning to phase zero.
static int refill(stream_data_t *s, uint8_t alg, const uint8_t *mu, size_t remaining) {
  if (!mu && s->dsa.state.sign.core.phase == 0) return -1;
  int n = mu && alg == MLDSA65 ? ck_mldsa_sign_first65(s->dsa.stage, &s->dsa.state.sign, mu, s->dsa.state.absorb.tail)
                               : ck_mldsa_sign_chunk(alg == MLDSA44, s->dsa.stage, &s->dsa.state.sign, mu);
  if (n <= 0 || (size_t)n > sizeof(s->dsa.stage) || (size_t)n > remaining) return -1;
  if (((size_t)n == remaining) != (s->dsa.state.sign.core.phase == 0)) return -1;
  return n;
}
// Keep algorithm-specific temporaries out of the PQ dispatch call path.
static __attribute__((noinline)) int ed_init(stream_data_t *s, const uint8_t *seed) {
  ecc_key_t key = {0};
  memcpy(key.pri, seed, ED25519_SEED_BYTES);
  int r = ck_ecc_complete_key(ED25519, &key);
  if (r == 0) r = ed25519_randomized_sign_init(&s->ed.state, &key);
  memzero(&key, sizeof(key));
  return r;
}
static __attribute__((noinline)) int sm2_identity(stream_data_t *s, const uint8_t *input, size_t n) {
  uint8_t id[1 + SM2_ID_MAX_BYTES], z[SM3_DIGEST_LENGTH];
  id[0] = (uint8_t)n;
  memcpy(id + 1, input, n);
  int r = sm2_z(n ? id : SM2_ID_DEFAULT, &s->sm2.key, z);
  if (r == 0) sm3_update(&s->sm2.hash, z, SM3_DIGEST_LENGTH);
  memzero(z, sizeof(z));
  return r;
}
static __attribute__((noinline)) int sm2_finish(stream_data_t *s) {
  uint8_t digest[SM3_DIGEST_LENGTH];
  sm3_final(&s->sm2.hash, digest);
  int r = ecc_sign(SM2, &s->sm2.key, digest, sizeof(digest), s->sm2.signature);
  memzero(digest, sizeof(digest));
  if (r < 0) return -1;
  return EC_SIGNATURE_BYTES;
}
void ck_stream_abort(void *scratch, uint8_t alg, uint8_t signature) {
  stream_data_t *s = scratch;
  if (signature && is_dsa(alg)) {
    if (alg == MLDSA44)
      ml_dsa_44_sign_streaming_abort(&s->dsa.state.sign);
    else
      ml_dsa_65_sign_streaming_abort(&s->dsa.state.sign.core);
  }
  if (alg == ED25519) ed25519_randomized_sign_clear(&s->ed.state);
  memzero(s, sizeof(*s));
}

const uint8_t *ck_stream_output(const void *scratch, uint8_t alg, uint8_t signature) {
  const stream_data_t *s = scratch;
  const uint8_t *source = s->public_key;
#ifdef RUST_CORE_PIV
  if (is_kem(alg)) source = s->kem.public_key;
#endif
  if (signature) source = alg == ED25519 ? s->ed.signature : alg == SM2 ? s->sm2.signature : s->dsa.stage;
  return source;
}

int32_t ck_stream_refill(void *scratch, uint8_t alg, size_t remaining) {
  return is_dsa(alg) ? refill(scratch, alg, NULL, remaining) : -1;
}

int32_t ck_stream_public_init(uint8_t alg, void *scratch, const uint8_t *input) {
  stream_data_t *s = scratch;
#ifdef RUST_CORE_PIV
  if (is_kem(alg)) {
    memcpy(s->kem.seed, input, sizeof(s->kem.seed));
    return alg == MLKEM512 ? ml_kem_512_seed_to_public(s->kem.public_key, s->kem.seed)
                           : ml_kem_768_seed_to_public(s->kem.public_key, s->kem.seed);
  }
#endif
  return ck_mldsa_public(alg == MLDSA44, s->public_key, input);
}

int32_t ck_stream_sign_init(uint8_t alg, void *scratch, const uint8_t *input) {
  stream_data_t *s = scratch;
  if (alg == SM2) {
    memcpy(s->sm2.key.pri, input, SM2_SCALAR_BYTES);
    if (ck_ecc_complete_key(SM2, &s->sm2.key) < 0) return -1;
    sm3_init(&s->sm2.hash);
    return 0;
  }
  if (is_dsa(alg)) {
    uint8_t tr[MLDSA_CRHBYTES];
    int r = alg == MLDSA65 ? ck_mldsa_prepare65_tail(s->dsa.stage, tr, input, s->dsa.state.absorb.tail)
                           : ck_mldsa_prepare(true, s->dsa.stage, tr, input);
    if (r < 0) return -1;
    memcpy(s->dsa.state.absorb.seed, input, MLDSA_SEEDBYTES);
    SHA3_CTX_T *hash = &s->dsa.state.absorb.hash;
    shake256_init(hash);
    shake_update(hash, tr, sizeof(tr));
    const uint8_t prefix[2] = {0, 0};
    shake_update(hash, prefix, sizeof(prefix));
    return 0;
  }
  if (alg == ED25519) {
    return ed_init(s, input);
  }
  return -1;
}
int32_t ck_stream_sm2_identity(void *scratch, const uint8_t *input, size_t n) {
  stream_data_t *s = scratch;
  return sm2_identity(s, input, n);
}
int32_t ck_stream_sign_update(void *scratch, uint8_t alg, const uint8_t *input, size_t n) {
  stream_data_t *s = scratch;
  if (alg == SM2) {
    sm3_update(&s->sm2.hash, input, n);
    return 0;
  }
  if (is_dsa(alg)) {
    shake_update(&s->dsa.state.absorb.hash, input, n);
    return 0;
  }
  if (alg == ED25519) return ed25519_randomized_sign_update(&s->ed.state, input, n);
  return -1;
}
int32_t ck_stream_sign_final(void *scratch, uint8_t alg, size_t total) {
  stream_data_t *s = scratch;
  if (alg == SM2) {
    return sm2_finish(s);
  }
  if (is_dsa(alg)) {
    uint8_t mu[MLDSA_CRHBYTES], seed[MLDSA_SEEDBYTES];
    shake_finalize(&s->dsa.state.absorb.hash);
    shake_squeeze(&s->dsa.state.absorb.hash, mu, sizeof(mu));
    memcpy(seed, s->dsa.state.absorb.seed, sizeof(seed));
    /* INIT cleared the union. Only seed and hash precede the prepared
     * fragment, which survives until the first signing call consumes it. */
    memzero(&s->dsa.state, offsetof(stream_data_t, dsa.state.absorb.tail) - offsetof(stream_data_t, dsa.state));
    memcpy(s->dsa.state.sign.core.seed, seed, sizeof(seed));
    memzero(seed, sizeof(seed));
    int r = refill(s, alg, mu, total);
    memzero(mu, sizeof(mu));
    return r;
  }
  if (alg == ED25519) {
    if (ed25519_randomized_sign_final(&s->ed.state, s->ed.signature) < 0) return -1;
    return EC_SIGNATURE_BYTES;
  }
  return -1;
}
#ifdef RUST_CORE_PIV
void ck_stream_decapsulate_init(void *scratch, const uint8_t *input) {
  stream_data_t *s = scratch;
  memcpy(s->kem.seed, input, sizeof(s->kem.seed));
}
void ck_stream_decapsulate_update(void *scratch, size_t offset, const uint8_t *input, size_t n) {
  stream_data_t *s = scratch;
  memcpy(s->kem.ciphertext + offset, input, n);
}
int32_t ck_stream_decapsulate_final(void *scratch, uint8_t alg, uint8_t *out) {
  stream_data_t *s = scratch;
  return alg == MLKEM512 ? ml_kem_512_decaps_seed(out, s->kem.ciphertext, s->kem.seed, s->kem.public_key)
                         : ml_kem_768_decaps_seed(out, s->kem.ciphertext, s->kem.seed, s->kem.public_key);
}
#endif

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
