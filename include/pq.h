/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_PQ_H
#define CANOKEY_CORE_PQ_H
#include <algo.h>
#include <stdbool.h>
#include <ml-dsa-65.h>
#include <ml-kem-768.h>
#include <ml-dsa-44.h>
#include <ml-kem-512.h>

/* Dispatch parameter sets through the platform streaming backends. */
static inline int pq_mldsa_keygen(key_type_t type, uint8_t *out, size_t len, mldsa_keygen_state_t *state, uint8_t *tr) {
  if (type == MLDSA44) return ml_dsa_44_keygen_streaming(out, len, state, tr);
  return type == MLDSA65 ? ml_dsa_65_keygen_streaming(out, len, state, tr) : -1;
}
static inline int pq_mldsa_seed_to_tr(key_type_t type, uint8_t *tr, const uint8_t *seed) {
  if (type == MLDSA44) return ml_dsa_44_seed_to_tr(tr, seed);
  return type == MLDSA65 ? ml_dsa_65_seed_to_tr(tr, seed) : -1;
}
static inline int pq_mlkem_public(key_type_t type, uint8_t *out, const uint8_t *seed) {
  if (type == MLKEM512) return ml_kem_512_seed_to_public(out, seed);
  return type == MLKEM768 ? ml_kem_768_seed_to_public(out, seed) : -1;
}
static inline int pq_mlkem_decaps(key_type_t type, uint8_t *ss, const uint8_t *ct, const uint8_t *seed,
                                  uint8_t *scratch) {
  if (type == MLKEM512) return ml_kem_512_decaps_seed(ss, ct, seed, scratch);
  return type == MLKEM768 ? ml_kem_768_decaps_seed(ss, ct, seed, scratch) : -1;
}
/* Reserve the hint outside the output/cache extent. No new global buffer. */
#define PQ_SMALL_HINT_BYTES 84
static inline size_t pq_mldsa_stage_capacity(bool small, size_t capacity) {
  return capacity - (small ? PQ_SMALL_HINT_BYTES : 0);
}
static inline int pq_mldsa_sign(bool small, uint8_t *out, size_t capacity, mldsa_sign_state_t *state,
                                const uint8_t *msg, size_t msg_len, const uint8_t *tr, const uint8_t *mu) {
  if (small) {
    if (capacity < PQ_SMALL_HINT_BYTES) return -1;
    const size_t len = pq_mldsa_stage_capacity(true, capacity);
    uint8_t *hint = out + len;
    return mu ? ml_dsa_44_sign_seed_mu_streaming_split(out, len, state, hint, mu)
              : ml_dsa_44_sign_seed_streaming_split(out, len, state, hint, msg, msg_len, NULL, 0, tr);
  }
  return mu ? ml_dsa_65_sign_seed_mu_streaming(out, capacity, state, mu)
            : ml_dsa_65_sign_seed_streaming(out, capacity, state, msg, msg_len, NULL, 0, tr);
}
#endif
