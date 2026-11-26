// SPDX-License-Identifier: Apache-2.0
// Shared incremental SHA-256 adapter; protocol state is owned by Rust.
#include "crypto_ops.h"
#include <memzero.h>
#include <sha.h>
_Static_assert(sizeof(sha256_ctx_t) <= CK_HASH_STATE_BYTES, "Rust digest state ABI");
int32_t ck_digest_init(void *state) {
  memzero(state, CK_HASH_STATE_BYTES);
  sha256_init(state);
  return 0;
}
int32_t ck_digest_update(void *state, const uint8_t *input, size_t n) {
  sha256_update(state, input, n);
  return 0;
}
int32_t ck_digest_final(void *state, uint8_t *out, size_t capacity) {
  if (capacity < SHA256_DIGEST_LENGTH) return -1;
  sha256_final(state, out);
  memzero(state, CK_HASH_STATE_BYTES);
  return 0;
}
int32_t ck_digest_abort(void *state) {
#ifdef USE_MBEDCRYPTO
  sha256_ctx_t *ctx = state;
  psa_hash_abort(&ctx->op);
#endif
  memzero(state, CK_HASH_STATE_BYTES);
  return 0;
}
