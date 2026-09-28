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
// Compatibility facade for native callers; firmware uses the typed entries.
int32_t ck_platform_digest(uint8_t op, void *state, const uint8_t *input, size_t n, uint8_t *out, size_t capacity) {
  switch (op) {
  case CK_DIGEST_INIT: return ck_digest_init(state);
  case CK_DIGEST_UPDATE: return ck_digest_update(state, input, n);
  case CK_DIGEST_FINAL: return ck_digest_final(state, out, capacity);
  case CK_DIGEST_ABORT: return ck_digest_abort(state);
  default: return -1;
  }
}
