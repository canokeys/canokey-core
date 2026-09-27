// SPDX-License-Identifier: Apache-2.0
// Shared incremental SHA-256 adapter; protocol state is owned by Rust.
#include "crypto_ops.h"
#include <memzero.h>
#include <sha.h>
_Static_assert(sizeof(sha256_ctx_t) <= CK_HASH_STATE_BYTES, "Rust digest state ABI");
int32_t ck_platform_digest(uint8_t op, void *state, const uint8_t *input, size_t n, uint8_t *out, size_t capacity) {
  sha256_ctx_t *ctx = state;
  switch (op) {
  case CK_DIGEST_INIT:
    memzero(state, CK_HASH_STATE_BYTES);
    sha256_init(ctx);
    return 0;
  case CK_DIGEST_UPDATE:
    sha256_update(ctx, input, n);
    return 0;
  case CK_DIGEST_FINAL:
    if (capacity < SHA256_DIGEST_LENGTH) return -1;
    sha256_final(ctx, out);
    memzero(state, CK_HASH_STATE_BYTES);
    return 0;
  case CK_DIGEST_ABORT:
#ifdef USE_MBEDCRYPTO
    psa_hash_abort(&ctx->op);
#endif
    memzero(state, CK_HASH_STATE_BYTES);
    return 0;
  default:
    return -1;
  }
}

