// SPDX-License-Identifier: Apache-2.0
#ifndef CK_TEST_CRYPTO_FIXTURE_H
#define CK_TEST_CRYPTO_FIXTURE_H
#include "crypto_ops.h"

int32_t ck_test_stream(uint8_t op, uint8_t alg, void *scratch, const uint8_t *input, size_t n, uint8_t *out,
                       size_t capacity);
int32_t ck_test_rewind_public(void *scratch);

static inline void fixture_stream_abort(void *scratch) {
  ck_test_stream(CK_STREAM_ABORT, 0, scratch, NULL, 0, NULL, 0);
}
static inline int32_t fixture_stream_read(void *scratch, uint8_t *out, size_t n) {
  return ck_test_stream(CK_STREAM_READ, 0, scratch, NULL, 0, out, n);
}
static inline int32_t fixture_stream_public_init(uint8_t alg, void *scratch, const uint8_t *seed, size_t n) {
  return ck_test_stream(CK_STREAM_PUBLIC_INIT, alg, scratch, seed, n, NULL, 0);
}
static inline int32_t fixture_stream_sign_init(uint8_t alg, void *scratch, const uint8_t *seed, size_t n) {
  return ck_test_stream(CK_STREAM_SIGN_INIT, alg, scratch, seed, n, NULL, 0);
}
static inline int32_t fixture_stream_sign_update(void *scratch, const uint8_t *in, size_t n) {
  return ck_test_stream(CK_STREAM_SIGN_UPDATE, 0, scratch, in, n, NULL, 0);
}
static inline int32_t fixture_stream_sign_final(void *scratch) {
  return ck_test_stream(CK_STREAM_SIGN_FINAL, 0, scratch, NULL, 0, NULL, 0);
}
static inline int32_t fixture_stream_decapsulate_init(uint8_t alg, void *scratch, const uint8_t *seed, size_t n) {
  return ck_test_stream(CK_STREAM_DECAPSULATE_INIT, alg, scratch, seed, n, NULL, 0);
}
static inline int32_t fixture_stream_decapsulate_update(void *scratch, const uint8_t *in, size_t n) {
  return ck_test_stream(CK_STREAM_DECAPSULATE_UPDATE, 0, scratch, in, n, NULL, 0);
}
static inline int32_t fixture_stream_decapsulate_final(void *scratch, uint8_t *out, size_t n) {
  return ck_test_stream(CK_STREAM_DECAPSULATE_FINAL, 0, scratch, NULL, 0, out, n);
}
#endif
