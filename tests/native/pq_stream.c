// SPDX-License-Identifier: Apache-2.0
// Real native primitives through the production bounded stream adapter.
#include "crypto_ops.h"
#include <ml-dsa-44.h>
#include <assert.h>
#include <stdalign.h>
#include <string.h>

enum { GUARD_BYTES = 8, GUARD = 0xa5 };
typedef struct {
  alignas(8) uint8_t before[GUARD_BYTES];
  uint8_t scratch[CK_CRYPTO_SCRATCH_BYTES];
  uint8_t after[GUARD_BYTES];
} workspace_t;

static void prepare(workspace_t *w) {
  memset(w, GUARD, sizeof(*w));
  memset(w->scratch, 0, sizeof(w->scratch));
}
static void guards(const workspace_t *w) {
  for (size_t i = 0; i < GUARD_BYTES; ++i) {
    assert(w->before[i] == GUARD && w->after[i] == GUARD);
  }
}
static void abort_stream(workspace_t *w) {
  for (unsigned repeat = 0; repeat < 2; ++repeat) {
    ck_stream_abort(w->scratch);
    for (size_t i = 0; i < sizeof(w->scratch); ++i) assert(w->scratch[i] == 0);
    guards(w);
  }
  uint8_t out = GUARD;
  assert(ck_stream_read(w->scratch, &out, 1) == -1 && out == GUARD);
}
static void read_prefix(workspace_t *w, uint8_t *out, size_t length, size_t step) {
  for (size_t at = 0; at < length;) {
    size_t count = length - at < step ? length - at : step;
    assert(ck_stream_read(w->scratch, out + at, count) == (int32_t)count);
    at += count;
    guards(w);
  }
}
static void sign_start(workspace_t *w, uint8_t algorithm, const uint8_t *seed,
                       const uint8_t *message, size_t length, size_t total) {
  assert(ck_stream_sign_init(algorithm, w->scratch, seed, MLDSA_SEEDBYTES) == 0);
  assert(ck_stream_sign_update(w->scratch, message, 1) == 0);
  assert(ck_stream_sign_update(w->scratch, message + 1, length - 1) == 0);
  assert(ck_stream_sign_final(w->scratch) == (int32_t)total);
}
static void check(uint8_t algorithm, size_t public_bytes, size_t signature_bytes) {
  const uint8_t message[] = "fragmented native ML-DSA signing";
  uint8_t seed[MLDSA_SEEDBYTES], tr[MLDSA_TRBYTES], reference_public[MLDSA_PK_BYTES];
  uint8_t reference_signature[MLDSA_SIG_BYTES], out[MLDSA_SIG_BYTES + 1];
  workspace_t w;
  memset(seed, 0x3c, sizeof(seed));
  int r = algorithm == MLDSA44 ? ml_dsa_44_keygen(reference_public, NULL, tr, seed)
                               : ml_dsa_65_keygen(reference_public, NULL, tr, seed);
  assert(r == 0);
  size_t n = 0;
  r = algorithm == MLDSA44
          ? ml_dsa_44_sign_seed(reference_signature, &n, message, sizeof(message), NULL, 0, seed, tr)
          : ml_dsa_65_sign_seed(reference_signature, &n, message, sizeof(message), NULL, 0, seed, tr);
  assert(r == 0 && n == signature_bytes);

  // Oversized reads must fail before changing either output or stream position.
  const size_t steps[] = {1, 64, 256};
  for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); ++i) {
    for (unsigned signing = 0; signing < 2; ++signing) {
      prepare(&w);
      memset(out, GUARD, sizeof(out));
      size_t total = signing ? signature_bytes : public_bytes;
      if (signing) sign_start(&w, algorithm, seed, message, sizeof(message), total);
      else assert(ck_stream_public_init(algorithm, w.scratch, seed, sizeof(seed)) == (int32_t)total);
      assert(ck_stream_read(w.scratch, out, total + 1) == -1);
      for (size_t j = 0; j < sizeof(out); ++j) assert(out[j] == GUARD);
      assert(ck_stream_read(w.scratch, out, 0) == 0);
      read_prefix(&w, out, total - 1, steps[i]);
      assert(ck_stream_read(w.scratch, out + total - 1, 2) == -1);
      assert(out[total - 1] == GUARD && out[total] == GUARD);
      assert(ck_stream_read(w.scratch, out + total - 1, 1) == 1);
      assert(!memcmp(out, signing ? reference_signature : reference_public, total));
      assert(out[total] == GUARD);
      assert(ck_stream_read(w.scratch, out + total, 1) == -1);
      assert(ck_stream_read(w.scratch, out + total, 0) == 0);
      abort_stream(&w);
    }
  }

  // Cancel on both sides of stage boundaries and immediately start a new key.
  const size_t positions[] = {0, 1, 32, 608, 1184, 1311, 1312, 1760, 2336};
  for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
    prepare(&w);
    sign_start(&w, algorithm, seed, message, sizeof(message), signature_bytes);
    read_prefix(&w, out, positions[i], 73);
    abort_stream(&w);
    assert(ck_stream_public_init(algorithm, w.scratch, seed, sizeof(seed)) == (int32_t)public_bytes);
    read_prefix(&w, out, public_bytes, 73);
    assert(!memcmp(out, reference_public, public_bytes));
    abort_stream(&w);
  }
  for (size_t i = 0; i < sizeof(seed); ++i) assert(seed[i] == 0x3c);
}
int main(void) {
  check(MLDSA44, MLDSA44_PUBLIC_KEY_BYTES, MLDSA44_SIGNATURE_BYTES);
  check(MLDSA65, MLDSA_PK_BYTES, MLDSA_SIG_BYTES);
  return 0;
}
