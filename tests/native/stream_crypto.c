// SPDX-License-Identifier: Apache-2.0
// Real streaming crypto adapter, with only the primitive's result/phase mocked.
#include "crypto_ops.h"
#include <ml-dsa-65.h>
#include <assert.h>
#include <stdalign.h>
#include <string.h>
static unsigned calls, aborts;
static int results[2];
static uint8_t phases[2], aborted_phase, seed[MLDSA_SEEDBYTES];
int ml_dsa_65_keygen_streaming(uint8_t *out, size_t capacity, mldsa_keygen_state_t *state, uint8_t *tr) {
  assert(calls < 2 && tr == NULL && capacity == 1312);
  assert(state->phase == calls);
  assert(!memcmp(state->seed, seed, sizeof(seed)));
  if (calls == 0) { assert(state->backend_state == 0); state->backend_state = 0x5a; }
  else assert(state->backend_state == 0x5a);
  int n = results[calls];
  state->phase = phases[calls];
  if (n > 0 && (size_t)n <= capacity) memset(out, 0x30 + calls, (size_t)n);
  ++calls;
  return n;
}
void ml_dsa_65_keygen_streaming_abort(mldsa_keygen_state_t *state) {
  assert(state->backend_state == 0x5a);
  aborted_phase = state->phase;
  memset(state, 0, sizeof(*state));
  ++aborts;
}
int main(void) {
  static const struct { int first, second; uint8_t phase0, phase1; int ok; } cases[] = {
    {-1, 0, 1, 0, 0}, {0, 0, 1, 0, 0}, {MLDSA_PK_BYTES + 1, 0, 1, 0, 0},
    {1312, -1, 1, 1, 0}, {1312, 0, 1, 1, 0}, {1312, 641, 1, 0, 0},
    {1312, 639, 1, 0, 0}, {1312, 640, 1, 1, 0}, {1312, 640, 1, 0, 1},
    {1311, 0, 1, 0, 0}, {1312, 640, 0, 0, 0}, {1312, 1313, 1, 0, 0}
  };
  alignas(8) uint8_t scratch[CK_CRYPTO_SCRATCH_BYTES + 8];
  uint8_t out[MLDSA_PK_BYTES + 1];
  memset(seed, 0xa7, sizeof(seed));
  for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
    memset(scratch, 0xa5, sizeof(scratch));
    memset(out, 0xa5, sizeof(out));
    calls = aborts = 0;
    results[0] = cases[i].first; results[1] = cases[i].second;
    phases[0] = cases[i].phase0; phases[1] = cases[i].phase1;
    int32_t n = ck_platform_stream(CK_STREAM_PUBLIC_INIT, MLDSA65, scratch, seed, sizeof(seed), NULL, 0);
    if (n == MLDSA_PK_BYTES) {
      // Different read sizes cross the 1312-byte stage boundary without keeping
      // a primitive-owned pointer or requesting another complete public key.
      size_t at = 0;
      while (at < MLDSA_PK_BYTES) {
        size_t count = MLDSA_PK_BYTES - at;
        if (count > 127) count = 127;
        n = ck_platform_stream(CK_STREAM_READ, MLDSA65, scratch, NULL, 0, out + at, count);
        if (n < 0) break;
        assert(n == (int32_t)count);
        at += count;
      }
      if (cases[i].ok) {
        assert(at == MLDSA_PK_BYTES);
        for (size_t j = 0; j < MLDSA_PK_BYTES; ++j) assert(out[j] == (j < 1312 ? 0x30 : 0x31));
      }
    }
    assert((n >= 0) == cases[i].ok);
    unsigned expected_calls = cases[i].first == 1312 && cases[i].phase0 == 1 ? 2 : 1;
    assert(calls == expected_calls);
    assert(ck_platform_stream(CK_STREAM_ABORT, MLDSA65, scratch, NULL, 0, NULL, 0) == 0);
    assert(aborts == 1 && aborted_phase == phases[expected_calls - 1]);
    assert(ck_platform_stream(CK_STREAM_ABORT, MLDSA65, scratch, NULL, 0, NULL, 0) == 0);
    assert(aborts == 1); // Repeated cleanup must not release the native engine twice.
    for (size_t j = CK_CRYPTO_SCRATCH_BYTES; j < sizeof(scratch); ++j) assert(scratch[j] == 0xa5);
    assert(out[MLDSA_PK_BYTES] == 0xa5);
    for (size_t j = 0; j < sizeof(seed); ++j) assert(seed[j] == 0xa7);
  }
  return 0;
}
