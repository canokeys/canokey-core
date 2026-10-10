// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <key.h>
#include <ml-dsa-65.h>
#include <string.h>

static unsigned calls;
static unsigned aborts;
static uint8_t aborted_phase;
static uint8_t expected_seed[MLDSA_SEEDBYTES];

int ml_dsa_65_keygen_streaming(uint8_t *out, size_t out_size, mldsa_keygen_state_t *state, uint8_t *tr_out) {
  assert_null(tr_out);
  assert_memory_equal(state->seed, expected_seed, sizeof(expected_seed));
  assert_int_equal(state->phase, calls);
  assert_int_equal(out_size, calls == 0 ? MLDSA_PK_BYTES : 640);
  if (calls == 0) {
    assert_int_equal(state->backend_state, 0);
    state->backend_state = 0x5A;
  } else {
    assert_int_equal(state->backend_state, 0x5A);
  }
  const int ret = mock_type(int);
  state->phase = mock_type(uint8_t);
  if (ret > 0 && (size_t)ret <= out_size) memset(out, 0x30 + calls, (size_t)ret);
  ++calls;
  return ret;
}

void ml_dsa_65_keygen_streaming_abort(mldsa_keygen_state_t *state) {
  assert_int_equal(state->backend_state, 0x5A);
  aborted_phase = state->phase;
  memset(state, 0, sizeof(*state));
  ++aborts;
}

static void test_encode_mldsa_stream_cleanup(void **test_state) {
  (void)test_state;
  static const struct {
    int first;
    int second;
    uint8_t final_phase;
    int result;
  } cases[] = {
      {-1, 0, 1, -1},
      {0, 0, 1, -1},
      {MLDSA_PK_BYTES + 1, 0, 1, -1},
      {1312, -1, 1, -1},
      {1312, 0, 1, -1},
      {1312, 641, 0, -1},
      {1312, 639, 0, -1},
      {1312, 640, 1, -1},
      {1312, 640, 0, MLDSA_PK_BYTES + 7},
  };
  ck_key_t key = {.meta.type = MLDSA65};
  memset(key.mldsa.seed, 0xA7, sizeof(key.mldsa.seed));
  memcpy(expected_seed, key.mldsa.seed, sizeof(expected_seed));
  uint8_t buf[MLDSA_PK_BYTES + 8];

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    calls = aborts = 0;
    memset(buf, 0xA5, sizeof(buf));
    will_return(ml_dsa_65_keygen_streaming, cases[i].first);
    will_return(ml_dsa_65_keygen_streaming, 1);
    if (cases[i].first == 1312) {
      will_return(ml_dsa_65_keygen_streaming, cases[i].second);
      will_return(ml_dsa_65_keygen_streaming, cases[i].final_phase);
    }
    assert_int_equal(ck_encode_public_key(&key, buf, true), cases[i].result);
    assert_int_equal(calls, cases[i].first == 1312 ? 2 : 1);
    assert_int_equal(aborts, 1);
    assert_int_equal(aborted_phase, cases[i].first == 1312 ? cases[i].final_phase : 1);
    assert_int_equal(buf[sizeof(buf) - 1], 0xA5);
    assert_memory_equal(key.mldsa.seed, expected_seed, sizeof(expected_seed));
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_encode_mldsa_stream_cleanup)};
  return cmocka_run_group_tests(tests, NULL, NULL);
}
