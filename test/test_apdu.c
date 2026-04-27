// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <apdu.h>
#include <pke.h>
#include <string.h>

static void test_input_chaining(void **state) {
  (void)state;

  uint8_t c_buf[1024], total_buf[2048];
  uint8_t data[] = {0x74, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = c_buf};
  CAPDU_CHAINING CC = {.capdu.data = total_buf, .in_chaining = 0};

  // test no chaining
  C.cla = 0x80;
  C.ins = 0x00;
  C.p1 = 0x01;
  C.p2 = 0xFF;
  C.lc = sizeof(data);
  memcpy(C.data, data, C.lc);
  int ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);

  // test normal chaining
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 3);

  // test abnormal chaining 1
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.ins = 0x20;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 2);

  // test abnormal chaining 2
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  C.ins = 0x10;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 1);
}

static void test_output_chaining(void **state) {
  (void)state;

  uint8_t r_buf[1024], total_buf[2048];
  RAPDU R = {.data = r_buf, .len = 254};
  RAPDU_CHAINING RC = {.rapdu.data = total_buf, .rapdu.len = 512, .rapdu.sw = 0x9000, .sent = 0};

  int ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 254);
  assert_int_equal(R.sw, 0x61FF);

  ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 254);
  assert_int_equal(R.sw, 0x6104);

  ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 4);
  assert_int_equal(R.sw, 0x9000);
}

static void test_pke_buffer_fallback_for_ctap(void **state) {
  (void)state;

  assert_true(pke_buffer_size() >= CTAP_MAX_REQUEST_SIZE);
  assert_int_equal(pke_buffer_clear(), 0);

  static const uint8_t payload[] = {
      0x01, 0xA6, 0x01, 0x58, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
  };
  uint8_t out[sizeof(payload)];
  uint8_t zero[sizeof(payload)] = {0};

  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), -1);
  assert_int_equal(pke_buffer_write(0, payload, sizeof(payload)), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_CTAP), 0);

  memset(out, 0, sizeof(out));
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_read(0, out, sizeof(out)), 0);
  assert_memory_equal(out, payload, sizeof(payload));
  assert_int_equal(pke_buffer_clear(), 0);
  memset(out, 0xA5, sizeof(out));
  assert_int_equal(pke_buffer_read(0, out, sizeof(out)), 0);
  assert_memory_equal(out, zero, sizeof(out));
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_CTAP), 0);
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_input_chaining),
      cmocka_unit_test(test_output_chaining),
      cmocka_unit_test(test_pke_buffer_fallback_for_ctap),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  return ret;
}
