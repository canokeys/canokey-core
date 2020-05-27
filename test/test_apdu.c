#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <apdu.h>
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

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_input_chaining),
      cmocka_unit_test(test_output_chaining),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  return ret;
}
