#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <apdu.h>
#include <crypto-util.h>
#include <bd/lfs_filebd.h>
#include <fs.h>
#include <lfs.h>
#include <oath.h>

static void test_helper_resp(uint8_t *data, size_t data_len, uint8_t ins, uint16_t expected_error, uint8_t *expected_resp, size_t resp_len) {
  uint8_t c_buf[1024], r_buf[1024];
  // only tag, no length nor data
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = ins;
  capdu->lc = data_len;
  if (data_len > 0) {
    // re alloc to help asan find overflow error
    capdu->data = malloc(data_len);
    memcpy(capdu->data, data, data_len);
  } else {
    // when lc = 0, data should never be read
    capdu->data = NULL;
  }

  oath_process_apdu(capdu, rapdu);
  if (data_len > 0) {
    free(capdu->data);
  }
  assert_int_equal(rapdu->sw, expected_error);
  print_hex(RDATA, LL);
  if (expected_resp != NULL) {
    assert_int_equal(rapdu->len, resp_len);
    assert_memory_equal(RDATA, expected_resp, resp_len);
  }
}

static void test_helper(uint8_t *data, size_t data_len, uint8_t ins, uint16_t expected_error) {
  // don't check resp
  test_helper_resp(data, data_len, ins, expected_error, NULL, 0);
}

static void test_invalid_ins(void **state) {
  test_helper(NULL, 0, 0xDD, 0x6D00);
  test_helper(NULL, 0, 0x06, 0x6985);
}

static void test_put(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  // name: abc, algo: TOTP+SHA1, digit: 6, key: 0x00 0x01 0x02
  uint8_t data[] = {0x71, 0x03, 'a', 'b', 'c', 0x73, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = OATH_INS_PUT;
  capdu->data = data;
  capdu->lc = sizeof(data);

  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  for (int i = 0; i != 10; ++i) {
    data[2] = 'b' + i;
    oath_process_apdu(capdu, rapdu);
    assert_int_equal(rapdu->sw, SW_NO_ERROR);
  }
}

static void test_hotp_touch(void **state) {
  // name: H1, algo: HOTP+SHA1, digit: 6, key: 0x00 0x01 0x02
  uint8_t data[] = {
    OATH_TAG_NAME, 0x02, 'H', '1',
    OATH_TAG_KEY, 0x05, 0x11, 0x06, 0x00, 0x01, 0x02,
    OATH_TAG_COUNTER, 0x04, 0x01, 0x00, 0xf1, 0x02,
  };
  int ret;
  char buf[7];

  test_helper(data, sizeof(data), OATH_INS_PUT, SW_NO_ERROR);

  // default item isn't set yet
  ret = oath_process_one_touch(buf, sizeof(buf));
  assert_int_equal(ret, -1);

  test_helper(data, 4, OATH_INS_SET_DEFAULT, SW_NO_ERROR);

  ret = oath_process_one_touch(buf, sizeof(buf));
  assert_int_equal(ret, 0);
  printf("%s\n", buf);

  ret = oath_process_one_touch(buf, sizeof(buf));
  assert_int_equal(ret, 0);
  printf("%s\n", buf);

  test_helper(data, 4, OATH_INS_DELETE, SW_NO_ERROR);

  ret = oath_process_one_touch(buf, sizeof(buf));
  assert_int_equal(ret, -1);
}

// should be called after test_put
static void test_calc(void **state) {
  (void)state;

  uint8_t data[] = {
    // name
    OATH_TAG_NAME, 0x03, 'a', 'b', 'c',
    // challenge: 0x21 0x06 0x00 0x01 0x02
    OATH_TAG_CHALLENGE, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  uint8_t resp[] = {
    // hmac: cbba68f6d4c567bc4b0ffff136befc3d2d86231a
    // part of hmac:             fff136be
    // mask:                     7f000000
    OATH_TAG_RESPONSE, 0x05, 0x06, 0x7F, 0xF1, 0x36, 0xBE};
  test_helper_resp(data, sizeof(data), OATH_INS_CALCULATE, SW_NO_ERROR, resp, sizeof(resp));

  // length of data exceeds the Lc
  test_helper(data, sizeof(data) - 1, OATH_INS_CALCULATE, SW_WRONG_LENGTH);
  test_helper(data, 1, OATH_INS_CALCULATE, SW_WRONG_LENGTH);
  test_helper(data, 2, OATH_INS_CALCULATE, SW_WRONG_LENGTH);

  // omit the TAG_CHALLENGE
  test_helper(data, 5, OATH_INS_CALCULATE, SW_WRONG_LENGTH);

  // zero-length challenge
  data[6] = 0;
  test_helper(data, sizeof(data), OATH_INS_CALCULATE, SW_WRONG_DATA);

  data[6] = MAX_CHALLENGE_LEN + 1;
  test_helper(data, sizeof(data), OATH_INS_CALCULATE, SW_WRONG_DATA);
}

static void test_list(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = OATH_INS_LIST;
  capdu->lc = 0;
  capdu->le = 64;

  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, 0x61FF);
  print_hex(RDATA, LL);

  capdu->ins = OATH_INS_SEND_REMAINING;
  capdu->le = 0xFF;
  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  print_hex(RDATA, LL);
}

static void test_calc_all(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  uint8_t data[] = {0x74, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = OATH_INS_CALCULATE_ALL;
  capdu->data = data;
  capdu->lc = sizeof(data);
  capdu->le = 64;

  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, 0x61FF);
  print_hex(RDATA, LL);

  capdu->ins = OATH_INS_SEND_REMAINING;
  capdu->le = 0xFF;
  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  print_hex(RDATA, LL);

  // length of data exceeds the Lc
  test_helper(data, sizeof(data) - 1, OATH_INS_CALCULATE_ALL, SW_WRONG_LENGTH);
  test_helper(data, 1, OATH_INS_CALCULATE_ALL, SW_WRONG_LENGTH);
  test_helper(data, 2, OATH_INS_CALCULATE_ALL, SW_WRONG_LENGTH);

  // zero-length challenge
  data[1] = 0;
  test_helper(data, sizeof(data), OATH_INS_CALCULATE, SW_WRONG_DATA);

  data[1] = MAX_CHALLENGE_LEN + 1;
  test_helper(data, sizeof(data), OATH_INS_CALCULATE, SW_WRONG_DATA);
}

// regression tests for crashes discovered by fuzzing
static void test_regression_fuzz(void **state) {
  (void)state;

  if (1) {
    // put only tag, no length nor data
    uint8_t data[] = {OATH_TAG_NAME};
    test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_LENGTH);
  }

  if (1) {
    // put with broken HOTP tag
    uint8_t data[] = {
      // name tag
      OATH_TAG_NAME, 0x01, 0x20,
      // key tag
      OATH_TAG_KEY, 0x03, 0x11, 0x10, 0x00,
      // HOTP tag
      OATH_TAG_COUNTER, 0x04};
    test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_LENGTH);
  }

  if (1) {
    // delete with only name tag
    uint8_t data[] = {OATH_TAG_NAME};
    test_helper(data, sizeof(data), OATH_INS_DELETE, SW_WRONG_LENGTH);
  }

  if (1) {
    // calculate with only name tag
    uint8_t data[] = {OATH_TAG_NAME};
    test_helper(data, sizeof(data), OATH_INS_CALCULATE, SW_WRONG_LENGTH);
  }

  if (1) {
    // set default with only name tag
    uint8_t data[] = {OATH_TAG_NAME};
    test_helper(data, sizeof(data), OATH_INS_SET_DEFAULT, SW_WRONG_LENGTH);
  }

  if (1) {
    // put with empty key tag
    uint8_t data[] = {OATH_TAG_NAME, 0x01, 0x00, OATH_TAG_KEY, 3};
    test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_LENGTH);
  }
}

static void test_put_long_key(void **state) {
  (void)state;

  // put with too long key length(0xFF)
  uint8_t data[] = {
    // name tag
    OATH_TAG_NAME, 0x01, 0x20,
    // key tag
    OATH_TAG_KEY, 0xff, 0x11, 0x10, 0x00};
  test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_DATA);
}

static void test_put_unsupported_algo(void **state) {
  (void)state;

  // put with wrong algo(0x0)
  uint8_t data[] = {
    // name tag
    OATH_TAG_NAME, 0x01, 0x20,
    // key tag
    OATH_TAG_KEY, 0x03, 0x00, 0x10, 0x00};
  test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_DATA);
}

static void test_put_unsupported_counter(void **state) {
  (void)state;

  // put with unsupported counter type(except HOTP)
  uint8_t data[] = {
    // name tag
    OATH_TAG_NAME, 0x01, 0x20,
    // key tag (TOTP + SHA1)
    OATH_TAG_KEY, 0x03, 0x21, 0x10, 0x00,
    // HOTP tag
    OATH_TAG_COUNTER, 0x04, 0x00, 0x00, 0x00, 0x00};
  test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_DATA);
}


int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_filebd_read;
  cfg.prog = &lfs_filebd_prog;
  cfg.erase = &lfs_filebd_erase;
  cfg.sync = &lfs_filebd_sync;
  cfg.read_size = 16;
  cfg.prog_size = 16;
  cfg.block_size = 512;
  cfg.block_count = 400;
  cfg.block_cycles = 50000;
  cfg.cache_size = 128;
  cfg.lookahead_size = 16;
  lfs_filebd_create(&cfg, "lfs-root");

  fs_init(&cfg);
  oath_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_invalid_ins),
      cmocka_unit_test(test_put),
      cmocka_unit_test(test_put_long_key),
      cmocka_unit_test(test_put_unsupported_algo),
      cmocka_unit_test(test_put_unsupported_counter),
      cmocka_unit_test(test_calc),
      cmocka_unit_test(test_list),
      cmocka_unit_test(test_calc_all),
      cmocka_unit_test(test_hotp_touch),
      cmocka_unit_test(test_regression_fuzz),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
