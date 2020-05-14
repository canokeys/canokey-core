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

static void test_put(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
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

static void test_calc(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  uint8_t data[] = {0x71, 0x03, 'a', 'b', 'c', 0x74, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = OATH_INS_CALCULATE;
  capdu->data = data;
  capdu->lc = sizeof(data);

  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  print_hex(RDATA, LL);
}

static void test_list(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = OATH_INS_LIST;
  capdu->lc = 0;
  capdu->le = 32;

  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, 0x61FF);
  print_hex(RDATA, LL);

  capdu->ins = OATH_INS_SEND_REMAINING;
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
  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  print_hex(RDATA, LL);
}

static void test_helper(uint8_t *data, size_t data_len, uint8_t ins, uint16_t expected_error) {
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
}

// regression tests for crashes discovered by fuzzing
static void test_regression_fuzz(void **state) {
  (void)state;

  if (1) {
    // put only tag, no length nor data
    uint8_t data[] = {0x71};
    test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_LENGTH);
  }

  if (1) {
    // put with broken HOTP tag
    uint8_t data[] = {
      // name tag
      0x71, 0x01, 0x20,
      // key tag
      0x73, 0x03, 0x11, 0x10, 0x00,
      // HOTP tag
      0x7A, 0x04};
    test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_LENGTH);
  }

  if (1) {
    // delete with only tag
    uint8_t data[] = {0x71};
    test_helper(data, sizeof(data), OATH_INS_DELETE, SW_WRONG_LENGTH);
  }

  if (1) {
    // calculate with only tag
    uint8_t data[] = {0x71};
    test_helper(data, sizeof(data), OATH_INS_CALCULATE, SW_WRONG_LENGTH);
  }

  if (1) {
    // set default with only tag
    uint8_t data[] = {0x71};
    test_helper(data, sizeof(data), OATH_INS_SET_DEFAULT, SW_WRONG_LENGTH);
  }
}

static void test_put_long_key(void **state) {
  (void)state;

  // put with too long key length(0xFF)
  uint8_t data[] = {
    // name tag
    0x71, 0x01, 0x20,
    // key tag
    0x73, 0xff, 0x11, 0x10, 0x00};
  test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_DATA);
}

static void test_put_unsupported_algo(void **state) {
  (void)state;

  // put with wrong algo(0x0)
  uint8_t data[] = {
    // name tag
    0x71, 0x01, 0x20,
    // key tag
    0x73, 0x03, 0x00, 0x10, 0x00};
  test_helper(data, sizeof(data), OATH_INS_PUT, SW_WRONG_DATA);
}

static void test_put_unsupported_counter(void **state) {
  (void)state;

  // put with unsupported counter type(except HOTP)
  uint8_t data[] = {
    // name tag
    0x71, 0x01, 0x20,
    // key tag (TOTP + SHA1)
    0x73, 0x03, 0x21, 0x10, 0x00,
    // HOTP tag
    0x7A, 0x04, 0x00, 0x00, 0x00, 0x00};
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
      cmocka_unit_test(test_put),
      cmocka_unit_test(test_calc),
      cmocka_unit_test(test_list),
      cmocka_unit_test(test_calc_all),
      cmocka_unit_test(test_regression_fuzz),
      cmocka_unit_test(test_put_long_key),
      cmocka_unit_test(test_put_unsupported_algo),
      cmocka_unit_test(test_put_unsupported_counter),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
