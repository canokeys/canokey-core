#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <cmocka.h>
#include <crypto-util.h>
#include <fs.h>
#include <lfs.h>
#include <piv.h>

static void test_helper_resp(uint8_t *data, size_t data_len, uint8_t ins, uint8_t p1, uint8_t p2,
                             uint16_t expected_error, uint8_t *expected_resp, size_t resp_len) {
  uint8_t c_buf[1024], r_buf[1024];
  // only tag, no length nor data
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = ins;
  capdu->p1 = p1;
  capdu->p2 = p2;
  capdu->lc = data_len;
  if (data_len > 0) {
    // re alloc to help asan find overflow error
    capdu->data = malloc(data_len);
    memcpy(capdu->data, data, data_len);
  } else {
    // when lc = 0, data should never be read
    capdu->data = NULL;
  }

  piv_process_apdu(capdu, rapdu);
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

static void test_helper(uint8_t *data, size_t data_len, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t expected_error) {
  // don't check resp
  test_helper_resp(data, data_len, ins, p1, p2, expected_error, NULL, 0);
}

// regression tests for crashes discovered by fuzzing
static void test_regression_fuzz(void **state) {
  (void)state;

  if (1) {
    // zero length data
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x00, SW_WRONG_LENGTH);
  }

  if (1) {
    // only tag
    uint8_t data[] = {0x7C};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // only tag and bad length
    uint8_t data[] = {0x7C, 0x80};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_IMPORT_ASYMMETRIC_KEY, 0x07, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, 0x9A, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty object path
    uint8_t data[] = {0x5C, 0x03, 0x5F, 0xC1};
    test_helper(data, sizeof(data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty object path
    uint8_t data[] = {0xAC, 0x00, 0x80, 0x01};
    test_helper(data, sizeof(data), PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, 0x9A, SW_WRONG_LENGTH);
  }
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
  piv_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_regression_fuzz),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
