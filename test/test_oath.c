#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <apdu.h>
#include <crypto-util.h>
#include <emubd/lfs_emubd.h>
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

  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, 0x61FF);
  print_hex(RDATA, LL);

  capdu->ins = OATH_INS_SEND_REMAINING;
  oath_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  print_hex(RDATA, LL);
}

int main() {
  struct lfs_config cfg;
  lfs_emubd_t bd;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_emubd_read;
  cfg.prog = &lfs_emubd_prog;
  cfg.erase = &lfs_emubd_erase;
  cfg.sync = &lfs_emubd_sync;
  cfg.read_size = 16;
  cfg.prog_size = 16;
  cfg.block_size = 512;
  cfg.block_count = 400;
  cfg.block_cycles = 50000;
  cfg.cache_size = 128;
  cfg.lookahead_size = 16;
  lfs_emubd_create(&cfg, "lfs-root");

  fs_init(&cfg);
  oath_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_put),
      cmocka_unit_test(test_calc),
      cmocka_unit_test(test_list),
      cmocka_unit_test(test_calc_all),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_emubd_destroy(&cfg);

  return ret;
}
