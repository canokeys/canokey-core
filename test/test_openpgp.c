#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "../openpgp/openpgp.h"
#include <apdu.h>
#include <emubd/lfs_emubd.h>
#include <fs.h>
#include <lfs.h>

static void test_verify(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_VERIFY;
  capdu->p1 = 0x00;
  capdu->p2 = 0x81;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "123456");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  capdu->lc = 4;
  strcpy((char *)capdu->data, "1234");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);
  capdu->lc = 6;
  strcpy((char *)capdu->data, "123465");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_AUTHENTICATION_BLOCKED);
  openpgp_initialize();
}

static void test_change_reference_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_CHANGE_REFERENCE_DATA;
  capdu->p1 = 0x01;
  capdu->p2 = 0x81;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "123456");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_P1P2);
  capdu->p1 = 0x00;
  capdu->lc = 10;
  strcpy((char *)capdu->data, "1234561234");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);
  capdu->lc = 10;
  strcpy((char *)capdu->data, "1234651234");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  capdu->lc = 12;
  strcpy((char *)capdu->data, "123456654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  openpgp_initialize();
}

static void test_reset_retry_counter(void **state) {
  (void)state;

  write_file("pgp-rc", "abcdef", 6);

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_RESET_RETRY_COUNTER;
  capdu->p1 = 0x02;
  capdu->p2 = 0x81;
  capdu->lc = 12;
  strcpy((char *)capdu->data, "abcdef654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  capdu->p1 = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->ins = OPENPGP_VERIFY;
  capdu->p1 = 0x00;
  capdu->p2 = 0x81;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
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
  openpgp_initialize();

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_verify),
      cmocka_unit_test(test_change_reference_data),
      cmocka_unit_test(test_reset_retry_counter),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
