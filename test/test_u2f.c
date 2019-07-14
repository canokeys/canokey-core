#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "../u2f/u2f.h"
#include <apdu.h>
#include <core.h>
#include <emubd/lfs_emubd.h>
#include <lfs.h>

static void test_u2f_personalization(void **state) {
  (void)state;
  uint8_t c_buf[100], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x80;
  capdu->ins = U2F_PERSONALIZATION;
  capdu->lc = 0;

  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  assert_int_equal(rapdu->len, 64);

  capdu->ins = U2F_INSTALL_CERT;
  capdu->lc = 1;
  capdu->data[0] = 0xDD;
  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

static void test_u2f_registration(void **state) {
  (void)state;
  uint8_t c_buf[100], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x00;
  capdu->ins = U2F_REGISTER;
  capdu->lc = 64;
  for (int i = 0; i < 64; ++i) {
    capdu->data[i] = i;
  }

  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_CONDITIONS_NOT_SATISFIED);

  u2f_press();
  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  assert_int_equal(rapdu->len, 266);
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
  lfs_emubd_create(&cfg, "test");

  init(&cfg);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_u2f_personalization),
      cmocka_unit_test(test_u2f_registration),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
