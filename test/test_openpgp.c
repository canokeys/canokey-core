// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "openpgp.h"
#include <apdu.h>
#include <crypto-util.h>
#include <bd/lfs_filebd.h>
#include <fs.h>
#include <lfs.h>

static void test_verify(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_VERIFY;
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
  assert_int_equal(rapdu->sw, SW_AUTHENTICATION_BLOCKED);
  openpgp_install(1);
}

static void test_change_reference_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_CHANGE_REFERENCE_DATA;
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
  openpgp_install(1);
}

static void test_reset_retry_counter(void **state) {
  (void)state;

  write_file("pgp-rc", "abcdefgh", 0, 8, 1);

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_RESET_RETRY_COUNTER;
  capdu->p1 = 0x02;
  capdu->p2 = 0x81;
  capdu->lc = 14;
  strcpy((char *)capdu->data, "abcdefgh654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  capdu->p1 = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->ins = OPENPGP_INS_VERIFY;
  capdu->p1 = 0x00;
  capdu->p2 = 0x82;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

static void test_get_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_GET_DATA;
  capdu->p1 = 0x00;
  capdu->p2 = TAG_APPLICATION_RELATED_DATA;
  capdu->lc = 0;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

static void test_import_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC1\x0A\x16\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01", 15);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // import an ecc key
  build_capdu(capdu, (uint8_t *)"\x00\xDB\x3F\xFF\x2C\x4D\x2A\xB6\x00\x7F\x48\x02\x92\x20\x5F\x48\x20\x4A\xDB\x8D\x21\xB8\xB7\xF3\xDD\x22\xFD\xE3\xB8\xEB\xAD\xDC\xE1\x89\x2A\x24\xA5\x7B\x9E\x35\xD0\x10\x67\xBB\x5A\xF9\x89\x89\xEB", 49);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // with public key (ignored by card)
  build_capdu(capdu, (uint8_t *)"\x00\xDB\x3F\xFF\x4E\x4D\x4C\xB6\x00\x7F\x48\x04\x92\x20\x99\x20\x5F\x48\x40\x4A\xDB\x8D\x21\xB8\xB7\xF3\xDD\x22\xFD\xE3\xB8\xEB\xAD\xDC\xE1\x89\x2A\x24\xA5\x7B\x9E\x35\xD0\x10\x67\xBB\x5A\xF9\x89\x89\xEB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 83);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

}

static void test_generate_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_GENERATE_ASYMMETRIC_KEY_PAIR;
  capdu->p1 = 0x80;
  capdu->p2 = 0x00;
  capdu->lc = 0x02;
  capdu->data[0] = 0xB8;
  capdu->data[1] = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  print_hex(rapdu->data, rapdu->len);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // Decipher with invalid input data
  capdu->ins = OPENPGP_INS_PSO;
  capdu->p1 = 0x80;
  capdu->p2 = 0x86;
  openpgp_process_apdu(capdu, rapdu);
  print_hex(rapdu->data, rapdu->len);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);
}

static void test_special(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x80\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);
}

int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  struct lfs_filebd_config bdcfg = {.read_size = 1, .prog_size = 512, .erase_size = 512, .erase_count = 256};
  bd.cfg = &bdcfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_filebd_read;
  cfg.prog = &lfs_filebd_prog;
  cfg.erase = &lfs_filebd_erase;
  cfg.sync = &lfs_filebd_sync;
  cfg.read_size = 1;
  cfg.prog_size = 512;
  cfg.block_size = 512;
  cfg.block_count = 256;
  cfg.block_cycles = 50000;
  cfg.cache_size = 256;
  cfg.lookahead_size = 32;
  lfs_filebd_create(&cfg, "lfs-root", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  openpgp_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_verify),
      cmocka_unit_test(test_change_reference_data),
      cmocka_unit_test(test_reset_retry_counter),
      cmocka_unit_test(test_get_data),
      cmocka_unit_test(test_import_key),
      cmocka_unit_test(test_generate_key),
      cmocka_unit_test(test_special),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
