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
  capdu->p2 = 0x81;
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

  build_capdu(
      capdu,
      (uint8_t *)"\x00\xDB\x3F\xFF\x00\x01\x1A\x4D\x82\x01\x16\xB6\x00\x7F\x48\x08\x91\x04\x92\x81\x80\x93\x81\x80\x5F"
                 "\x48\x82\x01\x04\x00\x01\x00\x01\xEC\x2A\x0A\xF7\x80\xD6\x43\x9D\x4D\x86\x99\x41\x90\x9C\xD1\xE3\xB6"
                 "\x28\x49\x30\x57\xD0\x3E\x22\x2A\xA4\xF5\x74\x18\x35\x1D\x27\x8B\xAC\x91\xBF\xD6\x1E\x78\xB1\xE2\x16"
                 "\x9C\xFD\xF9\xBC\xD1\x18\x2A\x38\x5B\xC0\x66\x55\xAB\xB7\xF5\xCC\x1A\xCB\x97\x98\xE7\x91\xF4\xF4\xEC"
                 "\x4B\x99\xE8\xEA\x80\xDD\xF7\x97\x3A\x7F\x7B\x19\x26\x27\x1A\x8E\x7A\xC4\x2C\x5B\x8F\x1A\xEF\xD8\xF0"
                 "\x8F\xB2\x9C\x22\x2C\x44\xD0\xB2\xB7\x9D\x79\x06\x39\x1E\xC8\xA1\x88\x4B\x22\x22\x47\x6E\x48\x54\x9F"
                 "\x46\x3A\x60\xD3\x51\x5A\xCC\x94\x51\x4F\x1D\xF6\x11\x4C\x04\x4B\x66\x46\x14\x78\xEB\x80\xC5\x26\xE2"
                 "\xCA\x23\xF8\x68\x2D\x10\xBA\xAE\xE8\x08\x48\x21\x5B\x3A\x4A\xF7\x8D\xA2\xDC\x8C\xB7\xC5\x70\x4F\x8F"
                 "\x6E\x66\x8C\xE2\x8F\x1B\xD3\xDC\xAB\x6C\x37\x8D\x7E\xDE\xD5\x4E\x25\x51\x9F\xA1\x4F\xA6\xE2\x0E\xA6"
                 "\x24\xCB\x6F\x74\x67\xEC\xE4\xD3\xE3\xBA\x51\x7A\x55\x4D\xB6\x8D\x17\x81\x9A\x12\xE0\x71\xB7\xF2\x57"
                 "\x1A\xE0\x55\xF6\x8F\x82\x72\x75\xFC\x74\x68\x8A\x11\x1F\x06\x45\x19\xAA\x77\xEF\x6D\xAC\xC0\xC8\x78"
                 "\x1F\x5D\x83\xEA\xEB\x79\x62\xA5\x2C\x9F\x8F\xB6\x7E\x27",
      289);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(
      capdu,
      (uint8_t *)"\x00\xDB\x3F\xFF\x00\x01\x1A\x4D\x82\x01\x16\xB8\x00\x7F\x48\x08\x91\x04\x92\x81\x80\x93\x81\x80\x5F"
                 "\x48\x82\x01\x04\x00\x01\x00\x01\xD6\x2F\x32\x91\x59\x9E\x87\x36\xFC\x9C\x48\x54\xEF\x6D\xF8\xCF\x63"
                 "\x37\x61\xF5\x22\x08\x58\x77\x33\xF0\x03\x6C\x7B\xD4\x7F\x2F\x88\x4F\x29\x4B\x73\x37\xA8\x00\x66\xBB"
                 "\xDB\xCD\xF1\xFA\x13\x40\x46\x90\x29\xB7\x40\xEB\x6B\xD8\x3F\x5E\x66\xD3\xFF\x41\x92\x01\xEF\x6A\x44"
                 "\x15\x07\xE3\x4A\xB8\xDC\x0D\xB7\xBE\x86\xC4\x62\xBA\x78\x4F\x29\x0D\x68\x2D\x5D\xEF\xC6\xF7\x82\x06"
                 "\xF0\x3D\xCC\x27\x58\xFD\xBD\xE8\x0D\x24\x13\x09\xA7\x8D\x9F\x84\x85\x1D\xF2\xD5\x1C\xB1\x85\xC1\xC5"
                 "\x62\x7B\xA8\x82\xBB\x3F\x58\x8F\xD1\x01\x15\xD8\xE5\x6E\x4B\xEF\x39\x47\xF0\xD0\xDE\x3B\x57\xC6\x7C"
                 "\x2E\x94\x01\x13\xB5\xA9\x98\x8E\x36\x54\x8D\xB6\x08\xEF\x76\x7E\xFE\x96\xB7\xD8\x06\xA6\x61\x3F\x28"
                 "\xA8\x9D\x89\x87\xE6\x27\x20\x6F\x9F\x02\x47\xD7\x60\xEA\xAC\x5A\x95\x69\x0C\x22\x00\x89\xCA\x96\x09"
                 "\xB6\xED\xFC\xFF\x5E\xDF\xD5\x09\x89\x7F\x74\x9C\x0F\xEF\x91\x37\x2F\x72\x5F\x11\xFA\xF6\x27\x1E\x6B"
                 "\x2F\x32\xF2\xB1\xD3\x64\x5B\xB1\xB1\x9C\xB2\x60\xB8\xC4\xC6\x9A\x8A\xAC\x44\x86\xF1\x05\x8A\x9A\xF3"
                 "\x45\xE8\x6D\x6E\x73\xDD\x56\x05\xF2\x22\x17\x8A\x53\x61",
      289);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x82\x06\x36\x35\x34\x33\x32\x31", 11);
  openpgp_process_apdu(capdu, rapdu);

  build_capdu(
      capdu,
      (uint8_t *)"\x00\x2A\x80\x86\x00\x01\x01\x00\x7C\x45\xED\x54\x25\x8A\xEF\xF7\x8A\x7A\x56\xB7\x6A\x80\x7F\x24\x7F"
                 "\x93\x47\x98\x93\x36\xE4\x44\x58\x1B\x3C\xEF\x98\x7B\x48\x69\xF9\x2C\x26\x9E\x91\xCD\x4C\x0E\x2A\x43"
                 "\xE3\xEE\xE6\x9C\x79\xB5\xF2\x94\x04\x41\x33\x9A\x76\xDA\xDD\x50\x16\x16\x68\x7B\x6F\x68\xF9\x6F\xB3"
                 "\xB9\x1D\x1D\xDF\xC3\xC8\xA6\xAF\x28\xB8\x24\x7E\x11\x16\x88\xD0\xD9\x84\x5F\xEF\x3F\x92\x32\xB2\xEA"
                 "\xBD\x35\x5D\xEA\xC2\x93\x96\x94\x42\x85\xE2\x39\xE5\x5B\x52\x4D\x60\xB8\xEA\x6F\xA3\xF6\xA8\xE3\xB1"
                 "\x7C\xAA\xEF\x77\xC5\xBC\xD5\x19\xEF\x1B\x27\x28\x08\x9C\x8E\x47\xC6\x7F\xF3\xF1\x0D\x52\x3F\xF3\x1F"
                 "\x8A\x65\x96\x01\x7B\xE3\x9A\x1F\xD0\xAF\xE7\x31\xD0\x68\x4F\x00\x09\x4E\xA8\x89\xF4\x8E\x75\x6E\x74"
                 "\xEE\x53\xFE\x09\xBB\x42\x48\x07\xD0\xF1\x0A\x6B\x84\xFD\x70\x28\xDA\x30\x11\xD4\x69\xA9\x0B\xE8\x97"
                 "\x9E\x0B\x57\x52\xAE\xAB\xFA\x23\x83\x4E\x4F\xDC\x9A\xDB\xD7\xF7\x2E\xF2\x12\x3E\x34\x41\xA4\xF8\x9E"
                 "\x84\x49\x7B\xCF\x7A\x17\x09\x92\xC4\xCE\x22\x5E\x3C\x17\x60\xCB\xB5\x9C\x79\x04\xB8\x62\x33\xA2\xCA"
                 "\x1C\xCB\xE1\x12\x21\xBE\x59\xB6\x73\xC0\xAE\xB9\x95\x97\x01\x00",
      266);
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
  capdu->data[0] = 0xB6;
  capdu->data[1] = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  print_hex(rapdu->data, rapdu->len);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
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
