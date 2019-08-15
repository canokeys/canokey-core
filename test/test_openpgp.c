#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "openpgp.h"
#include <apdu.h>
#include <crypto-util.h>
#include <emubd/lfs_emubd.h>
#include <fs.h>
#include <lfs.h>

static void test_verify(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
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
  openpgp_install();
}

static void test_change_reference_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
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
  openpgp_install();
}

static void test_reset_retry_counter(void **state) {
  (void)state;

  write_file("pgp-rc", "abcdefgh", 8);

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
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
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
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
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;

  apdu_fill_with_command(capdu, "00 20 00 83 08 31 32 33 34 35 36 37 38");
  openpgp_process_apdu(capdu, rapdu);

  apdu_fill_with_command(capdu, "00 DB 3F FF 00 01 1A 4D 82 01 16 B6 00 7F 48 08 91 04 92 81 80 93 81 80 5F 48 82 01 04 00 01 00 01 EC 2A 0A F7 80 D6 43 9D 4D 86 99 41 90 9C D1 E3 B6 28 49 30 57 D0 3E 22 2A A4 F5 74 18 35 1D 27 8B AC 91 BF D6 1E 78 B1 E2 16 9C FD F9 BC D1 18 2A 38 5B C0 66 55 AB B7 F5 CC 1A CB 97 98 E7 91 F4 F4 EC 4B 99 E8 EA 80 DD F7 97 3A 7F 7B 19 26 27 1A 8E 7A C4 2C 5B 8F 1A EF D8 F0 8F B2 9C 22 2C 44 D0 B2 B7 9D 79 06 39 1E C8 A1 88 4B 22 22 47 6E 48 54 9F 46 3A 60 D3 51 5A CC 94 51 4F 1D F6 11 4C 04 4B 66 46 14 78 EB 80 C5 26 E2 CA 23 F8 68 2D 10 BA AE E8 08 48 21 5B 3A 4A F7 8D A2 DC 8C B7 C5 70 4F 8F 6E 66 8C E2 8F 1B D3 DC AB 6C 37 8D 7E DE D5 4E 25 51 9F A1 4F A6 E2 0E A6 24 CB 6F 74 67 EC E4 D3 E3 BA 51 7A 55 4D B6 8D 17 81 9A 12 E0 71 B7 F2 57 1A E0 55 F6 8F 82 72 75 FC 74 68 8A 11 1F 06 45 19 AA 77 EF 6D AC C0 C8 78 1F 5D 83 EA EB 79 62 A5 2C 9F 8F B6 7E 27");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  apdu_fill_with_command(capdu, "00 47 81 00 00 00 02 B6 00 01 0F");
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  apdu_fill_with_command(capdu, "00 DB 3F FF 00 01 1A 4D 82 01 16 B8 00 7F 48 08 91 04 92 81 80 93 81 80 5F 48 82 01 04 00 01 00 01 D6 2F 32 91 59 9E 87 36 FC 9C 48 54 EF 6D F8 CF 63 37 61 F5 22 08 58 77 33 F0 03 6C 7B D4 7F 2F 88 4F 29 4B 73 37 A8 00 66 BB DB CD F1 FA 13 40 46 90 29 B7 40 EB 6B D8 3F 5E 66 D3 FF 41 92 01 EF 6A 44 15 07 E3 4A B8 DC 0D B7 BE 86 C4 62 BA 78 4F 29 0D 68 2D 5D EF C6 F7 82 06 F0 3D CC 27 58 FD BD E8 0D 24 13 09 A7 8D 9F 84 85 1D F2 D5 1C B1 85 C1 C5 62 7B A8 82 BB 3F 58 8F D1 01 15 D8 E5 6E 4B EF 39 47 F0 D0 DE 3B 57 C6 7C 2E 94 01 13 B5 A9 98 8E 36 54 8D B6 08 EF 76 7E FE 96 B7 D8 06 A6 61 3F 28 A8 9D 89 87 E6 27 20 6F 9F 02 47 D7 60 EA AC 5A 95 69 0C 22 00 89 CA 96 09 B6 ED FC FF 5E DF D5 09 89 7F 74 9C 0F EF 91 37 2F 72 5F 11 FA F6 27 1E 6B 2F 32 F2 B1 D3 64 5B B1 B1 9C B2 60 B8 C4 C6 9A 8A AC 44 86 F1 05 8A 9A F3 45 E8 6D 6E 73 DD 56 05 F2 22 17 8A 53 61");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  apdu_fill_with_command(capdu, "00 20 00 82 06 36 35 34 33 32 31");
  openpgp_process_apdu(capdu, rapdu);

  apdu_fill_with_command(capdu, "00 2A 80 86 00 01 01 00 7C 45 ED 54 25 8A EF F7 8A 7A 56 B7 6A 80 7F 24 7F 93 47 98 93 36 E4 44 58 1B 3C EF 98 7B 48 69 F9 2C 26 9E 91 CD 4C 0E 2A 43 E3 EE E6 9C 79 B5 F2 94 04 41 33 9A 76 DA DD 50 16 16 68 7B 6F 68 F9 6F B3 B9 1D 1D DF C3 C8 A6 AF 28 B8 24 7E 11 16 88 D0 D9 84 5F EF 3F 92 32 B2 EA BD 35 5D EA C2 93 96 94 42 85 E2 39 E5 5B 52 4D 60 B8 EA 6F A3 F6 A8 E3 B1 7C AA EF 77 C5 BC D5 19 EF 1B 27 28 08 9C 8E 47 C6 7F F3 F1 0D 52 3F F3 1F 8A 65 96 01 7B E3 9A 1F D0 AF E7 31 D0 68 4F 00 09 4E A8 89 F4 8E 75 6E 74 EE 53 FE 09 BB 42 48 07 D0 F1 0A 6B 84 FD 70 28 DA 30 11 D4 69 A9 0B E8 97 9E 0B 57 52 AE AB FA 23 83 4E 4F DC 9A DB D7 F7 2E F2 12 3E 34 41 A4 F8 9E 84 49 7B CF 7A 17 09 92 C4 CE 22 5E 3C 17 60 CB B5 9C 79 04 B8 62 33 A2 CA 1C CB E1 12 21 BE 59 B6 73 C0 AE B9 95 97 01 00");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

static void test_generate_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
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
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;

  apdu_fill_with_command(capdu, "00 47 81 00 00 00 02 B6 00 01 0F");
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  apdu_fill_with_command(capdu, "00 20 00 83 08 31 32 33 34 35 36 37 38");
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  apdu_fill_with_command(capdu, "00 47 80 00 00 00 02 B6 00 01 0F");
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  apdu_fill_with_command(capdu, "00 47 81 00 00 00 02 B6 00 01 0F");
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
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
  openpgp_install();

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

  lfs_emubd_destroy(&cfg);

  return ret;
}
