#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <apdu.h>
#include <crypto-util.h>
#include <emubd/lfs_emubd.h>
#include <fs.h>
#include <piv.h>

uint8_t buffer[2048];

static void test_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  CLA = 0x10;
  INS = PIV_INS_PUT_DATA;
  P1 = 0x3F;
  P2 = 0xFF;
  LC = 0xFF;
  DATA[0] = 0x5C;
  DATA[1] = 0x03;
  DATA[2] = 0x5F;
  DATA[3] = 0xC1;
  DATA[4] = 0x05;
  for (int i = 5; i <= 255; ++i)
    DATA[i] = i;
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(SW, SW_NO_ERROR);

  CLA = 0x00;
  INS = PIV_INS_GET_DATA;
  LC = 5;
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(SW, SW_FILE_NOT_FOUND);

  CLA = 0x10;
  INS = PIV_INS_PUT_DATA;
  LC = 0xFF;
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(SW, SW_NO_ERROR);

  CLA = 0x00;
  LC = 0xFF;
  for (int i = 0; i <= 255; ++i)
    DATA[i] = i;
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(SW, SW_NO_ERROR);

  CLA = 0x00;
  INS = PIV_INS_GET_DATA;
  LC = 5;
  DATA[0] = 0x5C;
  DATA[1] = 0x03;
  DATA[2] = 0x5F;
  DATA[3] = 0xC1;
  DATA[4] = 0x05;
  LE = 0x100;
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(RDATA[0], 0x5C);
  assert_int_equal(RDATA[1], 0x82);
  assert_int_equal(RDATA[2], 0x01);
  assert_int_equal(RDATA[3], 0xF9);
  for (int i = 5; i <= 254; ++i)
    assert_int_equal(RDATA[i - 1], i);
  assert_int_equal(RDATA[254], 0x00);
  assert_int_equal(RDATA[255], 0x01);
  assert_int_equal(SW, 0x61FD);

  INS = PIV_GET_RESPONSE;
  P1 = 0x00;
  P2 = 0x00;
  LC = 0;
  LE = 0xFD;
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(SW, SW_NO_ERROR);
  assert_int_equal(LL, 0xFD);
  for (int i = 0; i != 253; ++i)
    assert_int_equal(RDATA[i], i + 2);
}

static void test_auth(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  CLA = 0x00;
  INS = PIV_GENERAL_AUTHENTICATE;
  P1 = 0x00;
  P2 = 0x9B;
  LC = 0x04;
  memcpy(DATA, (uint8_t[]){0x7C, 0x02, 0x81, 0x00}, 0x04);
  LE = 256;
  piv_process_apdu(capdu, rapdu);
  printHex(RDATA, LL);
  assert_int_equal(SW, SW_NO_ERROR);
  assert_int_equal(LL, 12);

  LC = 0x0C;
  memcpy(DATA,
         (uint8_t[]){0x7C, 0x0A, 0x82, 0x08, 0x35, 0x51, 0xB0, 0xA1, 0x56, 0xF6,
                     0x95, 0xD1},
         0x0C);
  piv_process_apdu(capdu, rapdu);
  assert_int_equal(SW, SW_NO_ERROR);

  LC = 0x04;
  memcpy(DATA, (uint8_t[]){0x7C, 0x02, 0x80, 0x00}, 0x04);
  piv_process_apdu(capdu, rapdu);
  printHex(RDATA, LL);
  assert_int_equal(SW, SW_NO_ERROR);

  LC = 0x18;
  memcpy(DATA, (uint8_t[]){0x7C, 0x16, 0x80, 0x08, 0xE9, 0xF6, 0xCC, 0xD1,
                           0x34, 0x53, 0xF9, 0xAA, 0x81, 0x08, 0x01, 0x02,
                           0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x82, 0x00},
         0x18);
  piv_process_apdu(capdu, rapdu);
  printHex(RDATA, LL);
  assert_int_equal(SW, SW_NO_ERROR);
}

static void test_gen_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  CLA = 0x00;
  INS = PIV_GENERATE_ASYMMETRIC_KEY_PAIR;
  P1 = 0x00;
  P2 = 0x9E;
  LC = 0x05;
  memcpy(DATA, (uint8_t[]){0xAC, 0x0A, 0x80, 0x01, 0x07}, 0x05);
  LE = 256;
  piv_process_apdu(capdu, rapdu);
  printHex(RDATA, LL);
  assert_int_equal(SW, 0x610F);
}

static void test_sign(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;

  apdu_fill_with_command(capdu, "10 87 07 9E FF 7C 82 01 06 82 00 81 82 01 00 00 01 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 3D 29 57 C1 48 45 0A FF A1 16 67 C5 2B F9 C5 1B 78 3D 8D DB 35");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  printHex(RDATA, LL);

  apdu_fill_with_command(capdu, "00 87 07 9E 0B 02 A2 2B 99 FE 52 EE F9 9D BA 0F 00");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  printHex(RDATA, LL);
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
  piv_config(buffer, 2048);
  piv_install();

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_data),
      cmocka_unit_test(test_auth),
      cmocka_unit_test(test_gen_key),
      cmocka_unit_test(test_sign),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_emubd_destroy(&cfg);

  return ret;
}
