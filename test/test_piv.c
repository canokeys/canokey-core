#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <apdu.h>
#include <crypto-util.h>
#include <emubd/lfs_emubd.h>
#include <fs.h>
#include <piv.h>

static void test_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  // external auth
  apdu_fill_with_command(capdu, "00 87 00 9B 04 7C 02 81 00 00");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);
  apdu_fill_with_command(capdu,
                         "00 87 00 9B 0C 7C 0A 82 08 35 51 B0 A1 56 F6 95 D1");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  CLA = 0x00;
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
  assert_int_equal(SW, SW_NO_ERROR);
}

static void test_gen_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  CLA = 0x00;
  INS = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR;
  P1 = 0x00;
  P2 = 0x9E;
  LC = 0x05;
  memcpy(DATA, (uint8_t[]){0xAC, 0x03, 0x80, 0x01, 0x07}, 0x05);
  LE = 256;
  piv_process_apdu(capdu, rapdu);
  print_hex(RDATA, LL);
  assert_int_equal(SW, SW_NO_ERROR);
}

static void test_sign(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  apdu_fill_with_command(
      capdu,
      "10 87 07 9E FF 7C 82 01 06 82 00 81 82 01 00 00 01 FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF "
      "FF FF FF 00 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 3D "
      "29 57 C1 48 45 0A FF A1 16 67 C5 2B F9 C5 1B 78 3D 8D DB 35");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  apdu_fill_with_command(capdu,
                         "00 87 07 9E 0B 02 A2 2B 99 FE 52 EE F9 9D BA 0F 00");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);
}

static void test_decrypt(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  CLA = 0x00;
  INS = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR;
  P1 = 0x00;
  P2 = 0x9D;
  LC = 0x05;
  memcpy(DATA, (uint8_t[]){0xAC, 0x03, 0x80, 0x01, 0x11}, 0x05);
  LE = 256;
  piv_process_apdu(capdu, rapdu);
  print_hex(RDATA, LL);

  apdu_fill_with_command(capdu, "00 20 00 80 08 31 32 33 34 35 36 FF FF");
  piv_process_apdu(capdu, rapdu);
  printf("Verify PIN, SW: %X ", SW);

  apdu_fill_with_command(
      capdu, "00 87 11 9D 47 7C 45 82 00 85 41 04 D5 46 28 25 41 C7 53 E8 37 "
             "57 8A 91 41 07 CE A6 DE 47 B7 F8 72 49 A3 6D 70 AD D0 1C 00 5A "
             "22 85 66 4D 57 6D 95 33 25 03 B0 AF 45 58 7A CD 58 3B 07 4B 2D "
             "53 46 E9 4A 32 09 06 D1 7A 3B ED 24 55");
  LE = 256;
  piv_process_apdu(capdu, rapdu);
  printf("Decrypt, SW: %X ", SW);
  print_hex(RDATA, LL);
}

static void test_change_pin(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  apdu_fill_with_command(
      capdu, "00 2C 00 80 10 31 32 33 34 35 36 37 38 39 39 39 39 39 39 FF FF");
  piv_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);
}

static void test_import_rsa(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf}; RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  apdu_fill_with_command(
      capdu, "10 FE 07 9A FF 01 81 80 E8 12 82 34 EE 93 5F 33 ED DF 34 1F 4E "
             "E7 5A 73 8B 70 7E 39 A8 E5 53 1C 89 6F EA 86 33 AA 8C 7C 5B 8A "
             "94 C4 31 58 95 78 1E 50 CE 18 02 79 3F C0 ED 38 30 69 F8 A1 FC "
             "C1 1D 54 61 B1 E6 F6 54 D8 "
             "34 B3 59 A3 22 CA 8A AD E6 EF 81 6D 62 A6 62 7E 74 11 DD 15 8D "
             "54 C8 8B 89 CB 7A CD 10 51 BC B2 60 EF 48 0F 68 40 67 16 48 4A "
             "5B 35 30 2E D7 EF E8 D0 55 0B AC 5E 0F 0E 67 22 7C F7 7B E6 D2 "
             "2F 02 81 80 E1 0A 5D C6 6C B4 65 15 DE 90 "
             "11 8A 0D BF 6C 56 04 F5 FA 10 D7 81 0D 91 E0 ED C3 74 F4 DA 04 "
             "54 03 8F 7E F8 79 69 55 2C 40 5B D1 7B EA 99 20 58 E2 ED 6B BD "
             "D4 F1 A7 B6 54 6C E2 BB 5C 61 72 03 D3 82 9A 4B BA 75 E4 0C 54 "
             "35 BD 69 90 6B 7A A0 13 A3 F7 E2 6D F7 AF "
             "7E AB 5C AB 33 FA DF E9 B7 1B F5 B8 52 FA 5D 47 9E 8B 4B 8D 3B "
             "30 F4 A4 57 F9 C2 C0 F6 48 C9 0D FC 9F");
  piv_process_apdu(capdu, rapdu);

  apdu_fill_with_command(
      capdu, "10 FE 07 9A FF 2B 19 F7 F0 80 68 4D 03 81 80 E3 3C 34 48 76 0E "
             "D1 5A 7C A1 60 5D 03 9A 9F 43 A2 16 5D 52 42 21 82 36 E0 10 38 "
             "B8 7D 60 92 BC B5 B9 C5 1F 32 1E 46 04 DE D2 4A 6A D2 09 3D 36 "
             "C0 50 93 7F 40 18 04 F0 66 "
             "B2 98 12 65 4F 70 16 5F CB F9 8A 36 67 D2 50 A3 5E 83 01 C3 65 "
             "9D ED A9 E3 4F F2 69 77 CA 02 6F C3 51 13 F7 D5 C1 09 7C C6 EF "
             "6D 3E AC 49 04 55 76 91 46 4C 4E A1 DB E4 C0 11 76 23 A9 D9 DE "
             "45 78 4C 9A DB B4 50 BB 04 81 80 65 65 7F "
             "55 3D 7B 96 A4 60 F0 B7 06 66 25 5F 11 EF 10 49 C9 36 E0 AE 15 "
             "91 AC 6F CA 0D DD 01 E0 3C EE 75 FE 4C EE 39 F3 43 58 5B AE 22 "
             "C9 35 FA F6 DC 95 14 26 93 6F C6 C6 89 7D 2B 80 77 63 A0 F7 B7 "
             "3C 00 6D 16 5B 57 76 C5 F3 FF 51 94 2B DF "
             "5E 9A 1D C1 C7 5C B7 95 32 6F 01 B0 DD 13 F0 C1 91 76 88 C3 D2 "
             "8D 1F 0C FF A4 5E 11 52 80 98 60 0F 68");
  piv_process_apdu(capdu, rapdu);

  apdu_fill_with_command(
      capdu, "00 FE 07 9A 91 41 FB 76 56 28 D8 2F 7B 83 2A E5 11 66 6D 05 81 "
             "80 A8 75 86 28 68 79 C5 BA 99 3C A5 22 C3 9C C8 25 50 3D 13 40 "
             "17 7C 0A 40 C6 96 5F 3B 51 92 18 FE 84 7E 4D 0B 86 93 B9 20 82 "
             "36 D5 35 3A 6D E8 C0 9E 55 "
             "6A 3B EE 3B AE DD B6 AD 88 D3 52 B4 D4 44 7E 40 AF 1B EC 75 4F "
             "BE D9 5B 74 20 14 6B 23 31 16 73 2F 41 4B 63 B5 EE 7C 16 BE F4 "
             "6A 1F F7 C7 43 36 45 CE FF EF C8 61 B6 41 67 11 F7 BC 66 CD BA "
             "69 02 75 56 4D F8 CC 82 7E 99 DC 4E 5F 4C 75");
  piv_process_apdu(capdu, rapdu);
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
  piv_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_data),       cmocka_unit_test(test_gen_key),
      cmocka_unit_test(test_sign),       cmocka_unit_test(test_decrypt),
      cmocka_unit_test(test_change_pin), cmocka_unit_test(test_import_rsa),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_emubd_destroy(&cfg);

  return ret;
}
