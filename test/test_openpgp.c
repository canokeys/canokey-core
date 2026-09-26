// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "openpgp.h"
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <crypto-util.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <memzero.h>
#include <rsa.h>
#include <string.h>

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

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC1\x01\x01", 6);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_DATA);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC1\x06\x13\x2A\x86\x48\xCE\x3D", 11);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_DATA);

  // import an ecc key
  build_capdu(
      capdu,
      (uint8_t *)"\x00\xDB\x3F\xFF\x2C\x4D\x2A\xB6\x00\x7F\x48\x02\x92\x20\x5F\x48\x20\x4A\xDB\x8D\x21\xB8\xB7\xF3\xDD"
                 "\x22\xFD\xE3\xB8\xEB\xAD\xDC\xE1\x89\x2A\x24\xA5\x7B\x9E\x35\xD0\x10\x67\xBB\x5A\xF9\x89\x89\xEB",
      49);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // with public key (ignored by card)
  build_capdu(capdu,
              (uint8_t *)"\x00\xDB\x3F\xFF\x4E\x4D\x4C\xB6\x00\x7F\x48\x04\x92\x20\x99\x20\x5F\x48\x40\x4A\xDB\x8D\x21"
                         "\xB8\xB7\xF3\xDD\x22\xFD\xE3\xB8\xEB\xAD\xDC\xE1\x89\x2A\x24\xA5\x7B\x9E\x35\xD0\x10\x67\xBB"
                         "\x5A\xF9\x89\x89\xEB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
              83);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

// RSA CRT consistency is validated at import (rsa_check_crt, shared with the
// PIV path): an imported key with a corrupted dp or with p == q must be
// rejected with SW_WRONG_DATA instead of reaching storage and failing later at
// use time.
static void test_import_rsa_rejects_inconsistent_crt(void **state) {
  (void)state;

  uint8_t c_buf[16], r_buf[256];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};

  build_capdu(&C, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  // SIG key algorithm attributes: RSA-2048.
  build_capdu(&C, (uint8_t *)"\x00\xDA\x00\xC1\x06\x01\x08\x00\x00\x20\x00", 11);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  rsa_key_t rsa;
  assert_int_equal(rsa_generate_key(&rsa, 2048), 0);

  // 4D 82 029F || B6 00 || 7F48 11 <component headers> || 5F48 82 0284 || e || p || q || qinv || dp || dq
  static uint8_t blob[4 + 671];
  uint8_t *wp = blob;
  *wp++ = 0x4D;
  *wp++ = 0x82;
  *wp++ = 0x02;
  *wp++ = 0x9F;
  *wp++ = 0xB6;
  *wp++ = 0x00;
  *wp++ = 0x7F;
  *wp++ = 0x48;
  *wp++ = 0x11;
  *wp++ = 0x91;
  *wp++ = 0x04;
  for (uint8_t t = 0x92; t <= 0x96; ++t) {
    *wp++ = t;
    *wp++ = 0x81;
    *wp++ = 0x80;
  }
  *wp++ = 0x5F;
  *wp++ = 0x48;
  *wp++ = 0x82;
  *wp++ = 0x02;
  *wp++ = 0x84;
  const uint8_t *comps[] = {rsa.e, rsa.p, rsa.q, rsa.qinv, rsa.dp, rsa.dq};
  const size_t comp_lens[] = {E_LENGTH, 128, 128, 128, 128, 128};
  for (size_t i = 0; i < 6; ++i) {
    memcpy(wp, comps[i], comp_lens[i]);
    wp += comp_lens[i];
  }
  assert_int_equal(wp - blob, (long)sizeof(blob));

  CAPDU I = {.data = blob, .cla = 0x00, .ins = 0xDB, .p1 = 0x3F, .p2 = 0xFF, .lc = sizeof(blob)};
  openpgp_process_apdu(&I, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  // Offsets within blob: 5F48 data starts at 31; components e|p|q|qinv|dp|dq.
  const size_t p_off = 31 + 4, q_off = p_off + 128, dp_off = p_off + 3 * 128;

  // Corrupted dp: rejected at import.
  blob[dp_off + 50] ^= 0x55;
  openpgp_process_apdu(&I, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);
  blob[dp_off + 50] ^= 0x55; // restore

  // p == q: rejected at import as well.
  memcpy(blob + q_off, blob + p_off, 128);
  openpgp_process_apdu(&I, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  memzero(&rsa, sizeof(rsa));
  memzero(blob, sizeof(blob));
}

static void test_generate_key(void **state) {
  (void)state;

  openpgp_install(1);
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
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

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

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x82\x06\x31\x32\x33\x34\x35\x36", 11);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // Decipher with invalid input data
  capdu->ins = OPENPGP_INS_PSO;
  capdu->p1 = 0x80;
  capdu->p2 = 0x86;
  openpgp_process_apdu(capdu, rapdu);
  print_hex(rapdu->data, rapdu->len);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);

  openpgp_install(1);
}

static void test_decipher_chaining(void **state) {
  (void)state;

  openpgp_install(1);
  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x82\x06\x31\x32\x33\x34\x35\x36", 11);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_GENERATE_ASYMMETRIC_KEY_PAIR;
  capdu->p1 = 0x80;
  capdu->p2 = 0x00;
  capdu->lc = 0x02;
  capdu->data[0] = 0xB8;
  capdu->data[1] = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->cla = 0x10;
  capdu->ins = OPENPGP_INS_PSO;
  capdu->p1 = 0x80;
  capdu->p2 = 0x86;
  capdu->lc = 254;
  memset(capdu->data, 0, capdu->lc);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->cla = 0x00;
  capdu->lc = 3;
  memset(capdu->data, 0, capdu->lc);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_DATA);

  openpgp_install(1);
}

static void test_x25519_public_key_encoding(void **state) {
  (void)state;
  openpgp_install(1);

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC2\x0B\x12\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01", 16);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu,
              (uint8_t *)"\x00\xDB\x3F\xFF\x2C\x4D\x2A\xB8\x00\x7F\x48\x02\x92\x20\x5F\x48\x20\x5A\x83\x40\xFB"
                         "\x62\x3E\x85\x36\xB1\x11\x4E\xD6\xC4\x68\xDC\xA9\x49\x57\x89\x72\xE8\x3C\xB0\x2A"
                         "\xAF\x1C\xE3\x34\x9D\xCA\x0D\x68",
              49);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x02\xB8\x00\x00", 8);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  uint8_t expected[] = {
      0x7F, 0x49, 0x22, 0x86, 0x20, 0xA8, 0x2E, 0x8B, 0x07, 0xB3, 0x5E, 0x0B, 0xFF, 0xB5, 0xD3, 0x3D, 0x7C, 0xA6, 0x53,
      0x4F, 0x0C, 0x2B, 0x03, 0xB0, 0x0F, 0x65, 0xA4, 0x9A, 0xA9, 0x85, 0xF1, 0x16, 0xDE, 0x49, 0x42, 0x15, 0x3D,
  };
  assert_int_equal(rapdu->len, sizeof(expected));
  assert_memory_equal(rapdu->data, expected, sizeof(expected));

  openpgp_install(1);
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

// Block-device read counter and prog-failure injection for the
// terminated-cache test.
static unsigned bd_read_count;
static bool bd_prog_fails;

static int counted_bd_read(const struct lfs_config *cfg, lfs_block_t block, lfs_off_t off, void *buffer,
                           lfs_size_t size) {
  ++bd_read_count;
  return lfs_filebd_read(cfg, block, off, buffer, size);
}

static int guarded_bd_prog(const struct lfs_config *cfg, lfs_block_t block, lfs_off_t off, const void *buffer,
                           lfs_size_t size) {
  if (bd_prog_fails) return LFS_ERR_IO;
  return lfs_filebd_prog(cfg, block, off, buffer, size);
}

static void test_terminated_cache(void **state) {
  (void)state;
  openpgp_install(1);
  uint8_t c_buf[16], r_buf[300];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  C.cla = 0x00;
  C.ins = OPENPGP_INS_GET_DATA;
  C.p1 = 0x00;
  C.p2 = 0x4F; // AID: const data plus the config-page serial, no LittleFS access
  C.lc = 0;

  // install wrote the cache through: the per-APDU terminated check hits no flash
  unsigned before = bd_read_count;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(bd_read_count, before);

  // terminate the card (PW3 verified first)
  C.ins = OPENPGP_INS_VERIFY;
  C.p2 = 0x83;
  C.lc = 8;
  memcpy(C.data, "12345678", 8);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  C.ins = OPENPGP_INS_TERMINATE;
  C.p2 = 0x00;
  C.lc = 0;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  // the terminated rejection is also served from the cache: zero bd reads
  C.ins = OPENPGP_INS_GET_DATA;
  C.p2 = 0x4F;
  before = bd_read_count;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_TERMINATED);
  assert_int_equal(bd_read_count, before);

  // a failed terminate write invalidates the cache (commit outcome uncertain)
  C.ins = OPENPGP_INS_ACTIVATE; // reinstalls, card active again
  C.p2 = 0x00;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  C.ins = OPENPGP_INS_VERIFY; // install cleared the authorization
  C.p2 = 0x83;
  C.lc = 8;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  bd_prog_fails = true;
  C.ins = OPENPGP_INS_TERMINATE;
  C.p2 = 0x00;
  C.lc = 0;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_UNABLE_TO_PROCESS);
  bd_prog_fails = false;

  // cache was invalidated: the next command reloads from flash, and the card
  // is still active because the failed prog never landed
  before = bd_read_count;
  C.ins = OPENPGP_INS_GET_DATA;
  C.p2 = 0x4F;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(bd_read_count > before);

  openpgp_install(1);
}

int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  struct lfs_filebd_config bdcfg = {.read_size = 1, .prog_size = 512, .erase_size = 512, .erase_count = 256};
  bd.cfg = &bdcfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &counted_bd_read;
  cfg.prog = &guarded_bd_prog;
  cfg.erase = &lfs_filebd_erase;
  cfg.sync = &lfs_filebd_sync;
  cfg.read_size = 1;
  cfg.prog_size = 512;
  cfg.block_size = 512;
  cfg.block_count = 256;
  cfg.block_cycles = 50000;
  cfg.cache_size = 512;
  cfg.lookahead_size = 32;
  lfs_filebd_create(&cfg, "lfs-root-openpgp", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  openpgp_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_import_key),
      cmocka_unit_test(test_import_rsa_rejects_inconsistent_crt),
      cmocka_unit_test(test_generate_key),
      cmocka_unit_test(test_decipher_chaining),
      cmocka_unit_test(test_x25519_public_key_encoding),
      cmocka_unit_test(test_special),
      cmocka_unit_test(test_terminated_cache),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
