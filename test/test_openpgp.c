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
      cmocka_unit_test(test_special),
      cmocka_unit_test(test_terminated_cache),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
