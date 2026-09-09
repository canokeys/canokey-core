// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <bd/lfs_filebd.h>
#include <fs.h>
#include <lfs.h>
#include <ndef.h>
#include <string.h>

#define CC_LEN 15

// Block device wrappers with controllable failure injection and counters.
static int prog_fail_budget = -1; // >= 0: fail the (budget+1)-th prog call
static bool prog_fail_after;      // execute the underlying prog before failing
static bool fail_reads;
static unsigned bd_prog_count, bd_read_count;

static int ndef_bd_prog(const struct lfs_config *cfg, lfs_block_t block, lfs_off_t off, const void *buffer,
                        lfs_size_t size) {
  ++bd_prog_count;
  if (prog_fail_budget >= 0 && prog_fail_budget-- == 0) {
    if (prog_fail_after) lfs_filebd_prog(cfg, block, off, buffer, size);
    return LFS_ERR_IO;
  }
  return lfs_filebd_prog(cfg, block, off, buffer, size);
}

static int ndef_bd_read(const struct lfs_config *cfg, lfs_block_t block, lfs_off_t off, void *buffer,
                        lfs_size_t size) {
  ++bd_read_count;
  if (fail_reads) return LFS_ERR_IO;
  return lfs_filebd_read(cfg, block, off, buffer, size);
}

static void faults_disarm(void) {
  prog_fail_budget = -1;
  prog_fail_after = false;
  fail_reads = false;
}

static uint8_t resp[1200];

static void select_file(uint8_t id0, uint8_t id1) {
  uint8_t sel[] = {id0, id1};
  CAPDU c = {.ins = NDEF_INS_SELECT, .p1 = 0x00, .p2 = 0x0C, .data = sel, .lc = sizeof(sel)};
  RAPDU r = {.data = resp};
  assert_int_equal(ndef_process_apdu(&c, &r), 0);
  assert_int_equal(r.sw, SW_NO_ERROR);
}

static uint16_t read_cc(uint8_t out[CC_LEN]) {
  select_file(0xE1, 0x03);
  CAPDU c = {.ins = NDEF_INS_READ_BINARY, .p1 = 0, .p2 = 0, .le = CC_LEN};
  RAPDU r = {.data = resp};
  assert_int_equal(ndef_process_apdu(&c, &r), 0);
  if (r.sw == SW_NO_ERROR) {
    assert_int_equal(r.len, CC_LEN);
    memcpy(out, r.data, CC_LEN);
  }
  return r.sw;
}

static uint16_t update_ndef(const uint8_t *data, uint8_t len) {
  select_file(0x00, 0x01);
  CAPDU c = {.ins = NDEF_INS_UPDATE, .p1 = 0, .p2 = 0, .data = (uint8_t *)data, .lc = len};
  RAPDU r = {.data = resp};
  assert_int_equal(ndef_process_apdu(&c, &r), 0);
  return r.sw;
}

static int toggle(uint8_t p1, uint16_t *sw) {
  CAPDU c = {.p1 = p1};
  RAPDU r = {.data = resp};
  const int ret = ndef_toggle_read_only(&c, &r);
  if (sw) *sw = r.sw;
  return ret;
}

static void test_ndef_cc_toggle_and_readback(void **state) {
  (void)state;
  uint8_t cc[CC_LEN];
  assert_int_equal(ndef_install(1), 0);

  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_int_equal(cc[13], 0x00); // read access: open
  assert_int_equal(cc[14], 0x00); // write access: open
  assert_int_equal(ndef_is_read_only(), 0);

  uint16_t sw;
  assert_int_equal(toggle(2, &sw), 0); // bad P1
  assert_int_equal(sw, SW_WRONG_P1P2);

  assert_int_equal(toggle(1, NULL), 0);
  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_int_equal(cc[14], 0xFF);
  assert_int_equal(ndef_is_read_only(), 1);
  assert_int_equal(update_ndef((const uint8_t *)"x", 1), SW_SECURITY_STATUS_NOT_SATISFIED);

  assert_int_equal(toggle(0, NULL), 0);
  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_int_equal(cc[14], 0x00);
  assert_int_equal(ndef_is_read_only(), 0);
  assert_int_equal(update_ndef((const uint8_t *)"x", 1), SW_NO_ERROR);
}

static void test_ndef_cc_write_error_invalidates_cache(void **state) {
  (void)state;
  assert_int_equal(ndef_install(1), 0);
  assert_int_equal(ndef_is_read_only(), 0);

  // The toggle's commit lands on disk but the last prog reports an error.
  // The cache must be invalidated and the reload must observe the new state.
  const unsigned before = bd_prog_count;
  assert_int_equal(toggle(1, NULL), 0);
  const unsigned commit_progs = bd_prog_count - before;
  assert_true(commit_progs > 0);
  assert_int_equal(toggle(0, NULL), 0);

  prog_fail_budget = (int)(commit_progs - 1);
  prog_fail_after = true;
  assert_int_equal(toggle(1, NULL), -1);
  faults_disarm();
  assert_int_equal(ndef_is_read_only(), 1); // reload sees the applied write

  // The same failure without executing the prog does not apply the toggle;
  // the reload still sees the persisted read-only state.
  prog_fail_budget = 0;
  assert_int_equal(toggle(0, NULL), -1);
  faults_disarm();
  assert_int_equal(ndef_is_read_only(), 1);

  // A later toggle recovers without any repair step.
  assert_int_equal(toggle(0, NULL), 0);
  assert_int_equal(ndef_is_read_only(), 0);
}

static void test_ndef_cc_reload_failure_rejects(void **state) {
  (void)state;
  assert_int_equal(ndef_install(1), 0);
  assert_int_equal(toggle(1, NULL), 0); // read-only on disk
  assert_int_equal(ndef_is_read_only(), 1);

  // Invalidate the cache with a failed toggle, then make reloads fail.
  prog_fail_budget = 0;
  assert_int_equal(toggle(0, NULL), -1);
  faults_disarm();
  fail_reads = true;
  // Permission data is unavailable: conservatively read-only, and
  // permission-dependent operations error out instead of using stale state.
  assert_int_equal(ndef_is_read_only(), 1);
  assert_int_equal(update_ndef((const uint8_t *)"x", 1), SW_UNABLE_TO_PROCESS);
  fail_reads = false;

  // Recovery without any write: the reload succeeds and the persisted
  // read-only permission (not stale RAM) still rejects the update.
  assert_int_equal(ndef_is_read_only(), 1);
  assert_int_equal(update_ndef((const uint8_t *)"x", 1), SW_SECURITY_STATUS_NOT_SATISFIED);

  // With the CC file missing and the cache invalid, loads keep failing...
  prog_fail_budget = 0;
  assert_int_equal(toggle(0, NULL), -1);
  faults_disarm();
  assert_int_equal(remove_file("E103"), 0);
  uint8_t cc[CC_LEN];
  assert_int_equal(read_cc(cc), SW_UNABLE_TO_PROCESS);
  assert_int_equal(ndef_is_read_only(), 1);

  // ...until install re-creates the CC and re-establishes the cache.
  assert_int_equal(ndef_install(0), 0);
  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_int_equal(cc[14], 0x00);
  assert_int_equal(update_ndef((const uint8_t *)"x", 1), SW_NO_ERROR);
}

static void test_ndef_cc_read_served_from_cache(void **state) {
  (void)state;
  uint8_t cc[CC_LEN];
  assert_int_equal(ndef_install(1), 0); // establishes a valid cache

  // A CC read with a valid cache performs no block-device reads.
  unsigned reads = bd_read_count;
  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_int_equal(cc[13], 0x00);
  assert_int_equal(bd_read_count, reads);

  // With an invalidated cache the next read falls through to flash once...
  prog_fail_budget = 0;
  assert_int_equal(toggle(1, NULL), -1);
  faults_disarm();
  reads = bd_read_count;
  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_true(bd_read_count > reads);
  assert_int_equal(cc[14], 0x00); // the failed toggle did not apply

  // ...and is served from the re-populated cache afterwards.
  reads = bd_read_count;
  assert_int_equal(read_cc(cc), SW_NO_ERROR);
  assert_int_equal(bd_read_count, reads);

  // The NDEF data file is still read from flash.
  reads = bd_read_count;
  select_file(0x00, 0x01);
  CAPDU c = {.ins = NDEF_INS_READ_BINARY, .p1 = 0, .p2 = 0, .le = 4};
  RAPDU r = {.data = resp};
  assert_int_equal(ndef_process_apdu(&c, &r), 0);
  assert_int_equal(r.sw, SW_NO_ERROR);
  assert_int_equal(r.len, 4);
  assert_true(bd_read_count > reads);
}

int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  struct lfs_filebd_config bdcfg = {.read_size = 1, .prog_size = 512, .erase_size = 512, .erase_count = 256};
  bd.cfg = &bdcfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &ndef_bd_read;
  cfg.prog = &ndef_bd_prog;
  cfg.erase = &lfs_filebd_erase;
  cfg.sync = &lfs_filebd_sync;
  cfg.read_size = 1;
  cfg.prog_size = 512;
  cfg.block_size = 512;
  cfg.block_count = 256;
  cfg.block_cycles = 50000;
  cfg.cache_size = 512;
  cfg.lookahead_size = 32;
  lfs_filebd_create(&cfg, "lfs-root-ndef", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ndef_cc_toggle_and_readback),
      cmocka_unit_test(test_ndef_cc_write_error_invalidates_cache),
      cmocka_unit_test(test_ndef_cc_reload_failure_rejects),
      cmocka_unit_test(test_ndef_cc_read_served_from_cache),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
