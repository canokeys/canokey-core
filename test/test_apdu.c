// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <cmocka.h>

#include <admin.h>
#include <applets.h>
#include <applet-scratch.h>
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <canokey-core-git-rev.h>
#include <ccid.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device-config.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <platform-config.h>
#include "../applets/ctap/secret.h"
#include "../applets/ctap/ctap-errors.h"
#include "../applets/ctap/ctap-internal.h"
#include <hmac.h>
#include <sha.h>
#include <string.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>
#include <usbd_ccid.h>
#include <usbd_kbdhid.h>
#include <usbd_ctlreq.h>


#define CTAP_LARGE_BLOBS 0x0C
#define LB_FILE "ctap_lb"

#include "../virt-card/usb-dummy.h"

extern ccid_bulkin_data_t bulkin_data;

static void provision_test_attestation(void) {
  static const uint8_t private_key[PRI_KEY_SIZE] = {1};
  static const uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};

  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, private_key, sizeof(private_key)), 0);
  assert_int_equal(write_file(CTAP_CERT_FILE, cert, 0, sizeof(cert), 1), 0);
}

static void assert_ctap_install_resets_counter(void) {
  uint32_t counter = UINT32_MAX;

  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(read_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), sizeof(counter));
  assert_int_equal(counter, 0);
  provision_test_attestation();
  assert_int_equal(ctap_install(0), 0);
}

static void test_ctap_install_rebuilds_state_without_attestation_key(void **state) {
  (void)state;
  const uint32_t counter = 0x12345678;

  provision_test_attestation();
  assert_int_equal(remove_attr(CTAP_CERT_FILE, KEY_ATTR), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), 0);
  assert_ctap_install_resets_counter();
}

static void test_ctap_install_rebuilds_state_with_short_attestation_key(void **state) {
  (void)state;
  const uint8_t short_key[PRI_KEY_SIZE - 1] = {1};
  const uint32_t counter = 0x12345678;

  provision_test_attestation();
  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, short_key, sizeof(short_key)), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), 0);
  assert_ctap_install_resets_counter();
}

static void test_ctap_install_rebuilds_state_with_empty_attestation_cert(void **state) {
  (void)state;
  const uint32_t counter = 0x12345678;

  provision_test_attestation();
  assert_int_equal(write_file(CTAP_CERT_FILE, NULL, 0, 0, 1), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), 0);
  assert_ctap_install_resets_counter();
}

static void test_ctap_install_preserves_sm2_during_state_rebuild(void **state) {
  (void)state;
  CTAP_sm2_attr saved, actual;
  const CTAP_sm2_attr custom = {.curve_id = INT32_MIN, .algo_id = INT32_MAX};
  const CTAP_sm2_attr invalid = {.curve_id = 1, .algo_id = -54};
  assert_int_equal(ctap_platform_sm2_config_read(&saved, sizeof(saved)), 0);
  assert_int_equal(ctap_platform_sm2_config_write(&custom, sizeof(custom)), 0);
  assert_int_equal(write_file(LB_FILE, NULL, 0, 0, 1), 0);
  assert_int_equal(remove_attr(CTAP_CERT_FILE, KEY_ATTR), 0);
  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(ctap_platform_sm2_config_read(&actual, sizeof(actual)), 0);
  assert_memory_equal(&actual, &custom, sizeof(actual));

  assert_int_equal(ctap_platform_sm2_config_write(&invalid, sizeof(invalid)), 0);
  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(ctap_platform_sm2_config_read(&actual, sizeof(actual)), 0);
  assert_int_equal(actual.curve_id, 9);
  assert_int_equal(actual.algo_id, -54);
  assert_int_equal(ctap_platform_sm2_config_write(&saved, sizeof(saved)), 0);
  provision_test_attestation();
  assert_int_equal(ctap_install(0), 0);
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
  cfg.cache_size = 512;
  cfg.lookahead_size = 32;
  // Keep LittleFS work buffers owned by the fixture.
  static uint8_t read_buffer[512], prog_buffer[512], lookahead_buffer[32];
  cfg.read_buffer = read_buffer;
  cfg.prog_buffer = prog_buffer;
  cfg.lookahead_buffer = lookahead_buffer;
  lfs_filebd_create(&cfg, "lfs-root-apdu", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ctap_install_preserves_sm2_during_state_rebuild),
      cmocka_unit_test(test_ctap_install_rebuilds_state_without_attestation_key),
      cmocka_unit_test(test_ctap_install_rebuilds_state_with_short_attestation_key),
      cmocka_unit_test(test_ctap_install_rebuilds_state_with_empty_attestation_cert),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
