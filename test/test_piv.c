// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <bd/lfs_filebd.h>
#include <cmocka.h>
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <piv.h>
#include <platform-config.h>
#include <string.h>


static void test_piv_migrates_legacy_management_key_types(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  enum { LEGACY_TDEA = 11, LEGACY_AES128 = 12, LEGACY_AES256 = 13 };
  static const struct {
    unsigned legacy_type;
    key_type_t current_type;
    size_t key_len;
  } cases[] = {
      {LEGACY_TDEA, TDEA, 24},
      {LEGACY_AES128, AES128, 16},
      {LEGACY_AES256, AES256, 32},
  };
  uint8_t key_material[32] = {0};
  key_meta_t meta;
  assert_true(ck_read_key_metadata("piv-k9b", &meta) >= 0);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    meta.type = (key_type_t)cases[i].legacy_type;
    assert_int_equal(write_file("piv-k9b", key_material, 0, cases[i].key_len, 1), 0);
    assert_true(ck_write_key_metadata("piv-k9b", &meta) >= 0);
    assert_int_equal(piv_install(0), 0);
    assert_true(ck_read_key_metadata("piv-k9b", &meta) >= 0);
    assert_int_equal(meta.type, cases[i].current_type);
  }

  assert_int_equal(piv_install(1), 0);
}

static void test_piv_startup_preserves_state_when_platform_config_is_invalid(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  static const uint8_t key_sentinel[] = {0x4B, 0x45, 0x59};
  static const uint8_t cert_sentinel[] = {0x43, 0x45, 0x52, 0x54};
  assert_int_equal(write_file("piv-k9a", key_sentinel, 0, sizeof(key_sentinel), 1), 0);
  assert_int_equal(write_file("piv-c9a", cert_sentinel, 0, sizeof(cert_sentinel), 1), 0);

  uint8_t valid_config[PLATFORM_CONFIG_PAGE_SIZE];
  uint8_t invalid_config[PLATFORM_CONFIG_PAGE_SIZE];
  assert_int_equal(platform_config_page_read(0, valid_config, sizeof(valid_config)), 0);
  memcpy(invalid_config, valid_config, sizeof(invalid_config));
  invalid_config[sizeof(invalid_config) - 1] ^= 0x01;
  assert_int_equal(platform_config_page_write(invalid_config, sizeof(invalid_config)), 0);

  assert_int_equal(piv_install(0), -1);
  uint8_t actual[sizeof(cert_sentinel)];
  assert_int_equal(read_file("piv-k9a", actual, 0, sizeof(key_sentinel)), sizeof(key_sentinel));
  assert_memory_equal(actual, key_sentinel, sizeof(key_sentinel));
  assert_int_equal(read_file("piv-c9a", actual, 0, sizeof(cert_sentinel)), sizeof(cert_sentinel));
  assert_memory_equal(actual, cert_sentinel, sizeof(cert_sentinel));

  assert_int_equal(platform_config_page_write(valid_config, sizeof(valid_config)), 0);
  assert_int_equal(piv_install(1), 0);
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
  lfs_filebd_create(&cfg, "lfs-root-piv", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  piv_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_piv_migrates_legacy_management_key_types),
      cmocka_unit_test(test_piv_startup_preserves_state_when_platform_config_is_invalid),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
