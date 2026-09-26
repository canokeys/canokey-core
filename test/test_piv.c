// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <apdu.h>
#include <aes.h>
#include <bd/lfs_filebd.h>
#include <cmocka.h>
#include <crypto-util.h>
#include <device.h>
#include <device-config.h>
#include <firmware-version.h>
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <memzero.h>
#include <ml-kem-768.h>
#include <piv.h>
#include <platform-config.h>
#include <rsa.h>
#include <sha.h>
#include <string.h>

#include "ecdsa-generic.h"
#include "nist256p1.h"

extern void set_admin_status(int status);


static void test_helper_resp(uint8_t *data, size_t data_len, uint8_t ins, uint8_t p1, uint8_t p2,
                             uint16_t expected_error, uint8_t *expected_resp, size_t resp_len) {
  uint8_t c_buf[1024], r_buf[1024];
  // only tag, no length nor data
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = ins;
  capdu->p1 = p1;
  capdu->p2 = p2;
  capdu->lc = data_len;
  if (data_len > 0) {
    // re alloc to help asan find overflow error
    capdu->data = malloc(data_len);
    memcpy(capdu->data, data, data_len);
  } else {
    // when lc = 0, data should never be read
    capdu->data = NULL;
  }

  piv_process_apdu(capdu, rapdu);
  if (data_len > 0) {
    free(capdu->data);
  }
  assert_int_equal(rapdu->sw, expected_error);
  print_hex(RDATA, LL);
  if (expected_resp != NULL) {
    assert_int_equal(rapdu->len, resp_len);
    assert_memory_equal(RDATA, expected_resp, resp_len);
  }
}

static void test_helper(uint8_t *data, size_t data_len, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t expected_error) {
  // don't check resp
  test_helper_resp(data, data_len, ins, p1, p2, expected_error, NULL, 0);
}

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









static void test_piv_get_metadata_directory(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  ck_key_t key;
  ck_key_init_empty(&key, SECP256R1, SIGN, PIN_POLICY_ONCE, TOUCH_POLICY_NEVER);
  key.meta.origin = KEY_ORIGIN_GENERATED;
  assert_int_equal(ck_write_key("piv-k9a", &key), 0);

  const uint8_t cert = 0x53;
  assert_int_equal(write_file("piv-c9c", &cert, 0, sizeof(cert), 1), 0);
  assert_int_equal(write_file("piv-c9d", NULL, 0, 0, 1), 0); // Empty certificate files do not count.

  ck_key_init_empty(&key, SECP384R1, KEY_USAGE_ANY, PIN_POLICY_ALWAYS, TOUCH_POLICY_CACHED);
  key.meta.origin = KEY_ORIGIN_IMPORTED;
  assert_int_equal(ck_write_key("piv-k82", &key), 0);
  assert_int_equal(write_file("piv-c82", &cert, 0, sizeof(cert), 1), 0);
  memzero(&key, sizeof(key));

  uint8_t response[APDU_BUFFER_SIZE];
  RAPDU R = {.data = response};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x01, .p2 = 0x00, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  static const uint8_t expected[] = {
      0x01, 0x01, 0x01, 0x02, 18,
      0x9A, 0x01, 0x11, KEY_ORIGIN_GENERATED, PIN_POLICY_ONCE, TOUCH_POLICY_NEVER,
      0x9C, 0x02, 0x00, 0x00, 0x00, 0x00,
      0x82, 0x03, 0x14, KEY_ORIGIN_IMPORTED, PIN_POLICY_ALWAYS, TOUCH_POLICY_CACHED,
  };
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, expected, sizeof(expected));

  // The maximum 24-entry directory still uses a single-byte length and fits in one response.
  assert_int_equal(piv_install(1), 0);
  static const uint8_t slots[] = {0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x83, 0x84, 0x85,
                                  0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
                                  0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95};
  static const char hex[] = "0123456789abcdef";
  char cert_path[] = "piv-c00";
  for (size_t i = 0; i < sizeof(slots); ++i) {
    cert_path[5] = hex[slots[i] >> 4u];
    cert_path[6] = hex[slots[i] & 0x0Fu];
    assert_int_equal(write_file(cert_path, &cert, 0, sizeof(cert), 1), 0);
  }

  R.len = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 5 + sizeof(slots) * 6);
  assert_memory_equal(R.data, ((const uint8_t[]){0x01, 0x01, 0x01, 0x02, 0x90}), 5);
  for (size_t i = 0; i < sizeof(slots); ++i) {
    const uint8_t expected_entry[] = {slots[i], 0x02, 0x00, 0x00, 0x00, 0x00};
    assert_memory_equal(R.data + 5 + i * sizeof(expected_entry), expected_entry, sizeof(expected_entry));
  }

  C.p2 = 0x01;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);
  C.p2 = 0x00;
  C.data = (uint8_t *)&cert;
  C.lc = 1;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);
  C.data = NULL;
  C.lc = 0;
  C.p1 = 0x02;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  assert_int_equal(piv_install(1), 0);
}


static void test_piv_move_delete_key_extension(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  ck_key_t key = {.meta = {.type = SECP256R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-k9a", &key), 0);
  ck_key_t original_key = key;

  uint8_t cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xA5};
  set_admin_status(1);
  test_helper(cert, sizeof(cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  set_admin_status(0);

  uint8_t r_buf[256];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9A, .lc = 0};

  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  set_admin_status(1);

  C = (CAPDU){.data = r_buf, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9A, .lc = 1};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9B, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9B, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9D, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9A, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  assert_int_equal(ck_write_key("piv-k9c", &key), 0);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9C, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  ck_key_t moved_key;
  assert_true(ck_read_key("piv-k9c", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));

  assert_int_equal(get_file_size("piv-k9a"), LFS_ERR_NOENT);

  // Simulate reboot: an absent ordinary key slot is valid initialized state.
  assert_int_equal(piv_install(0), 0);
  assert_true(ck_read_key("piv-k9c", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));
  assert_int_equal(get_file_size("piv-k9a"), LFS_ERR_NOENT);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  set_admin_status(1);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x95, .p2 = 0x9C, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key("piv-k95", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));
  assert_int_equal(get_file_size("piv-k9c"), LFS_ERR_NOENT);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9D, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-k95") < 0);
  assert_true(ck_read_key("piv-k9d", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9D, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  uint8_t get_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05};
  uint8_t expected_cert[] = {0x53, 0x01, 0xA5};
  C = (CAPDU){.data = get_cert,
              .cla = 0x00,
              .ins = PIV_INS_GET_DATA,
              .p1 = 0x3F,
              .p2 = 0xFF,
              .lc = sizeof(get_cert),
              .le = 256};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected_cert));
  assert_memory_equal(R.data, expected_cert, sizeof(expected_cert));

  piv_install(1);
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
      cmocka_unit_test(test_piv_get_metadata_directory),
      cmocka_unit_test(test_piv_move_delete_key_extension),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
