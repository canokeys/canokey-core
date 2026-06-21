// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <cmocka.h>
#include <crypto-util.h>
#include <device.h>
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <piv.h>
#include <string.h>

extern void set_admin_status(int status);

static void inject_write_error(const char *path) {
  testmode_inject_error(0, 0, (uint16_t)strlen(path), (const uint8_t *)path);
}

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

// regression tests for crashes discovered by fuzzing
static void test_regression_fuzz(void **state) {
  (void)state;

  if (1) {
    // zero length data
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x00, SW_WRONG_LENGTH);
  }

  if (1) {
    // only tag
    uint8_t data[] = {0x7C};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // only tag and bad length
    uint8_t data[] = {0x7C, 0x80};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // malformed authenticate payload
    uint8_t data[] = {0x00, 0x00};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0xFF, 0x9B, SW_WRONG_DATA);
  }

  if (1) {
    // valid authenticate payload with unsupported card admin algorithm
    uint8_t data[] = {0x7C, 0x00};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0xFF, 0x9B, SW_WRONG_P1P2);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  // bypass authentication, testing only
  set_admin_status(1);

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, 0x9A, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty object path
    uint8_t data[] = {0x5C, 0x03, 0x5F, 0xC1};
    test_helper(data, sizeof(data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty object path
    uint8_t data[] = {0xAC, 0x00, 0x80, 0x01};
    test_helper(data, sizeof(data), PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, 0x9A, SW_WRONG_LENGTH);
  }

  if (1) {
    // import symmetric key
    // 00FE079C 91
    // 013E4C9CA1020204000000000000005B08020C00000000000000020202020202020202020202020202020202022D0D0202020202020202020202020202020202025050505050505002505050505002020202025002020202020202028202020202E78DE4F3D506F6B7A3F8BD10CB29DADE18B83B6ED7AB37A3B73A9A11348E17B60B65119055DD2497942D363431323734
    uint8_t data[] = {0x01,
                      // TLV
                      0x3E, 0x01, 0x00};
    test_helper(data, sizeof(data), PIV_INS_IMPORT_ASYMMETRIC_KEY, 0x07, 0x9C, SW_WRONG_LENGTH);
  }
}

static void test_delete_certificate_object(void **state) {
  (void)state;

  set_admin_status(1);

  uint8_t put_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xAA};
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-pauc"), 3);

  uint8_t delete_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x00};
  test_helper(delete_cert, sizeof(delete_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_true(get_file_size("piv-pauc") < 0);
}

static const uint8_t default_piv_pin[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
static const uint8_t default_mgmt_key[24] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

static void configure_host_managed_admin_data(void) {
  set_admin_status(1);

  uint8_t printed[5 + 30] = {0x5C, 0x03, 0x5F, 0xC1, 0x09, 0x53, 0x1C, 0x88, 0x1A, 0x89, 0x18};
  memcpy(printed + 11, default_mgmt_key, sizeof(default_mgmt_key));
  test_helper(printed, sizeof(printed), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);

  uint8_t admin_data[] = {0x5C, 0x03, 0x5F, 0xFF, 0x00, 0x53, 0x05, 0x80, 0x03, 0x81, 0x01, 0x03};
  test_helper(admin_data, sizeof(admin_data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);

  set_admin_status(0);
}

static void test_piv_host_managed_admin_data_objects(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  const int admin_key_size = get_file_size("piv-admk");
  configure_host_managed_admin_data();
  assert_int_equal(get_file_size("piv-admk"), admin_key_size);
  piv_poweroff();

  uint8_t get_printed[] = {0x5C, 0x03, 0x5F, 0xC1, 0x09};
  test_helper(get_printed, sizeof(get_printed), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);

  test_helper((uint8_t *)default_piv_pin, sizeof(default_piv_pin), PIV_INS_VERIFY, 0x00, 0x80, SW_NO_ERROR);

  uint8_t expected_printed[30] = {0x53, 0x1C, 0x88, 0x1A, 0x89, 0x18};
  memcpy(expected_printed + 6, default_mgmt_key, sizeof(default_mgmt_key));
  test_helper_resp(get_printed, sizeof(get_printed), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_NO_ERROR, expected_printed,
                   sizeof(expected_printed));

  piv_poweroff();
  uint8_t get_admin[] = {0x5C, 0x03, 0x5F, 0xFF, 0x00};
  uint8_t expected_admin[] = {0x53, 0x05, 0x80, 0x03, 0x81, 0x01, 0x03};
  test_helper_resp(get_admin, sizeof(get_admin), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_NO_ERROR, expected_admin,
                   sizeof(expected_admin));
}

static void test_piv_pin_does_not_satisfy_admin(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  configure_host_managed_admin_data();
  piv_poweroff();

  uint8_t put_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xAA};
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);

  test_helper((uint8_t *)default_piv_pin, sizeof(default_piv_pin), PIV_INS_VERIFY, 0x00, 0x80, SW_NO_ERROR);
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);
  assert_true(get_file_size("piv-pauc") < 0);
}

static void test_piv_retired_cert_lazy_storage(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  assert_true(get_file_size("piv-r20") < 0);

  set_admin_status(1);
  uint8_t put_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x20, 0x53, 0x01, 0x55};
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-r20"), 3);

  uint8_t get_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x20};
  uint8_t expected[] = {0x53, 0x01, 0x55};
  uint8_t r_buf[256];
  CAPDU C = {.data = get_cert, .ins = PIV_INS_GET_DATA, .p1 = 0x3F, .p2 = 0xFF, .lc = sizeof(get_cert), .le = 256};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, expected, sizeof(expected));
}

static void test_piv_metadata_bounded_do_storage(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  set_admin_status(1);

  uint8_t inline_printed[5 + 64] = {0x5C, 0x03, 0x5F, 0xC1, 0x09};
  for (size_t i = 5; i < sizeof(inline_printed); ++i) {
    inline_printed[i] = (uint8_t)i;
  }
  test_helper(inline_printed, sizeof(inline_printed), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_true(get_file_size("piv-pi") < 0);

  uint8_t max_admin_data[5 + 128] = {0x5C, 0x03, 0x5F, 0xFF, 0x00};
  for (size_t i = 5; i < sizeof(max_admin_data); ++i) {
    max_admin_data[i] = (uint8_t)(0x80 + i);
  }
  test_helper(max_admin_data, sizeof(max_admin_data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);

  uint8_t large_printed[5 + 80] = {0x5C, 0x03, 0x5F, 0xC1, 0x09};
  for (size_t i = 5; i < sizeof(large_printed); ++i) {
    large_printed[i] = (uint8_t)i;
  }
  test_helper(large_printed, sizeof(large_printed), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-pi"), 80);

  uint8_t security[] = {0x5C, 0x03, 0x5F, 0xC1, 0x06, 0x53, 0x02, 0x11, 0x22};
  test_helper(security, sizeof(security), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-sec"), 4);

  uint8_t key_history[] = {0x5C, 0x03, 0x5F, 0xC1, 0x0C, 0x53, 0x01, 0x33};
  test_helper(key_history, sizeof(key_history), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-kh"), 3);

  configure_host_managed_admin_data();
  assert_true(get_file_size("piv-pi") < 0);
}

// piv_get_metadata's key_type_to_algo_id switch maps each supported
// PIV key type to the runtime-configurable algorithm-extension byte.
// Integration tests only exercise the RSA2048 / SECP256R1 / SECP384R1
// arms; the extended types (ED25519, X25519, SECP256K1, SECP521R1, SM2) live
// behind alg_ext_cfg.* defaults that piv_install pre-populates. Drop a
// well-formed asymmetric key in the AUTH slot for each type and read
// metadata back; the second algorithm byte should match the default
// table.
static void test_piv_get_metadata_extended_algo_ids(void **state) {
  (void)state;

  // alg_ext_cfg defaults from piv_install.
  static const struct {
    key_type_t type;
    uint8_t expected_algo_id;
  } cases[] = {
      {ED25519, 0xE0}, {X25519, 0xE1}, {SECP256K1, 0x53}, {SECP521R1, 0x15}, {SM2, 0x54},
  };

  set_admin_status(1);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    ck_key_t key = {.meta = {.type = cases[i].type,
                             .origin = KEY_ORIGIN_GENERATED,
                             .usage = SIGN,
                             .pin_policy = PIN_POLICY_NEVER,
                             .touch_policy = TOUCH_POLICY_NEVER}};
    assert_int_equal(ck_generate_key(&key), 0);
    assert_int_equal(ck_write_key("piv-pauk", &key), 0);

    uint8_t r_buf[256];
    CAPDU C = {.data = NULL, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
    RAPDU R = {.data = r_buf};
    piv_process_apdu(&C, &R);

    assert_int_equal(R.sw, SW_NO_ERROR);
    // Layout: 01 01 <algo> 02 02 <pin> <touch> 03 01 <origin> 04 ...
    assert_true(R.len >= 11);
    assert_int_equal(R.data[0], 0x01);
    assert_int_equal(R.data[1], 0x01);
    assert_int_equal(R.data[2], cases[i].expected_algo_id);
    assert_int_equal(R.data[3], 0x02);
    assert_int_equal(R.data[4], 0x02);
    assert_int_equal(R.data[5], PIN_POLICY_NEVER);
    assert_int_equal(R.data[6], TOUCH_POLICY_NEVER);
    assert_int_equal(R.data[7], 0x03);
    assert_int_equal(R.data[8], 0x01);
    assert_int_equal(R.data[9], KEY_ORIGIN_GENERATED);
    assert_int_equal(R.data[10], 0x04);
  }
}

static void test_piv_delete_key_extension(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  ck_key_t key = {.meta = {.type = SECP256R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);

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

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = r_buf, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9A, .lc = 1};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9B, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

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

static void test_piv_dynamic_retired_key_slots(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  uint8_t r_buf[256];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);
  assert_true(get_file_size("piv-95") < 0);

  set_admin_status(1);
  uint8_t generate_p256[] = {0xAC, 0x03, 0x80, 0x01, 0x11};
  C = (CAPDU){.data = generate_p256,
              .cla = 0x00,
              .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
              .p1 = 0x00,
              .p2 = 0x95,
              .lc = sizeof(generate_p256)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-95") >= 0);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len >= 11);
  assert_int_equal(R.data[2], 0x11);
  assert_int_equal(R.data[5], PIN_POLICY_ONCE);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-95") < 0);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  piv_install(1);
}

static void test_piv_reset_preserves_platform_algorithm_extension(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t custom = {
      .enabled = 1,
      .ed25519 = 0x22,
      .rsa3072 = 0x05,
      .rsa4096 = 0x51,
      .x25519 = 0x52,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&custom), 0);

  // A PIV reset rebuilds LittleFS-backed applet state, but the algorithm
  // extension record belongs to platform configuration and must survive it.
  assert_int_equal(piv_install(1), 0);

  piv_algorithm_extension_config_t actual;
  assert_int_equal(piv_platform_algorithm_extension_config_read(&actual), 0);
  assert_memory_equal(&actual, &custom, sizeof(custom));

  set_admin_status(1);
  uint8_t generate_ed25519[] = {0xAC, 0x03, 0x80, 0x01, custom.ed25519};
  uint8_t r_buf[128];
  CAPDU C = {.data = generate_ed25519,
             .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
             .p1 = 0x00,
             .p2 = 0x9A,
             .lc = sizeof(generate_ed25519)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  const piv_algorithm_extension_config_t defaults = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x55,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&defaults), 0);
  assert_int_equal(piv_install(1), 0);
}

static void test_piv_algorithm_extension_read_without_admin(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t expected = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&expected), 0);
  assert_int_equal(piv_install(1), 0);

  set_admin_status(0);
  uint8_t r_buf[128];
  CAPDU C = {.data = NULL, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x01, .p2 = 0x00, .lc = 0};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, &expected, sizeof(expected));

  C = (CAPDU){
      .data = (uint8_t *)&expected, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x02, .p2 = 0x00, .lc = sizeof(expected)};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
}

static void test_piv_algorithm_extension_read_after_write(void **state) {
  (void)state;

  piv_algorithm_extension_config_t expected = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };

  set_admin_status(1);
  uint8_t r_buf[128];
  CAPDU C = {
      .data = (uint8_t *)&expected, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x02, .p2 = 0x00, .lc = sizeof(expected)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  set_admin_status(0);
  C = (CAPDU){.data = NULL, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x01, .p2 = 0x00, .lc = 0};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, &expected, sizeof(expected));
}

static void test_ed25519_general_authenticate_long_message(void **state) {
  (void)state;

  ck_key_t key = {.meta = {.type = ED25519,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);

  enum { MSG_LEN = 130 };
  uint8_t data[8 + MSG_LEN] = {0};
  data[0] = 0x7C;
  data[1] = 0x81;
  data[2] = MSG_LEN + 5;
  data[3] = 0x82;
  data[4] = 0x00;
  data[5] = 0x81;
  data[6] = 0x81;
  data[7] = MSG_LEN;
  for (uint8_t i = 0; i < MSG_LEN; ++i)
    data[8 + i] = i;

  uint8_t r_buf[128];
  CAPDU C = {.data = data, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0xE0, .p2 = 0x9A, .lc = sizeof(data)};
  RAPDU R = {.data = r_buf};

  piv_process_apdu(&C, &R);

  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 68);
  assert_memory_equal(R.data, ((uint8_t[]){0x7C, 0x42, 0x82, 0x40}), 4);
}

static void test_secp521r1_generate_and_authenticate(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t defaults = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&defaults), 0);
  assert_int_equal(piv_install(1), 0);
  set_admin_status(1);

  uint8_t r_buf[512];
  uint8_t generate[] = {0xAC, 0x03, 0x80, 0x01, 0x15};
  CAPDU C = {
      .data = generate, .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, .p1 = 0x00, .p2 = 0x9A, .lc = sizeof(generate)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 140);
  assert_memory_equal(R.data, ((uint8_t[]){0x7F, 0x49, 0x81, 0x88, 0x86, 0x81, 0x85, 0x04}), 8);

  uint8_t generate_with_policy[] = {0xAC, 0x06, 0x80, 0x01, 0x15, 0xAA, 0x01, 0x02, 0xAB, 0x01, 0x01};
  C = (CAPDU){.data = generate_with_policy,
              .cla = 0x00,
              .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
              .p1 = 0x00,
              .p2 = 0x9A,
              .lc = sizeof(generate_with_policy)};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len > 11);
  assert_int_equal(R.data[2], 0x15);

  ck_key_t key = {.meta = {.type = SECP521R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);

  uint8_t data[6 + 66] = {0};
  data[0] = 0x7C;
  data[1] = 0x46;
  data[2] = 0x82;
  data[3] = 0x00;
  data[4] = 0x81;
  data[5] = 0x42;
  for (uint8_t i = 0; i < 66; ++i)
    data[6 + i] = i;

  C = (CAPDU){
      .data = data, .cla = 0x00, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0x15, .p2 = 0x9A, .lc = sizeof(data)};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);

  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len > 8);
  assert_int_equal(R.data[0], 0x7C);
  assert_int_equal(R.data[1], 0x82);
  assert_int_equal(R.data[4], 0x82);
  assert_int_equal(R.data[5], 0x82);
  assert_int_equal(R.data[6], 0x00);
  assert_true(R.data[7] >= 0x89);
  assert_int_equal(R.data[8], 0x30);
  assert_int_equal(R.data[9], 0x81);
  assert_int_equal(R.data[10] + 3, R.data[7]);
}

static void test_secp521r1_custom_algorithm_id(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t custom = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x55,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&custom), 0);
  assert_int_equal(piv_install(1), 0);
  set_admin_status(1);

  uint8_t r_buf[512];
  uint8_t generate_with_policy[] = {0xAC, 0x06, 0x80, 0x01, 0x55, 0xAA, 0x01, 0x02, 0xAB, 0x01, 0x01};
  CAPDU C = {.data = generate_with_policy,
             .cla = 0x00,
             .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
             .p1 = 0x00,
             .p2 = 0x9A,
             .lc = sizeof(generate_with_policy)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 140);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[2], 0x55);

  const piv_algorithm_extension_config_t defaults = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&defaults), 0);
  assert_int_equal(piv_install(1), 0);
}

static void test_set_pin_retries(void **state) {
  (void)state;

  uint8_t r_buf[128];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};

  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  uint8_t pin_data[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
  C = (CAPDU){.data = pin_data, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(pin_data)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 0, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 16, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = pin_data, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 1};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x80, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[5], 1);
  assert_int_equal(R.data[8], 4);
  assert_int_equal(R.data[9], 4);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x81, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[5], 1);
  assert_int_equal(R.data[8], 5);
  assert_int_equal(R.data[9], 5);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, 0x63C4);

  uint8_t old_pin[8] = {'0', '0', '0', '0', '0', '0', 0xFF, 0xFF};
  C = (CAPDU){.data = old_pin, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(old_pin)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, 0x63C3);

  C = (CAPDU){.data = pin_data, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(pin_data)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  set_admin_status(1);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 15, .p2 = 15, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  piv_install(1);
}

static void test_set_pin_retries_failure_invalidates_auth(void **state) {
  (void)state;

  uint8_t r_buf[128];
  RAPDU R = {.data = r_buf};
  uint8_t pin_data[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
  CAPDU C = {.data = pin_data, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(pin_data)};

  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  inject_write_error("piv-puk");
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_UNABLE_TO_PROCESS);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  piv_install(1);
}

// piv_process_apdu_message uses RAPDU_CHAINING + apdu_output to stream
// large responses in 256-byte chunks. Stage a >256-byte certificate via
// chained PUT DATA APDUs (PIV applet handles cross-APDU chaining itself),
// then walk the GET DATA + GET RESPONSE chain and verify byte content +
// SW chain. This covers the PIV chaining dispatcher's GET DATA / GET
// RESPONSE state transitions and the apdu_output non-source chaining
// branch.
static void test_piv_cert_chained_read(void **state) {
  (void)state;
  set_admin_status(1);

  // 600-byte payload large enough to span three 256-byte chunks.
  enum { CERT_LEN = 600 };
  uint8_t cert[CERT_LEN];
  for (size_t i = 0; i < CERT_LEN; ++i)
    cert[i] = (uint8_t)(0xC0 + (i & 0x3F));

  uint8_t r_buf[1024];
  RAPDU rapdu = {.data = r_buf};
  RAPDU_CHAINING rc = {.rapdu.data = r_buf};

  // First PUT DATA chunk: 5C-tag selects PIV Authentication slot, then 53
  // BER-TLV with the cert length, then the first 200 bytes of cert. CLA
  // 0x10 = "more chunks follow"; PIV applet handles the chain itself.
  enum { HDR_LEN = 5 + 4, FIRST_CHUNK = 200 };
  uint8_t first_data[HDR_LEN + FIRST_CHUNK];
  first_data[0] = 0x5C;
  first_data[1] = 0x03;
  first_data[2] = 0x5F;
  first_data[3] = 0xC1;
  first_data[4] = 0x05;
  first_data[5] = 0x53;
  first_data[6] = 0x82;
  first_data[7] = (uint8_t)(CERT_LEN >> 8);
  first_data[8] = (uint8_t)(CERT_LEN & 0xFF);
  memcpy(first_data + HDR_LEN, cert, FIRST_CHUNK);
  CAPDU put_first = {
      .data = first_data,
      .cla = 0x10,
      .ins = PIV_INS_PUT_DATA,
      .p1 = 0x3F,
      .p2 = 0xFF,
      .lc = sizeof(first_data),
      .le = 0,
  };
  rc.rapdu.len = 0;
  rc.sent = 0;
  rapdu.len = 0;
  rapdu.sw = 0;
  piv_process_apdu_message(&rc, &put_first, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // Subsequent chunks: 200 bytes each, last one without the chain bit.
  uint8_t chunk[200];
  for (int round = 0; round < 2; ++round) {
    size_t off = FIRST_CHUNK + (size_t)round * 200;
    memcpy(chunk, cert + off, 200);
    CAPDU put_more = {
        .data = chunk,
        .cla = (round == 1) ? 0x00 : 0x10,
        .ins = PIV_INS_PUT_DATA,
        .p1 = 0x3F,
        .p2 = 0xFF,
        .lc = 200,
        .le = 0,
    };
    rc.rapdu.len = 0;
    rc.sent = 0;
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu_message(&rc, &put_more, &rapdu);
    assert_int_equal(rapdu.sw, SW_NO_ERROR);
  }
  assert_int_equal(get_file_size("piv-pauc"), CERT_LEN + 4); // 53 82 LL HH header + cert

  // Now read it back via GET DATA + GET RESPONSE chain.
  uint8_t get_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05};
  CAPDU get_apdu = {
      .data = get_cert,
      .cla = 0x00,
      .ins = PIV_INS_GET_DATA,
      .p1 = 0x3F,
      .p2 = 0xFF,
      .lc = sizeof(get_cert),
      .le = 0x100,
  };
  rc.rapdu.len = 0;
  rc.sent = 0;
  rapdu.len = 0;
  rapdu.sw = 0;
  piv_process_apdu_message(&rc, &get_apdu, &rapdu);
  // First chunk: 256 bytes, SW indicates more remaining.
  assert_int_equal(rapdu.len, 256);
  assert_int_equal(rapdu.sw & 0xFF00, 0x6100);

  uint8_t reassembled[1024];
  size_t total = rapdu.len;
  memcpy(reassembled, rapdu.data, rapdu.len);

  // Drain via GET RESPONSE until SW_NO_ERROR.
  CAPDU gr_apdu = {.data = NULL, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .lc = 0, .le = 0x100};
  while ((rapdu.sw & 0xFF00) == 0x6100) {
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu_message(&rc, &gr_apdu, &rapdu);
    assert_true(rapdu.len > 0);
    assert_true(total + rapdu.len <= sizeof(reassembled));
    memcpy(reassembled + total, rapdu.data, rapdu.len);
    total += rapdu.len;
  }
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // The retrieved object is a 53/82 BER-TLV wrapper around the original
  // cert: 53 82 LL HH || cert bytes.
  assert_true(total >= 4 + CERT_LEN);
  assert_int_equal(reassembled[0], 0x53);
  assert_int_equal(reassembled[1], 0x82);
  assert_int_equal(reassembled[2], (CERT_LEN >> 8) & 0xFF);
  assert_int_equal(reassembled[3], CERT_LEN & 0xFF);
  assert_memory_equal(reassembled + 4, cert, CERT_LEN);
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
  lfs_filebd_create(&cfg, "lfs-root", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  piv_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_regression_fuzz),
      cmocka_unit_test(test_delete_certificate_object),
      cmocka_unit_test(test_piv_host_managed_admin_data_objects),
      cmocka_unit_test(test_piv_pin_does_not_satisfy_admin),
      cmocka_unit_test(test_piv_retired_cert_lazy_storage),
      cmocka_unit_test(test_piv_metadata_bounded_do_storage),
      cmocka_unit_test(test_piv_get_metadata_extended_algo_ids),
      cmocka_unit_test(test_piv_delete_key_extension),
      cmocka_unit_test(test_piv_dynamic_retired_key_slots),
      cmocka_unit_test(test_piv_reset_preserves_platform_algorithm_extension),
      cmocka_unit_test(test_piv_algorithm_extension_read_without_admin),
      cmocka_unit_test(test_piv_algorithm_extension_read_after_write),
      cmocka_unit_test(test_ed25519_general_authenticate_long_message),
      cmocka_unit_test(test_secp521r1_generate_and_authenticate),
      cmocka_unit_test(test_secp521r1_custom_algorithm_id),
      cmocka_unit_test(test_set_pin_retries),
      cmocka_unit_test(test_set_pin_retries_failure_invalidates_auth),
      cmocka_unit_test(test_piv_cert_chained_read),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
