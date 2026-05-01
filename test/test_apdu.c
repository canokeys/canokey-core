// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <applets.h>
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <ccid.h>
#include <ctap.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <pke.h>
#include <string.h>

static void test_input_chaining(void **state) {
  (void)state;

  uint8_t c_buf[1024], total_buf[2048];
  uint8_t data[] = {0x74, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = c_buf};
  CAPDU_CHAINING CC = {.capdu.data = total_buf, .in_chaining = 0};

  // test no chaining
  C.cla = 0x80;
  C.ins = 0x00;
  C.p1 = 0x01;
  C.p2 = 0xFF;
  C.lc = sizeof(data);
  memcpy(C.data, data, C.lc);
  int ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);

  // test normal chaining
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 3);

  // test abnormal chaining 1
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.ins = 0x20;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 2);

  // test abnormal chaining 2
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  C.ins = 0x10;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 1);
}

static void test_output_chaining(void **state) {
  (void)state;

  uint8_t r_buf[1024], total_buf[2048];
  RAPDU R = {.data = r_buf, .len = 254};
  RAPDU_CHAINING RC = {.rapdu.data = total_buf, .rapdu.len = 512, .rapdu.sw = 0x9000, .sent = 0};

  int ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 254);
  assert_int_equal(R.sw, 0x61FF);

  ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 254);
  assert_int_equal(R.sw, 0x6104);

  ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 4);
  assert_int_equal(R.sw, 0x9000);
}

static void test_acquire_apdu_interface_releases_session_on_buffer_conflict(void **state) {
  (void)state;

  init_apdu_buffer();
  device_init();

  assert_int_equal(acquire_apdu_buffer(BUFFER_OWNER_CCID), 0);
  assert_int_equal(acquire_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID), -1);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);
  assert_int_equal(release_apdu_buffer(BUFFER_OWNER_CCID), 0);
}

static void test_ccid_power_on_clears_stale_session(void **state) {
  (void)state;

  static const uint8_t power_on[] = {
      PC_TO_RDR_ICCPOWERON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  };

  init_apdu_buffer();
  device_init();
  CCID_Init();

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_on, sizeof(power_on)), 0);
  CCID_Loop();

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);
}

static uint32_t observed_streaming_le;

static int record_streaming_capdu_le(const CAPDU *capdu, RAPDU *rapdu) {
  observed_streaming_le = capdu->le;
  rapdu->len = 0;
  rapdu->sw = SW_NO_ERROR;
  return 0;
}

static void test_streaming_message_preserves_original_le_for_handler(void **state) {
  (void)state;

  static const uint8_t read_binary_extended[] = {
      0x00, 0xB0, 0x00, 0x00, 0x00, 0x04, 0x01,
  };

  uint8_t c_buf[16], r_buf[16];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  RAPDU_CHAINING rapdu_chaining = {.rapdu.data = r_buf};

  observed_streaming_le = 0;

  assert_int_equal(build_capdu(&capdu, read_binary_extended, sizeof(read_binary_extended)), 0);
  assert_int_equal(capdu.le, 0x0401);
  assert_int_equal(
      apdu_process_streaming_message(&rapdu_chaining, &capdu, &rapdu, 0, APDU_BUFFER_SIZE, record_streaming_capdu_le),
      0);
  assert_int_equal(observed_streaming_le, 0x0401);
}

static void test_pke_buffer_fallback_for_ctap(void **state) {
  (void)state;

  assert_true(pke_buffer_size() >= CTAP_MAX_REQUEST_SIZE);
  assert_int_equal(pke_buffer_clear(), 0);

  static const uint8_t payload[] = {
      0x01, 0xA6, 0x01, 0x58, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
  };
  uint8_t out[sizeof(payload)];
  uint8_t zero[sizeof(payload)] = {0};

  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), -1);
  assert_int_equal(pke_buffer_write(0, payload, sizeof(payload)), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_CTAP), 0);

  memset(out, 0, sizeof(out));
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_read(0, out, sizeof(out)), 0);
  assert_memory_equal(out, payload, sizeof(payload));
  assert_int_equal(pke_buffer_clear(), 0);
  memset(out, 0xA5, sizeof(out));
  assert_int_equal(pke_buffer_read(0, out, sizeof(out)), 0);
  assert_memory_equal(out, zero, sizeof(out));
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_CTAP), 0);
}

static void test_fido_chained_make_credential_nfc(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static const uint8_t mc_part1[] = {
      0x90, 0x10, 0x80, 0x00, 0xFA, 0x01, 0xA6, 0x01, 0x58, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
      0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63,
      0x64, 0x65, 0x66, 0x30, 0x02, 0xA2, 0x62, 0x69, 0x64, 0x6B, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x6F,
      0x72, 0x67, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x69, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x52, 0x50, 0x03, 0xA4,
      0x62, 0x69, 0x64, 0x58, 0x20, 0xF2, 0x0F, 0x6B, 0x47, 0xCB, 0x6E, 0xA1, 0x3C, 0x3E, 0xA4, 0x28, 0xE2, 0x4D, 0xF7,
      0x6B, 0x65, 0x8E, 0x8C, 0x7F, 0x3B, 0x39, 0x4E, 0x29, 0x3B, 0x44, 0x7D, 0xA3, 0x79, 0xB5, 0x7B, 0x78, 0x98, 0x64,
      0x69, 0x63, 0x6F, 0x6E, 0x78, 0x1F, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77,
      0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x54, 0x52, 0x2F, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6E, 0x2F, 0x64,
      0x6E, 0x61, 0x6D, 0x65, 0x74, 0x42, 0x72, 0x61, 0x6E, 0x61, 0x20, 0x44, 0x61, 0x63, 0x79, 0x20, 0x52, 0x6F, 0x73,
      0x65, 0x6D, 0x61, 0x72, 0x69, 0x61, 0x6B, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x4E, 0x61, 0x6D, 0x65, 0x78,
      0x1E, 0x44, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x20, 0x42, 0x72, 0x61, 0x6E, 0x61, 0x20, 0x44, 0x61,
      0x63, 0x79, 0x20, 0x52, 0x6F, 0x73, 0x65, 0x6D, 0x61, 0x72, 0x69, 0x61, 0x04, 0x81, 0xA2, 0x63, 0x61, 0x6C, 0x67,
      0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x06, 0xA1,
      0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65,
  };
  static const uint8_t mc_part2[] = {
      0x80, 0x10, 0x80, 0x00, 0x0B, 0x63, 0x72, 0x65, 0x74, 0xF5, 0x07, 0xA1, 0x62, 0x72, 0x6B, 0xF5, 0x00,
  };

  uint8_t c_buf[512], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  set_nfc_state(1);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, mc_part1, sizeof(mc_part1)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 0);

  assert_int_equal(build_capdu(&capdu, mc_part2, sizeof(mc_part2)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, 0x9100);
  assert_int_equal(rapdu.len, 1);
  assert_int_equal(rapdu.data[0], 0x02);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
}

static void test_fido_ctap1_register_nfc(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static const uint8_t register_apdu[] = {
      0x00, 0x01, 0x00, 0x00, 0x40, 0xE0, 0x78, 0xA7, 0xB2, 0xCA, 0xC4, 0x1D, 0xDC, 0x13, 0x14, 0x72, 0x90, 0x76,
      0xB6, 0xDF, 0xC1, 0xCD, 0x53, 0x45, 0x50, 0xFE, 0x0A, 0x78, 0xB8, 0x28, 0x5D, 0x8F, 0x06, 0xEC, 0x37, 0xC9,
      0xBD, 0xBF, 0xAB, 0xC3, 0x74, 0x32, 0x95, 0x8B, 0x06, 0x33, 0x60, 0xD3, 0xAD, 0x64, 0x61, 0xC9, 0xC4, 0x73,
      0x5A, 0xE7, 0xF8, 0xED, 0xD4, 0x65, 0x92, 0xA5, 0xE0, 0xF0, 0x14, 0x52, 0xB2, 0xE4, 0xB5, 0x00,
  };

  uint8_t c_buf[512], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  set_nfc_state(1);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, register_apdu, sizeof(register_apdu)), 0);
  process_apdu(&capdu, &rapdu);
  assert_true(rapdu.len > 0);
  assert_int_equal(rapdu.data[0], 0x05);

  uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
  size_t total = rapdu.len;
  while (rapdu.sw != SW_NO_ERROR) {
    assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
    process_apdu(&capdu, &rapdu);
    total += rapdu.len;
  }

  assert_true(total >= rapdu.len);
}

static void test_fido_cbor_after_reset_without_select(void **state) {
  (void)state;

  static const uint8_t get_info_apdu[] = {
      0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00,
  };

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(build_capdu(&capdu, get_info_apdu, sizeof(get_info_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_not_equal(rapdu.sw, SW_FILE_NOT_FOUND);
  assert_true(rapdu.sw == SW_NO_ERROR || (rapdu.sw & 0xFF00) == 0x6100);
  assert_true(rapdu.len > 0);
  assert_int_equal(rapdu.data[0], 0x00);
}

static void test_fido_chained_cbor_after_reset_without_select(void **state) {
  (void)state;

  static const uint8_t get_info_apdu[] = {
      0x90, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00,
  };

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(build_capdu(&capdu, get_info_apdu, sizeof(get_info_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_not_equal(rapdu.sw, SW_FILE_NOT_FOUND);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 0);
}

static void test_ctap_deselect_clears_get_next_assertion_state(void **state) {
  (void)state;

  uint8_t req[] = {0x08};
  uint8_t resp[16] = {0};
  size_t resp_len = sizeof(resp);

  init_apdu_buffer();
  device_init();
  applets_install();

  ctap_test_seed_get_next_assertion_state();
  ctap_deselect();

  assert_int_equal(ctap_process_cbor_with_src(req, sizeof(req), resp, &resp_len, CTAP_SRC_CCID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x30);
}

static void test_ctap_hid_get_info_stream_source(void **state) {
  (void)state;

  uint8_t req[] = {0x04};
  uint8_t scratch[64] = {0};
  uint8_t chunk[320] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len > 1);
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(written, source.total_len);
  assert_int_equal(chunk[0], 0x00);
}

static void test_get_response_after_reset_without_pending_response(void **state) {
  (void)state;

  static const uint8_t get_response[] = {
      0x00, 0xC0, 0x00, 0x00, 0x2D,
  };

  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_COMMAND_NOT_ALLOWED);
}

static void test_fido_magic_reboot_after_reset_without_select(void **state) {
  (void)state;

  static const uint8_t magic_reboot_apdu[] = {
      0x00, 0xEE, 0x00, 0x00, 0x04, 0x12, 0x56, 0xAB, 0xF0,
  };

  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(build_capdu(&capdu, magic_reboot_apdu, sizeof(magic_reboot_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
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
  init_apdu_buffer();
  device_init();
  applets_install();

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_input_chaining),
      cmocka_unit_test(test_output_chaining),
      cmocka_unit_test(test_acquire_apdu_interface_releases_session_on_buffer_conflict),
      cmocka_unit_test(test_ccid_power_on_clears_stale_session),
      cmocka_unit_test(test_streaming_message_preserves_original_le_for_handler),
      cmocka_unit_test(test_pke_buffer_fallback_for_ctap),
      cmocka_unit_test(test_fido_chained_make_credential_nfc),
      cmocka_unit_test(test_fido_ctap1_register_nfc),
      cmocka_unit_test(test_fido_cbor_after_reset_without_select),
      cmocka_unit_test(test_fido_chained_cbor_after_reset_without_select),
      cmocka_unit_test(test_ctap_deselect_clears_get_next_assertion_state),
      cmocka_unit_test(test_ctap_hid_get_info_stream_source),
      cmocka_unit_test(test_get_response_after_reset_without_pending_response),
      cmocka_unit_test(test_fido_magic_reboot_after_reset_without_select),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
