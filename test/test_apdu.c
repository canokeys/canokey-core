// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <applets.h>
#include <applet-scratch.h>
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <ccid.h>
#include <ctap.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <pke.h>
#include <string.h>

#define CTAP_LARGE_BLOBS 0x0C
#define CTAP_CONFIG 0x0D
#define CTAP2_ERR_PIN_POLICY_VIOLATION 0x37
#define LB_FILE "ctap_lb"

static const void *find_bytes(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
  const uint8_t *h = haystack;
  const uint8_t *n = needle;

  if (needle_len == 0) return haystack;
  if (haystack_len < needle_len) return NULL;
  for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
    if (memcmp(h + i, n, needle_len) == 0) return h + i;
  }
  return NULL;
}

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

static void test_ccid_power_on_does_not_steal_ctaphid_session(void **state) {
  (void)state;

  static const uint8_t power_on[] = {
      PC_TO_RDR_ICCPOWERON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  };
  static const uint8_t power_off[] = {
      PC_TO_RDR_ICCPOWEROFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  };

  init_apdu_buffer();
  device_init();
  CCID_Init();

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);
  assert_int_equal(acquire_apdu_buffer(BUFFER_OWNER_CTAPHID), 0);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_on, sizeof(power_on)), 0);
  CCID_Loop();

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_off, sizeof(power_off)), 0);
  CCID_Loop();

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);
  assert_int_equal(release_apdu_buffer(BUFFER_OWNER_CTAPHID), 0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
}

static void test_ccid_power_on_preempts_idle_webusb_session(void **state) {
  (void)state;

  static const uint8_t power_on[] = {
      PC_TO_RDR_ICCPOWERON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  };

  init_apdu_buffer();
  device_init();
  CCID_Init();

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_WEBUSB), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_WEBUSB);

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

static void test_ctap_poweroff_keeps_credential_management_state(void **state) {
  (void)state;

  init_apdu_buffer();
  device_init();
  applets_install();

  ctap_test_seed_credential_management_state();
  ctap_poweroff();

  assert_true(ctap_test_credential_management_state_active());
}

static void test_ctap_deselect_clears_credential_management_state(void **state) {
  (void)state;

  init_apdu_buffer();
  device_init();
  applets_install();

  ctap_test_seed_credential_management_state();
  ctap_deselect();

  assert_false(ctap_test_credential_management_state_active());
}

static void test_ctap_hid_get_info_stream_source(void **state) {
  (void)state;

  uint8_t req[] = {0x04};
  uint8_t scratch[64] = {0};
  uint8_t chunk[APPLET_SHARED_BUFFER_LENGTH] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len > 1);
  assert_true(source.total_len <= sizeof(chunk));
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(written, source.total_len);
  assert_int_equal(chunk[0], 0x00);
  assert_non_null(find_bytes(chunk, written, "FIDO_2_3", sizeof("FIDO_2_3") - 1));
  assert_non_null(find_bytes(chunk, written, "authnrCfg", sizeof("authnrCfg") - 1));
  assert_non_null(find_bytes(chunk, written, "minPinLength", sizeof("minPinLength") - 1));
}

static void test_ctap_config_toggle_always_uv_without_pin(void **state) {
  (void)state;

  uint8_t config_req[] = {CTAP_CONFIG, 0xA1, 0x01, 0x02};
  uint8_t get_info_req[] = {0x04};
  uint8_t resp[64] = {0};
  size_t resp_len = sizeof(resp);
  uint8_t scratch[64] = {0};
  uint8_t chunk[APPLET_SHARED_BUFFER_LENGTH] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(ctap_process_cbor_with_src(config_req, sizeof(config_req), resp, &resp_len, CTAP_SRC_HID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x00);

  assert_int_equal(ctap_process_cbor_stream_with_src(get_info_req, sizeof(get_info_req), scratch, sizeof(scratch),
                                                     &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len <= sizeof(chunk));
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(written, source.total_len);
  assert_null(find_bytes(chunk, written, "U2F_V2", sizeof("U2F_V2") - 1));

  resp_len = sizeof(resp);
  assert_int_equal(ctap_process_cbor_with_src(config_req, sizeof(config_req), resp, &resp_len, CTAP_SRC_HID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x00);
}

static void test_ctap_config_pin_complexity_policy_persists_and_enforces(void **state) {
  (void)state;

  uint8_t config_req_true[] = {CTAP_CONFIG, 0xA2, 0x01, 0x03, 0x02, 0xA1, 0x04, 0xF5};
  uint8_t config_req_false[] = {CTAP_CONFIG, 0xA2, 0x01, 0x03, 0x02, 0xA1, 0x04, 0xF4};
  uint8_t get_info_req[] = {0x04};
  uint8_t resp[64] = {0};
  size_t resp_len = sizeof(resp);
  uint8_t scratch[64] = {0};
  uint8_t chunk[APPLET_SHARED_BUFFER_LENGTH] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;
  uint8_t code_points = 0;
  const uint8_t pin_complexity_false[] = {0x18, 0x1B, 0xF4};
  const uint8_t pin_complexity_true[] = {0x18, 0x1B, 0xF5};

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(ctap_test_validate_new_pin((const uint8_t *)"1234", 4, &code_points), 0);
  assert_int_equal(code_points, 4);

  assert_int_equal(ctap_process_cbor_stream_with_src(get_info_req, sizeof(get_info_req), scratch, sizeof(scratch),
                                                     &source, CTAP_SRC_HID),
                   1);
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(chunk[0], 0x00);
  assert_non_null(find_bytes(chunk + 1, written - 1, pin_complexity_false, sizeof(pin_complexity_false)));

  assert_int_equal(ctap_process_cbor_with_src(config_req_true, sizeof(config_req_true), resp, &resp_len, CTAP_SRC_HID),
                   0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x00);

  memset(&source, 0, sizeof(source));
  written = 0;
  assert_int_equal(ctap_process_cbor_stream_with_src(get_info_req, sizeof(get_info_req), scratch, sizeof(scratch),
                                                     &source, CTAP_SRC_HID),
                   1);
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(chunk[0], 0x00);
  assert_non_null(find_bytes(chunk + 1, written - 1, pin_complexity_true, sizeof(pin_complexity_true)));

  assert_int_equal(ctap_test_validate_new_pin((const uint8_t *)"1234", 4, &code_points),
                   CTAP2_ERR_PIN_POLICY_VIOLATION);
  assert_int_equal(ctap_test_validate_new_pin((const uint8_t *)"123a", 4, &code_points), 0);

  resp_len = sizeof(resp);
  assert_int_equal(ctap_process_cbor_with_src(config_req_false, sizeof(config_req_false), resp, &resp_len, CTAP_SRC_HID),
                   0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x00);
  assert_int_equal(ctap_test_validate_new_pin((const uint8_t *)"1234", 4, &code_points),
                   CTAP2_ERR_PIN_POLICY_VIOLATION);
}

static void test_ctap_hid_make_credential_accepts_p9_pub_key_param_order(void **state) {
  (void)state;

  static uint8_t req[] = {
      0x01, 0xA5, 0x01, 0x58, 0x20, 0xA5, 0x14, 0x7D, 0x80, 0x4F, 0xFC, 0x8B, 0x7E, 0xAD, 0x9F, 0x64, 0x7A, 0x9C, 0x8B,
      0x30, 0x29, 0xCB, 0x37, 0xAE, 0x35, 0xB7, 0x2A, 0xB1, 0xD5, 0xEA, 0x58, 0x1A, 0xB7, 0x75, 0x47, 0xD6, 0x1F, 0x02,
      0xA2, 0x62, 0x69, 0x64, 0x6F, 0x68, 0x61, 0x70, 0x6C, 0x65, 0x73, 0x73, 0x67, 0x75, 0x69, 0x64, 0x65, 0x2E, 0x72,
      0x65, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x78, 0x29, 0x54, 0x68, 0x65, 0x20, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
      0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x66,
      0x61, 0x6B, 0x65, 0x20, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x21, 0x03, 0xA3, 0x62, 0x69, 0x64, 0x58, 0x20, 0x9B,
      0xD3, 0xD8, 0xBA, 0x12, 0xC6, 0xA3, 0x05, 0xBB, 0x96, 0xB2, 0x2F, 0x8A, 0xE5, 0xEE, 0xEF, 0x34, 0xA3, 0x19, 0x12,
      0x29, 0x16, 0xD0, 0x6A, 0xBA, 0x49, 0x86, 0x08, 0x16, 0xBF, 0x9B, 0xC3, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x78, 0x1D,
      0x72, 0x6F, 0x73, 0x61, 0x6C, 0x69, 0x61, 0x6A, 0x61, 0x72, 0x72, 0x65, 0x74, 0x40, 0x6E, 0x6F, 0x69, 0x73, 0x65,
      0x6C, 0x65, 0x73, 0x73, 0x66, 0x69, 0x67, 0x2E, 0x63, 0x76, 0x6B, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x4E,
      0x61, 0x6D, 0x65, 0x6E, 0x52, 0x6F, 0x73, 0x61, 0x6C, 0x69, 0x61, 0x20, 0x4A, 0x61, 0x72, 0x72, 0x65, 0x74, 0x04,
      0x82, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
      0x2D, 0x6B, 0x65, 0x79, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x27, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62,
      0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x07, 0xA0,
  };
  uint8_t scratch[64] = {0};
  uint8_t resp[8] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  applets_install();

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len > 0);
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, resp, MIN(source.total_len, sizeof(resp)), &written), 0);
  assert_true(written > 0);
  assert_int_not_equal(resp[0], 0x11);
  if (source.close) source.close(source.ctx);
}

static void test_ctap_hid_large_cbor_response_keeps_payload(void **state) {
  (void)state;

  static uint8_t req[] = {
      CTAP_LARGE_BLOBS, 0xA2, 0x01, 0x19, 0x01, 0x2C, 0x03, 0x00,
  };
  uint8_t blob[300];
  uint8_t scratch[64] = {0};
  uint8_t chunk[16] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  applets_install();

  for (size_t i = 0; i < sizeof(blob); ++i) {
    blob[i] = (uint8_t)i;
  }
  assert_int_equal(write_file(LB_FILE, blob, 0, sizeof(blob), 1), 0);

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_int_equal(source.total_len, 1 + 1 + 1 + 3 + sizeof(blob));
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, chunk, sizeof(chunk), &written), 0);
  assert_int_equal(written, sizeof(chunk));
  assert_int_equal(chunk[0], 0x00);
  assert_int_equal(chunk[1], 0xA1);
  assert_int_equal(chunk[2], 0x01);
  assert_int_equal(chunk[3], 0x59);
  assert_int_equal(chunk[4], 0x01);
  assert_int_equal(chunk[5], 0x2C);
  assert_int_equal(chunk[6], 0x00);
  assert_int_equal(chunk[7], 0x01);
  if (source.close) source.close(source.ctx);
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

// ---------------------------------------------------------------------------
// Streaming response source coverage
//
// `apdu_response_source_set` + `apdu_output` are the streaming primitive
// used by PIV / OpenPGP / NFC FIDO to emit responses larger than the APDU
// buffer. The tests below exercise:
//   - the multi-chunk read loop driven by GET RESPONSE
//   - the tail-restore branch that protects bytes the caller will overwrite
//     with the SW trailer when the source is aliased on shared_io_buffer
//   - the read-failure error path (sets sh->sw to SW_UNABLE_TO_PROCESS)
//   - the close callback bookkeeping
//
// Each callback uses static state because the response source API stores raw
// pointers (no per-source allocation) and we want to verify ordering.

typedef struct {
  const uint8_t *data;
  size_t total;
  size_t reads;
  size_t closes;
  int read_should_fail;
} streaming_source_ctx;

static streaming_source_ctx stream_ctx;

static int streaming_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  streaming_source_ctx *s = (streaming_source_ctx *)ctx;
  s->reads++;
  if (s->read_should_fail) return -1;
  if (offset > s->total || len > s->total - offset) return -1;
  memcpy(buf, s->data + offset, len);
  return len;
}

static void streaming_source_close(void *ctx) {
  streaming_source_ctx *s = (streaming_source_ctx *)ctx;
  s->closes++;
}

static void test_response_source_multi_chunk_get_response(void **state) {
  (void)state;
  init_apdu_buffer();

  // 600 bytes is enough to require three GET RESPONSE rounds at the 250-byte
  // streaming chunk size (250 + 250 + 100).
  static uint8_t payload[600];
  for (size_t i = 0; i < sizeof(payload); ++i)
    payload[i] = (uint8_t)(i * 7 + 1);

  stream_ctx = (streaming_source_ctx){.data = payload, .total = sizeof(payload)};
  apdu_response_source_set((uint32_t)sizeof(payload), SW_NO_ERROR, streaming_source_read, streaming_source_close,
                           &stream_ctx);
  assert_int_equal(apdu_response_source_active(), 1);

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  // Round 1: 250 bytes, 0x61FF (more than 0xFF remaining).
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 250);
  assert_int_equal(rapdu.sw, 0x61FF);
  assert_memory_equal(rapdu.data, payload, 250);

  // Round 2: another 250 bytes, still 0x61FF (100 remaining).
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 250);
  assert_int_equal(rapdu.sw, 0x6164);
  assert_memory_equal(rapdu.data, payload + 250, 250);

  // Round 3: final 100 bytes + 0x9000.
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 100);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_memory_equal(rapdu.data, payload + 500, 100);

  // Stream is finalized; close callback must have fired exactly once.
  assert_int_equal(apdu_response_source_active(), 0);
  assert_int_equal(stream_ctx.closes, 1);
  assert_int_equal(stream_ctx.reads, 3);

  // A trailing GET RESPONSE without a pending stream is rejected.
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_COMMAND_NOT_ALLOWED);
}

// Source that reads directly from shared_io_buffer, exercising the case where
// the source data IS the response buffer (e.g. PIV / OpenPGP staging the
// payload in shared_io_buffer before calling apdu_response_source_set with
// ctx == shared_io_buffer-relative pointer). The interesting bug this guards
// against: after the first chunk, the transport stamps the SW trailer at
// sh->data + sh->len, which lands inside the source's still-pending data;
// apdu_output must save and restore those bytes around the SW stamp so the
// next chunk's read gets the original payload.
static int shared_buffer_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  (void)ctx;
  // The source data lives in shared_io_buffer at the "source view" offset
  // we set up before kicking the stream. memmove handles the buffer overlap
  // when buf == shared_io_buffer + 0 and the source data starts at the same
  // address (first chunk is a no-op copy; later chunks read from forward
  // offsets and write back near the start).
  memmove(buf, shared_io_buffer + offset, len);
  return len;
}

static void test_response_source_tail_restore_on_shared_buffer(void **state) {
  (void)state;
  init_apdu_buffer();

  // Stage 260 bytes of payload directly into shared_io_buffer. The source
  // reads from shared_io_buffer and writes back to it.
  for (size_t i = 0; i < 260; ++i)
    shared_io_buffer[i] = (uint8_t)(0x40 + (i & 0x3F));
  const uint8_t expected_byte250 = shared_io_buffer[250];
  const uint8_t expected_byte251 = shared_io_buffer[251];
  assert_int_not_equal(expected_byte250, 0x61);
  assert_int_not_equal(expected_byte251, 0x0A);

  stream_ctx = (streaming_source_ctx){.data = NULL, .total = 260};
  apdu_response_source_set(260, SW_NO_ERROR, shared_buffer_source_read, streaming_source_close, &stream_ctx);

  CAPDU capdu = {.data = shared_io_buffer};
  RAPDU rapdu = {.data = shared_io_buffer};
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 250);
  assert_int_equal(rapdu.sw, 0x610A);
  // First chunk content: payload[0..249] which still equals the original
  // staging bytes since memmove covers same-source/dest.
  for (size_t i = 0; i < 250; ++i)
    assert_int_equal(rapdu.data[i], (uint8_t)(0x40 + (i & 0x3F)));

  // Simulate the transport stamping the 2-byte SW trailer right after the
  // chunk data. This corrupts shared_io_buffer[250..251], which is what the
  // source would otherwise return on the next read.
  shared_io_buffer[250] = 0x61;
  shared_io_buffer[251] = 0x0A;

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 10);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  // The tail-restore branch must have written the saved bytes back to
  // shared_io_buffer[250..251] before the source read; otherwise the first
  // two output bytes would be 0x61 0x0A.
  assert_int_equal(rapdu.data[0], expected_byte250);
  assert_int_equal(rapdu.data[1], expected_byte251);
  assert_int_equal(stream_ctx.closes, 1);
}

static void test_response_source_read_failure_clears_state(void **state) {
  (void)state;
  init_apdu_buffer();

  static uint8_t payload[300];
  memset(payload, 0xAA, sizeof(payload));
  stream_ctx = (streaming_source_ctx){.data = payload, .total = sizeof(payload), .read_should_fail = 1};
  apdu_response_source_set((uint32_t)sizeof(payload), SW_NO_ERROR, streaming_source_read, streaming_source_close,
                           &stream_ctx);

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_UNABLE_TO_PROCESS);
  assert_int_equal(apdu_response_source_active(), 0);
  // close should still fire so applets release their backing storage.
  assert_int_equal(stream_ctx.closes, 1);
}

// apdu_output non-source path: when ex->rapdu.data aliases sh->data (the
// transport stages and emits from the same shared_io_buffer), the SW trailer
// the caller stamps after each chunk corrupts bytes that later chunks still
// need. The tail-save branch captures those bytes on the first call and
// replays them on subsequent calls.
//
// shared_io_buffer is APDU_COMMAND_BUFFER_SIZE bytes (288 by default), so
// a 280-byte response chunked at 256 bytes lets us exercise the path
// without overflowing the staging buffer.
static void test_apdu_output_chaining_aliased_buffer(void **state) {
  (void)state;
  init_apdu_buffer();

  enum { RESP_LEN = 280 };
  uint8_t expected[RESP_LEN];
  for (size_t i = 0; i < RESP_LEN; ++i)
    expected[i] = (uint8_t)(0x80 + (i & 0x3F));

  memcpy(shared_io_buffer, expected, RESP_LEN);
  RAPDU_CHAINING rc = {
      .rapdu.data = shared_io_buffer,
      .rapdu.len = RESP_LEN,
      .rapdu.sw = SW_NO_ERROR,
      .sent = 0,
  };
  RAPDU sh = {.data = shared_io_buffer, .len = APDU_BUFFER_SIZE};

  // First chunk: 256 bytes, 0x6118 because 24 bytes still pending.
  assert_int_equal(apdu_output(&rc, &sh), 0);
  assert_int_equal(sh.len, 256);
  assert_int_equal(sh.sw, 0x6118);
  assert_memory_equal(sh.data, expected, 256);

  // Simulate the transport stamping the SW trailer right after the chunk
  // data; this corrupts shared_io_buffer[256..257], which originally held
  // expected[256..257]. Tail-save must have copied those bytes out before
  // we did this corruption.
  shared_io_buffer[256] = 0x61;
  shared_io_buffer[257] = 0x18;

  // Second chunk: remaining 24 bytes + 0x9000. Without tail-save the first
  // two output bytes would be 0x61 0x18 (the SW), not the original payload.
  sh.len = APDU_BUFFER_SIZE;
  assert_int_equal(apdu_output(&rc, &sh), 0);
  assert_int_equal(sh.len, 24);
  assert_int_equal(sh.sw, SW_NO_ERROR);
  assert_memory_equal(sh.data, expected + 256, 24);
}

// fido_apdu_input rejects chains whose accumulated length would exceed the
// PKE staging buffer. Send maximum-sized chained APDUs until APDU_CHAINING_OVERFLOW
// fires, which process_apdu maps to SW_WRONG_LENGTH and which must also reset
// the chain so subsequent commands can run.
static void test_fido_apdu_chain_overflow_returns_wrong_length(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };

  uint8_t c_buf[512], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  applets_install();
  set_nfc_state(0);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // Build a maximally-sized chained APDU (CLA=0x90, INS=0x10, Lc=0xFF=255).
  uint8_t big[5 + 255];
  big[0] = 0x90;
  big[1] = 0x10;
  big[2] = 0x00;
  big[3] = 0x00;
  big[4] = 0xFF;
  memset(big + 5, 0xAB, 255);

  size_t total = 0;
  for (int i = 0; i < 32; ++i) {
    assert_int_equal(build_capdu(&capdu, big, sizeof(big)), 0);
    process_apdu(&capdu, &rapdu);
    if (rapdu.sw == SW_WRONG_LENGTH) {
      // Overflow correctly signaled. fido_capdu_reset was called on this
      // path, releasing PKE; we should now be able to acquire it elsewhere.
      assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
      assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
      return;
    }
    assert_int_equal(rapdu.sw, SW_NO_ERROR);
    total += 255;
  }
  fail_msg("Expected SW_WRONG_LENGTH after %zu accumulated bytes", total);
}

static void test_response_source_clear_calls_close(void **state) {
  (void)state;
  init_apdu_buffer();

  static const uint8_t payload[16] = {0};
  stream_ctx = (streaming_source_ctx){.data = payload, .total = sizeof(payload)};
  apdu_response_source_set((uint32_t)sizeof(payload), SW_NO_ERROR, streaming_source_read, streaming_source_close,
                           &stream_ctx);
  assert_int_equal(apdu_response_source_active(), 1);
  assert_int_equal(stream_ctx.closes, 0);

  apdu_response_source_clear();
  assert_int_equal(apdu_response_source_active(), 0);
  assert_int_equal(stream_ctx.closes, 1);

  // Clearing again is a no-op; close must not fire twice.
  apdu_response_source_clear();
  assert_int_equal(stream_ctx.closes, 1);
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
      cmocka_unit_test(test_ccid_power_on_does_not_steal_ctaphid_session),
      cmocka_unit_test(test_ccid_power_on_preempts_idle_webusb_session),
      cmocka_unit_test(test_streaming_message_preserves_original_le_for_handler),
      cmocka_unit_test(test_pke_buffer_fallback_for_ctap),
      cmocka_unit_test(test_fido_chained_make_credential_nfc),
      cmocka_unit_test(test_fido_ctap1_register_nfc),
      cmocka_unit_test(test_fido_cbor_after_reset_without_select),
      cmocka_unit_test(test_fido_chained_cbor_after_reset_without_select),
      cmocka_unit_test(test_ctap_deselect_clears_get_next_assertion_state),
      cmocka_unit_test(test_ctap_poweroff_keeps_credential_management_state),
      cmocka_unit_test(test_ctap_deselect_clears_credential_management_state),
      cmocka_unit_test(test_ctap_hid_get_info_stream_source),
      cmocka_unit_test(test_ctap_config_toggle_always_uv_without_pin),
      cmocka_unit_test(test_ctap_config_pin_complexity_policy_persists_and_enforces),
      cmocka_unit_test(test_ctap_hid_make_credential_accepts_p9_pub_key_param_order),
      cmocka_unit_test(test_ctap_hid_large_cbor_response_keeps_payload),
      cmocka_unit_test(test_get_response_after_reset_without_pending_response),
      cmocka_unit_test(test_response_source_multi_chunk_get_response),
      cmocka_unit_test(test_response_source_tail_restore_on_shared_buffer),
      cmocka_unit_test(test_response_source_read_failure_clears_state),
      cmocka_unit_test(test_apdu_output_chaining_aliased_buffer),
      cmocka_unit_test(test_fido_apdu_chain_overflow_returns_wrong_length),
      cmocka_unit_test(test_response_source_clear_calls_close),
      cmocka_unit_test(test_fido_magic_reboot_after_reset_without_select),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
