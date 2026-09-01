// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <bd/lfs_filebd.h>
#include <common.h>
#include <ctaphid.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <platform-config.h>
#include <pin.h>
#include <stdbool.h>
#include <string.h>

static uint32_t fake_tick;
static uint32_t tick_step;
static int led_on_calls;
static int led_off_calls;
static int applets_poweroff_calls;
static int apdu_response_source_clear_calls;
static int ccid_loop_calls;
static int ctaphid_loop_calls;
static int ctaphid_loop_wait_calls;
static int webusb_loop_calls;
static int kbdhid_loop_calls;
static int keepalive_processing_calls;
static int keepalive_upneeded_calls;
static bool apdu_session_preemptable;
static uint8_t ctaphid_wait_result;
static bool led_normally_on;
static bool inject_write_error;
static char inject_write_error_path[64];
static uint8_t test_config_page[PLATFORM_CONFIG_PAGE_SIZE];

typedef enum {
  AUTO_TOUCH_NONE = 0,
  AUTO_TOUCH_WHEN_BLINKING = 1,
} auto_touch_mode_t;

static auto_touch_mode_t auto_touch_mode;

static void reset_test_state(void) {
  fake_tick = 0;
  tick_step = 0;
  led_on_calls = 0;
  led_off_calls = 0;
  applets_poweroff_calls = 0;
  apdu_response_source_clear_calls = 0;
  ccid_loop_calls = 0;
  ctaphid_loop_calls = 0;
  ctaphid_loop_wait_calls = 0;
  webusb_loop_calls = 0;
  kbdhid_loop_calls = 0;
  keepalive_processing_calls = 0;
  keepalive_upneeded_calls = 0;
  apdu_session_preemptable = false;
  ctaphid_wait_result = LOOP_SUCCESS;
  led_normally_on = false;
  inject_write_error = false;
  inject_write_error_path[0] = 0;
  memset(test_config_page, 0xFF, sizeof(test_config_page));
  auto_touch_mode = AUTO_TOUCH_NONE;
}

static void arm_write_error(const char *path) {
  inject_write_error = true;
  strncpy(inject_write_error_path, path, sizeof(inject_write_error_path) - 1);
  inject_write_error_path[sizeof(inject_write_error_path) - 1] = 0;
}

void device_delay(int ms) { UNUSED(ms); }

uint32_t device_get_tick(void) {
  uint32_t current = fake_tick;
  fake_tick += tick_step;
  return current;
}

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking) {
  UNUSED(blocking);
  if (*lock) return -1;
  *lock = 1;
  return 0;
}

void device_spinlock_unlock(volatile uint32_t *lock) { *lock = 0; }

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update) {
  if (*var != expect) return -1;
  *var = update;
  return 0;
}

void led_on(void) { led_on_calls++; }

void led_off(void) { led_off_calls++; }

void device_set_timeout(void (*callback)(void), uint16_t timeout) {
  UNUSED(callback);
  UNUSED(timeout);
}

void fm_csn_low(void) {}

void fm_csn_high(void) {}

void spi_transmit(const uint8_t *buf, uint8_t len) {
  UNUSED(buf);
  UNUSED(len);
}

void spi_receive(uint8_t *buf, uint8_t len) {
  if (len > 0) memset(buf, 0, len);
}

int testmode_emulate_user_presence(void) {
  if (auto_touch_mode == AUTO_TOUCH_WHEN_BLINKING && device_is_blinking()) {
    set_touch_result(TOUCH_SHORT);
  }
  return 0;
}

int testmode_get_is_nfc_mode(void) { return 0; }

void testmode_set_initial_ticks(uint32_t ticks) { fake_tick = ticks; }

void testmode_inject_error(uint8_t p1, uint8_t p2, uint16_t len, const uint8_t *data) {
  UNUSED(p1);
  UNUSED(p2);
  UNUSED(len);
  UNUSED(data);
}

bool testmode_err_triggered(const char *filename, bool file_wr) {
  UNUSED(file_wr);
  if (!inject_write_error) return false;
  if (strcmp(filename, inject_write_error_path) != 0) return false;
  inject_write_error = false;
  inject_write_error_path[0] = 0;
  return true;
}

void applets_poweroff(void) { applets_poweroff_calls++; }

void apdu_response_source_clear(void) { apdu_response_source_clear_calls++; }

int apdu_session_can_preempt(void) { return apdu_session_preemptable; }

void apdu_fido_chain_reset(void) {}

void CCID_Loop(void) { ccid_loop_calls++; }

uint8_t CTAPHID_Loop(uint8_t wait_for_user) {
  ctaphid_loop_calls++;
  if (wait_for_user) {
    ctaphid_loop_wait_calls++;
    return ctaphid_wait_result;
  }
  return LOOP_SUCCESS;
}

void CTAPHID_SendKeepAlive(uint8_t status) {
  if (status == KEEPALIVE_STATUS_PROCESSING) {
    keepalive_processing_calls++;
  } else if (status == KEEPALIVE_STATUS_UPNEEDED) {
    keepalive_upneeded_calls++;
  }
}

void WebUSB_Loop(void) { webusb_loop_calls++; }

uint8_t KBDHID_Loop(void) {
  kbdhid_loop_calls++;
  return 0;
}

int platform_config_page_read(size_t off, void *buf, size_t len) {
  if (buf == NULL || off > sizeof(test_config_page) || len > sizeof(test_config_page) - off) return -1;
  memcpy(buf, test_config_page + off, len);
  return 0;
}

int platform_config_page_write(const void *page, size_t len) {
  if (page == NULL || len != sizeof(test_config_page)) return -1;
  memcpy(test_config_page, page, sizeof(test_config_page));
  return 0;
}

uint8_t device_config_is_led_normally_on(void) { return led_normally_on ? 1 : 0; }

uint8_t device_config_is_pass_enabled(void) { return 1; }

uint8_t device_config_is_openpgp_ccid_enabled(void) { return 1; }

uint8_t device_config_is_openpgp_nfc_enabled(void) { return 1; }

uint8_t device_config_is_piv_ccid_enabled(void) { return 1; }

uint8_t device_config_is_piv_nfc_enabled(void) { return 1; }

uint8_t device_config_is_webauthn_enabled(void) { return 1; }

static void test_tlv_get_length_safe_variants(void **state) {
  (void)state;

  int fail = 0;
  size_t length_size = 0;
  uint8_t one_byte[] = {0x02, 0xAA, 0xBB};
  uint8_t one_byte_truncated[] = {0x02, 0xAA};
  uint8_t two_byte[] = {0x81, 0x03, 0xAA, 0xBB, 0xCC};
  uint8_t three_byte[] = {0x82, 0x01, 0x02};
  uint8_t invalid[] = {0x83, 0x00, 0x00, 0x00};

  assert_int_equal(tlv_get_length_safe(one_byte, 0, &fail, &length_size), 0);
  assert_int_equal(fail, 1);

  fail = 0;
  length_size = 0;
  assert_int_equal(tlv_get_length_safe(one_byte, sizeof(one_byte), &fail, &length_size), 2);
  assert_int_equal(fail, 0);
  assert_int_equal(length_size, 1);

  fail = 0;
  length_size = 0;
  assert_int_equal(tlv_get_length_safe(one_byte_truncated, sizeof(one_byte_truncated), &fail, &length_size), 2);
  assert_int_equal(fail, 1);
  assert_int_equal(length_size, 1);

  fail = 0;
  length_size = 0;
  assert_int_equal(tlv_get_length_safe(two_byte, sizeof(two_byte), &fail, &length_size), 3);
  assert_int_equal(fail, 0);
  assert_int_equal(length_size, 2);

  fail = 0;
  length_size = 0;
  assert_int_equal(tlv_get_length_safe(two_byte, 1, &fail, &length_size), 0);
  assert_int_equal(fail, 1);

  fail = 0;
  length_size = 0;
  assert_int_equal(tlv_get_length_safe(three_byte, sizeof(three_byte), &fail, &length_size), 0x0102);
  assert_int_equal(fail, 1);
  assert_int_equal(length_size, 3);

  fail = 0;
  length_size = 0;
  assert_int_equal(tlv_get_length_safe(invalid, sizeof(invalid), &fail, &length_size), 0);
  assert_int_equal(fail, 1);
}

static void test_fs_roundtrip_and_metadata(void **state) {
  (void)state;

  static const uint8_t initial[] = {'a', 'b', 'c'};
  static const uint8_t suffix[] = {'d', 'e', 'f'};
  static const uint8_t attr[] = {'x', 'y'};
  uint8_t buf[8] = {0};

  assert_int_equal(write_file("fs-basic", initial, 0, sizeof(initial), 1), 0);
  assert_int_equal(read_file("fs-basic", buf, 0, sizeof(initial)), (int)sizeof(initial));
  assert_memory_equal(buf, initial, sizeof(initial));

  assert_int_equal(append_file("fs-basic", suffix, sizeof(suffix)), 0);
  assert_int_equal(get_file_size("fs-basic"), 6);

  memset(buf, 0, sizeof(buf));
  assert_int_equal(read_file("fs-basic", buf, 2, 4), 4);
  assert_memory_equal(buf, "cdef", 4);

  assert_int_equal(write_attr("fs-basic", 7, attr, sizeof(attr)), 0);
  memset(buf, 0, sizeof(buf));
  assert_int_equal(read_attr("fs-basic", 7, buf, sizeof(attr)), (int)sizeof(attr));
  assert_memory_equal(buf, attr, sizeof(attr));

  assert_int_equal(truncate_file("fs-basic", 4), 0);
  assert_int_equal(get_file_size("fs-basic"), 4);

  assert_int_equal(fs_rename("fs-basic", "fs-basic-renamed"), 0);
  memset(buf, 0, sizeof(buf));
  assert_int_equal(read_file("fs-basic-renamed", buf, 0, 4), 4);
  assert_memory_equal(buf, "abcd", 4);

  assert_true(get_fs_size() > 0);
  assert_true(get_fs_usage() >= 0);
  int free_bytes = get_fs_free_bytes();
  assert_true(free_bytes > 0);
  assert_int_equal(fs_has_free_space(1, 0), 1);
  assert_int_equal(fs_has_free_space(1, (lfs_size_t)free_bytes), 0);
  assert_int_equal(fs_has_free_space((lfs_size_t)-1, 0), 0);
}

static void test_fs_error_paths(void **state) {
  (void)state;

  uint8_t buf[4] = {0};

  assert_true(read_file("missing-file", buf, 0, sizeof(buf)) < 0);
  assert_true(get_file_size("missing-file") < 0);

  assert_int_equal(write_file("fs-seek", "abc", 0, 3, 1), 0);
  assert_true(read_file("fs-seek", buf, -1, 1) < 0);
  assert_true(write_file("fs-seek", "z", -1, 1, 0) < 0);

  arm_write_error("fs-write-error");
  assert_int_equal(write_file("fs-write-error", "x", 0, 1, 1), LFS_ERR_IO);
}

static void test_device_blinking_and_led_behaviour(void **state) {
  (void)state;

  reset_test_state();
  device_init();

  assert_false(device_is_blinking());
  assert_int_equal(led_off_calls, 1);

  start_blinking_interval(1, 50);
  assert_true(device_is_blinking());
  assert_int_equal(led_on_calls, 1);

  start_blinking_interval(1, 50);
  assert_int_equal(led_on_calls, 1);
  assert_int_equal(led_off_calls, 1);

  fake_tick = 60;
  device_update_led();
  assert_int_equal(led_off_calls, 2);

  fake_tick = 1100;
  device_update_led();
  assert_false(device_is_blinking());
  assert_int_equal(led_off_calls, 3);

  led_normally_on = true;
  stop_blinking();
  assert_int_equal(led_on_calls, 2);

  start_blinking_interval(0, 25);
  assert_true(device_is_blinking());
}

static void test_device_allow_kbd_touch_rules(void **state) {
  (void)state;

  reset_test_state();
  device_init();

  fake_tick = TOUCH_AFTER_PWRON + TOUCH_EXPIRE_TIME + 10;
  set_touch_result(TOUCH_SHORT);
  assert_true(device_allow_kbd_touch());

  set_touch_result(TOUCH_NO);
  assert_false(device_allow_kbd_touch());

  set_touch_result(TOUCH_SHORT);
  fake_tick = TOUCH_AFTER_PWRON;
  assert_false(device_allow_kbd_touch());

  fake_tick = TOUCH_AFTER_PWRON + TOUCH_EXPIRE_TIME + 20;
  start_blinking_interval(1, 50);
  assert_false(device_allow_kbd_touch());
}

static void test_device_sessions_and_keepalive(void **state) {
  (void)state;

  reset_test_state();
  device_init();

  fake_tick = 100;
  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CCID), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CCID);
  assert_int_equal(send_keepalive_during_processing(WAIT_ENTRY_CCID), 0);
  assert_int_equal(keepalive_processing_calls, 0);

  fake_tick = 2099;
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CCID);

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID), -1);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CCID);

  fake_tick = 2101;
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);
  assert_int_equal(applets_poweroff_calls, 1);
  assert_int_equal(apdu_response_source_clear_calls, 1);

  fake_tick = 300;
  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID), 0);
  assert_int_equal(send_keepalive_during_processing(WAIT_ENTRY_CCID), 0);
  assert_int_equal(keepalive_processing_calls, 1);

  fake_tick = 1000;
  device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
  fake_tick = 2299;
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);

  fake_tick = 2401;
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);

  fake_tick = 2500;
  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CCID), 0);
  apdu_session_preemptable = true;
  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_WEBUSB), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_WEBUSB);

  fake_tick = 500;
  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_WEBUSB), 0);
  assert_int_equal(send_keepalive_during_processing(WAIT_ENTRY_CCID), 0);
  assert_int_equal(keepalive_processing_calls, 1);
  device_applet_session_release(DEVICE_APPLET_SESSION_WEBUSB);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);
}

static void test_wait_for_user_presence_ok(void **state) {
  (void)state;

  reset_test_state();
  device_init();
  set_touch_result(TOUCH_SHORT);

  assert_int_equal(wait_for_user_presence(WAIT_ENTRY_CCID), USER_PRESENCE_OK);
  assert_int_equal(get_touch_result(), TOUCH_NO);
  assert_false(device_is_blinking());
}

static void test_wait_for_user_presence_services_ctaphid_while_ccid_waits(void **state) {
  (void)state;

  reset_test_state();
  device_init();
  auto_touch_mode = AUTO_TOUCH_WHEN_BLINKING;

  assert_int_equal(wait_for_user_presence(WAIT_ENTRY_CCID), USER_PRESENCE_OK);
  assert_true(ctaphid_loop_wait_calls > 0);
  assert_int_equal(get_touch_result(), TOUCH_NO);
  assert_false(device_is_blinking());
}

static void test_wait_for_user_presence_cancel_and_timeout(void **state) {
  (void)state;

  reset_test_state();
  device_init();
  tick_step = 1;
  ctaphid_wait_result = LOOP_CANCEL;

  assert_int_equal(wait_for_user_presence(WAIT_ENTRY_CTAPHID), USER_PRESENCE_CANCEL);
  assert_true(ctaphid_loop_wait_calls > 0);
  assert_false(device_is_blinking());

  reset_test_state();
  device_init();
  tick_step = 5000;

  assert_int_equal(wait_for_user_presence(WAIT_ENTRY_CTAPHID), USER_PRESENCE_TIMEOUT);
  assert_true(ctaphid_loop_wait_calls > 0);
  assert_false(device_is_blinking());
}

static void test_strong_user_presence_test_success_and_failure(void **state) {
  (void)state;

  reset_test_state();
  device_init();
  auto_touch_mode = AUTO_TOUCH_WHEN_BLINKING;
  tick_step = 1000;
  assert_int_equal(strong_user_presence_test(), 0);

  reset_test_state();
  device_init();
  tick_step = 2500;
  assert_int_equal(strong_user_presence_test(), -1);
}

static void test_device_loop_and_nfc_state(void **state) {
  (void)state;

  reset_test_state();
  device_init();
  device_loop();

  assert_int_equal(ccid_loop_calls, 1);
  assert_int_equal(ctaphid_loop_calls, 1);
  assert_int_equal(webusb_loop_calls, 1);
  assert_int_equal(kbdhid_loop_calls, 1);

  set_nfc_state(1);
  assert_int_equal(is_nfc(), 1);
  set_nfc_state(0);
  assert_int_equal(is_nfc(), 0);
}

static void test_pin_lifecycle(void **state) {
  (void)state;

  static pin_t pin = {.min_length = 4, .max_length = 8, .is_validated = 0, .path = "pin-life"};
  uint8_t retries = 0xFF;

  assert_int_equal(pin_create(&pin, "1234", 4, 3), 0);
  assert_int_equal(pin_get_size(&pin), 4);
  assert_int_equal(pin_get_retries(&pin), 3);
  assert_int_equal(pin_get_default_retries(&pin), 3);

  assert_int_equal(pin_verify(&pin, "9999", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 2);
  assert_int_equal(pin.is_validated, 0);
  assert_int_equal(pin_get_retries(&pin), 2);

  assert_int_equal(pin_verify(&pin, "1234", 4, NULL), 0);
  assert_int_equal(pin.is_validated, 1);
  assert_int_equal(pin_get_retries(&pin), 3);

  assert_int_equal(pin_update(&pin, "5678", 4), 0);
  assert_int_equal(pin.is_validated, 0);
  assert_int_equal(pin_verify(&pin, "5678", 4, NULL), 0);
  assert_int_equal(pin.is_validated, 1);

  assert_int_equal(pin_set_retries(&pin, 15), 0);
  assert_int_equal(pin_get_retries(&pin), 15);
  assert_int_equal(pin_get_default_retries(&pin), 15);
  assert_int_equal(pin_get_retry_sw(15), 0x63CF);
  assert_int_equal(pin_get_retry_sw(16), 0x63CF);

  assert_int_equal(pin_clear(&pin), 0);
  assert_int_equal(pin_get_size(&pin), 0);
  assert_int_equal(pin_get_retries(&pin), 0);
  assert_int_equal(pin_get_default_retries(&pin), 0);
}

static void test_pin_error_paths(void **state) {
  (void)state;

  static pin_t pin = {.min_length = 4, .max_length = 8, .is_validated = 0, .path = "pin-err"};
  static pin_t missing_pin = {.min_length = 4, .max_length = 8, .is_validated = 0, .path = "pin-missing"};
  uint8_t retries = 0xFF;

  arm_write_error("pin-err");
  assert_int_equal(pin_create(&pin, "1234", 4, 3), PIN_IO_FAIL);

  assert_int_equal(pin_verify(&missing_pin, "1234", 4, &retries), PIN_IO_FAIL);
  assert_int_equal(pin_get_retries(&missing_pin), PIN_IO_FAIL);
  assert_int_equal(pin_get_default_retries(&missing_pin), PIN_IO_FAIL);
  assert_int_equal(pin_clear(&missing_pin), PIN_IO_FAIL);

  assert_int_equal(pin_create(&pin, "1234", 4, 3), 0);
  assert_int_equal(pin_create(&pin, "1234", 4, 0), PIN_LENGTH_INVALID);
  assert_int_equal(pin_create(&pin, "1234", 4, 16), PIN_LENGTH_INVALID);
  assert_int_equal(pin_set_retries(&pin, 0), PIN_LENGTH_INVALID);
  assert_int_equal(pin_set_retries(&pin, 16), PIN_LENGTH_INVALID);
  assert_int_equal(pin_verify(&pin, "12", 2, &retries), PIN_LENGTH_INVALID);
  assert_int_equal(pin_update(&pin, "12", 2), PIN_LENGTH_INVALID);

  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 2);
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 1);
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 0);
  assert_int_equal(pin_verify(&pin, "1234", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 0);
}

int main(void) {
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

  lfs_filebd_create(&cfg, "lfs-root-core-helpers", &bdcfg);
  fs_format(&cfg);
  fs_mount(&cfg);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_tlv_get_length_safe_variants),
      cmocka_unit_test(test_fs_roundtrip_and_metadata),
      cmocka_unit_test(test_fs_error_paths),
      cmocka_unit_test(test_device_blinking_and_led_behaviour),
      cmocka_unit_test(test_device_allow_kbd_touch_rules),
      cmocka_unit_test(test_device_sessions_and_keepalive),
      cmocka_unit_test(test_wait_for_user_presence_ok),
      cmocka_unit_test(test_wait_for_user_presence_services_ctaphid_while_ccid_waits),
      cmocka_unit_test(test_wait_for_user_presence_cancel_and_timeout),
      cmocka_unit_test(test_strong_user_presence_test_success_and_failure),
      cmocka_unit_test(test_device_loop_and_nfc_state),
      cmocka_unit_test(test_pin_lifecycle),
      cmocka_unit_test(test_pin_error_paths),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);
  return ret;
}
