// SPDX-License-Identifier: Apache-2.0
// Host-side tests for the KBDHID typing path (interfaces/USB/class/kbdhid/kbdhid.c).
// The PASS applet and the USB LL layer are stubbed: pass_handle_touch() feeds a
// controlled string, USBD_KBDHID_SendReport() captures reports, and the fake
// touch latch drives the state machine.

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include <device.h>
#include <kbdhid.h>
#include <pass.h>
#include <usbd_kbdhid.h>

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

USBD_HandleTypeDef usb_device = {0}; // kbdhid.c only passes &usb_device through

static uint8_t fake_touch = TOUCH_NO;

bool device_allow_kbd_touch(void) { return fake_touch != TOUCH_NO; }
uint8_t get_touch_result(void) { return fake_touch; }
void set_touch_result(uint8_t result) { fake_touch = result; }

static char stub_sequence[PASS_MAX_PASSWORD_LENGTH + 1];
static int stub_touch_type = -1;

int pass_handle_touch(uint8_t touch_type, char *output) {
  stub_touch_type = touch_type;
  const int len = (int)strlen(stub_sequence);
  memcpy(output, stub_sequence, len);
  return len;
}

static keyboard_report_t captured[2 * (PASS_MAX_PASSWORD_LENGTH + 3)];
static uint8_t captured_len[2 * (PASS_MAX_PASSWORD_LENGTH + 3)];
static int captured_n;

uint8_t USBD_KBDHID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len) {
  (void)pdev;
  assert_true(captured_n < (int)(sizeof(captured) / sizeof(captured[0])));
  memset(&captured[captured_n], 0, sizeof(keyboard_report_t));
  memcpy(&captured[captured_n], report, len);
  captured_len[captured_n] = (uint8_t)len;
  captured_n++;
  return 0;
}

uint8_t USBD_KBDHID_IsIdle(void) { return 1; }

// ---------------------------------------------------------------------------
// Independent HID usage-table oracle (HID Usage Tables, US keyboard layout)
// ---------------------------------------------------------------------------

static char decode_report(uint8_t modifier, uint8_t keycode) {
  const bool shift = (modifier & 0x02) != 0; // HID left/right shift bits are 0x02/0x20; fw uses left shift
  if (keycode >= 0x04 && keycode <= 0x1D) return (shift ? 'A' : 'a') + (char)(keycode - 0x04);
  if (keycode >= 0x1E && keycode <= 0x26) {
    if (!shift) return (char)('1' + keycode - 0x1E);
    return "!@#$%^&*("[keycode - 0x1E];
  }
  if (keycode == 0x27) return shift ? ')' : '0';
  if (keycode == 0x28) return '\r';
  if (keycode == 0x2C) return ' ';
  if (keycode >= 0x2D && keycode <= 0x38 && keycode != 0x32) { // 0x32 is the non-US key, never emitted
    const char *lo = "-=[]\\?;'`" ",./";
    const char *hi = "_+{}|?:\"~<>?";
    return shift ? hi[keycode - 0x2D] : lo[keycode - 0x2D];
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Driver helpers
// ---------------------------------------------------------------------------

static void reset_harness(const char *sequence) {
  memset(&captured, 0, sizeof(captured));
  captured_n = 0;
  stub_touch_type = -1;
  snprintf(stub_sequence, sizeof(stub_sequence), "%s", sequence);
  fake_touch = TOUCH_NO;
  KBDHID_Init();
}

// KBDHID_Loop consumes a pending touch when idle and emits at most one report
// per call; pump a bounded number of iterations (key-down + key-up per char,
// plus the touch-consuming call and the trailing idle transition).
static void pump(void) {
  const int iterations = 2 * ((int)strlen(stub_sequence) + 2) + 4;
  for (int i = 0; i < iterations; ++i)
    KBDHID_Loop();
}

// Decode the captured key-down reports back into a string.
static size_t decode_typed(char *out, size_t out_size) {
  size_t n = 0;
  for (int i = 0; i < captured_n; ++i) {
    if (captured[i].id == 1 && captured[i].keycode[0] != 0) {
      assert_true(n + 1 < out_size);
      out[n] = decode_report(captured[i].modifier, captured[i].keycode[0]);
      assert_true(out[n] != 0);
      n++;
    }
  }
  out[n] = 0;
  return n;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_typing_full_charset(void **state) {
  (void)state;
  // key_sequence is bounded by PASS_MAX_PASSWORD_LENGTH+2, so chunk it
  for (int start = ' '; start <= '~'; start += 32) {
    char chunk[33];
    int n = 0;
    for (int c = start; c <= '~' && n < 32; ++c) chunk[n++] = (char)c;
    chunk[n] = 0;

    reset_harness(chunk);
    fake_touch = TOUCH_SHORT;
    pump();

    char typed[64];
    decode_typed(typed, sizeof(typed));
    assert_string_equal(typed, chunk);
  }
}

static void test_typing_with_enter(void **state) {
  (void)state;
  reset_harness("ok\r");
  fake_touch = TOUCH_SHORT;
  pump();
  char typed[8];
  decode_typed(typed, sizeof(typed));
  assert_string_equal(typed, "ok\r");
}

static void test_eject_sequence(void **state) {
  (void)state;
  reset_harness("");
  KBDHID_Eject();
  pump();
  assert_int_equal(captured_n, 2);
  assert_int_equal(captured[0].id, 2);
  assert_int_equal(captured[0].modifier, 0xB8); // consumer-control eject press
  assert_int_equal(captured_len[0], 2);
  assert_int_equal(captured[1].id, 2);
  assert_int_equal(captured[1].modifier, 0); // release
}

static void test_no_touch_no_output(void **state) {
  (void)state;
  reset_harness("secret");
  pump();
  assert_int_equal(captured_n, 0);
}

static void test_touch_consumed_and_routed(void **state) {
  (void)state;
  reset_harness("ab");
  fake_touch = TOUCH_LONG;
  pump();
  assert_int_equal(stub_touch_type, TOUCH_LONG);
  assert_int_equal(fake_touch, TOUCH_NO); // KBDHID_Loop must consume the touch
  char typed[8];
  decode_typed(typed, sizeof(typed));
  assert_string_equal(typed, "ab");
}

static void test_empty_sequence_types_nothing(void **state) {
  (void)state;
  reset_harness("");
  fake_touch = TOUCH_SHORT;
  pump();
  assert_int_equal(captured_n, 0);
  assert_int_equal(fake_touch, TOUCH_NO);
}

static void test_pending_touch_waits_for_current_sequence(void **state) {
  (void)state;
  reset_harness("xy");
  fake_touch = TOUCH_SHORT;
  KBDHID_Loop();           // consumes the touch, starts typing "xy"
  KBDHID_Loop();           // key-down 'x'
  fake_touch = TOUCH_SHORT; // mid-typing touch must not clobber the sequence
  pump();
  char typed[16];
  decode_typed(typed, sizeof(typed));
  assert_string_equal(typed, "xyxy"); // old sequence finishes, then the pending touch types again
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_typing_full_charset),
      cmocka_unit_test(test_typing_with_enter),
      cmocka_unit_test(test_eject_sequence),
      cmocka_unit_test(test_no_touch_no_output),
      cmocka_unit_test(test_touch_consumed_and_routed),
      cmocka_unit_test(test_empty_sequence_types_nothing),
      cmocka_unit_test(test_pending_touch_waits_for_current_sequence),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
