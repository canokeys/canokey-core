// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <cmocka.h>
#include <ifdhandler.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "apdu.h"
#include "applets.h"
#include "ccid.h"
#include "device.h"
#include "fabrication.h"

static const uint8_t standard_select[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
static const uint8_t private_select[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xF0, 0x43, 0x41, 0x4E, 0x4F, 0x46, 0x49, 0x44};
static const uint8_t get_info[] = {0x80, 0x10, 0x00, 0x00, 0x01, 0x04, 0x00};
static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

static DWORD exchange(const uint8_t *command, DWORD command_len, uint8_t *response, DWORD capacity) {
  SCARD_IO_HEADER send = {.Protocol = SCARD_PROTOCOL_T1}, recv = {0};
  DWORD len = capacity;
  assert_int_equal(IFDHTransmitToICC(0, send, (PUCHAR)command, command_len, response, &len, &recv), IFD_SUCCESS);
  assert_int_equal(recv.Protocol, send.Protocol);
  assert_true(len >= 2);
  return len;
}

static uint16_t status(const uint8_t *response, DWORD len) {
  return (uint16_t)(response[len - 2] << 8) | response[len - 1];
}

static void select_applet(const uint8_t *command, size_t len, uint16_t expected) {
  uint8_t response[32];
  DWORD received = exchange(command, len, response, sizeof(response));
  assert_int_equal(status(response, received), expected);
  if (expected == SW_NO_ERROR) {
    assert_int_equal(received, 8);
    assert_memory_equal(response, "U2F_V2", 6);
  }
}

static void test_transport_routing(void **state) {
  (void)state;
  uint8_t usb_info[2048], nfc_info[2048];
  assert_int_equal(setenv("CANOKEY_TEST_NFC", "0", 1), 0);
  select_applet(standard_select, sizeof(standard_select), SW_FILE_NOT_FOUND);
  select_applet(private_select, sizeof(private_select), SW_NO_ERROR);
  DWORD usb_len = exchange(get_info, sizeof(get_info), usb_info, sizeof(usb_info));
  assert_int_equal(status(usb_info, usb_len) & 0xFF00, 0x6100);
  // USB exposes ISO GET RESPONSE to the caller rather than aggregating it.
  while ((status(usb_info, usb_len) & 0xFF00) == 0x6100) {
    usb_len -= 2;
    usb_len += exchange(get_response, sizeof(get_response), usb_info + usb_len, sizeof(usb_info) - usb_len);
  }
  assert_int_equal(status(usb_info, usb_len), SW_NO_ERROR);

  // Switch without a manual reset: the old USB selection must not survive.
  assert_int_equal(setenv("CANOKEY_TEST_NFC", "1", 1), 0);
  DWORD rejected_len = exchange(get_info, sizeof(get_info), nfc_info, sizeof(nfc_info));
  assert_int_equal(status(nfc_info, rejected_len), SW_FILE_NOT_FOUND);
  select_applet(private_select, sizeof(private_select), SW_FILE_NOT_FOUND);
  select_applet(standard_select, sizeof(standard_select), SW_NO_ERROR);
  // Short NFC APDUs expose the same ISO continuation as the hardware.
  DWORD nfc_len = exchange(get_info, sizeof(get_info), nfc_info, sizeof(nfc_info));
  assert_int_equal(status(nfc_info, nfc_len) & 0xFF00, 0x6100);
  while ((status(nfc_info, nfc_len) & 0xFF00) == 0x6100) {
    nfc_len -= 2;
    nfc_len += exchange(get_response, sizeof(get_response), nfc_info + nfc_len, sizeof(nfc_info) - nfc_len);
  }
  assert_int_equal(status(nfc_info, nfc_len), SW_NO_ERROR);
  assert_int_equal(nfc_len, usb_len);
  assert_memory_equal(nfc_info, usb_info, usb_len);

  // The reverse transition must also require a fresh transport-specific SELECT.
  assert_int_equal(setenv("CANOKEY_TEST_NFC", "0", 1), 0);
  rejected_len = exchange(get_info, sizeof(get_info), usb_info, sizeof(usb_info));
  assert_int_equal(status(usb_info, rejected_len), SW_FILE_NOT_FOUND);
  select_applet(private_select, sizeof(private_select), SW_NO_ERROR);
  // Abandon a pending USB response while switching, then check GET RESPONSE.
  usb_len = exchange(get_info, sizeof(get_info), usb_info, sizeof(usb_info));
  assert_int_equal(status(usb_info, usb_len) & 0xff00, 0x6100);
  assert_int_equal(setenv("CANOKEY_TEST_NFC", "1", 1), 0);
  rejected_len = exchange(get_response, sizeof(get_response), nfc_info, sizeof(nfc_info));
  assert_int_equal(status(nfc_info, rejected_len), SW_COMMAND_NOT_ALLOWED);
  select_applet(standard_select, sizeof(standard_select), SW_NO_ERROR);
}

// Preserve the original extended Le across every internal short-buffer refill.
static void test_nfc_response_budget(void **state) {
  (void)state;
  assert_int_equal(setenv("CANOKEY_TEST_NFC", "1", 1), 0);
  select_applet(standard_select, sizeof(standard_select), SW_NO_ERROR);
  uint8_t command[] = {0x80, 0x10, 0, 0, 0, 0, 1, 4, 0, 0};
  uint8_t reference[2048], response[2048];
  DWORD reference_len = exchange(command, sizeof(command), reference, sizeof(reference));
  assert_int_equal(status(reference, reference_len), SW_NO_ERROR);
  DWORD case3_len = exchange(command, sizeof(command) - 2, response, sizeof(response));
  assert_int_equal(case3_len, reference_len);
  assert_memory_equal(response, reference, reference_len);
  const uint8_t short_info[] = {0x80, 0x10, 0, 0, 1, 4, 1};
  DWORD short_len = exchange(short_info, sizeof(short_info), response, 3);
  assert_int_equal(short_len, 3);
  assert_int_equal(response[0], reference[0]);
  assert_int_equal(status(response, short_len) & 0xFF00, 0x6100);
  const uint32_t limits[] = {1, 255, 256, 257, 65535, 65536};
  for (size_t i = 0; i < sizeof(limits) / sizeof(*limits); ++i) {
    command[8] = limits[i] >> 8;
    command[9] = limits[i];
    DWORD capacity = MIN(limits[i], reference_len - 2) + 2;
    DWORD len = exchange(command, sizeof(command), response, capacity);
    assert_int_equal(len, capacity);
    assert_memory_equal(response, reference, len - 2);
    if (limits[i] >= reference_len - 2) {
      assert_int_equal(status(response, len), SW_NO_ERROR);
      continue;
    }
    assert_int_equal(status(response, len) & 0xFF00, 0x6100);
    // Case 2E GET RESPONSE must also aggregate within its own Le budget.
    const uint8_t more[] = {0, 0xC0, 0, 0, 0, 0, 0};
    DWORD remaining = exchange(more, sizeof(more), response, sizeof(response));
    assert_int_equal(remaining, reference_len - limits[i]);
    assert_memory_equal(response, reference + limits[i], remaining);
  }
}

static void test_transport_errors(void **state) {
  (void)state;
  uint8_t response[32];
  const uint8_t malformed[] = {0x00, 0xA4, 0x04};
  for (int nfc = 0; nfc <= 1; ++nfc) {
    init_apdu_buffer();
    device_init();
    assert_int_equal(setenv("CANOKEY_TEST_NFC", nfc ? "1" : "0", 1), 0);
    DWORD len = exchange(malformed, sizeof(malformed), response, sizeof(response));
    assert_int_equal(len, 2);
    assert_int_equal(status(response, len), SW_WRONG_LENGTH);
    SCARD_IO_HEADER send = {.Protocol = SCARD_PROTOCOL_T1}, recv = {0};
    len = 1;
    assert_int_equal(
        IFDHTransmitToICC(0, send, (PUCHAR)standard_select, sizeof(standard_select), response, &len, &recv),
        IFD_ERROR_INSUFFICIENT_BUFFER);
    assert_int_equal(len, 0);
    len = sizeof(response);
    assert_int_equal(IFDHTransmitToICC(0, send, (PUCHAR)standard_select, ABDATA_SIZE + 1, response, &len, &recv),
                     IFD_ERROR_INSUFFICIENT_BUFFER);
    assert_int_equal(len, 0);
  }
}

int main(void) {
  char directory[] = "/tmp/canokey-ifd-XXXXXX";
  assert_non_null(mkdtemp(directory));
  char path[128], config_path[136];
  snprintf(path, sizeof(path), "%s/card", directory);
  snprintf(config_path, sizeof(config_path), "%s.config", path);
  assert_int_equal(card_fs_init(path), 0);
  CCID_Init();
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_transport_routing), cmocka_unit_test(test_transport_errors),
                                       cmocka_unit_test(test_nfc_response_budget)};
  int ret = cmocka_run_group_tests(tests, NULL, NULL);
  unlink(path);
  unlink(config_path);
  rmdir(directory);
  return ret;
}
