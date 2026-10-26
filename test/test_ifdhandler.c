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

  init_apdu_buffer();
  device_init();
  assert_int_equal(setenv("CANOKEY_TEST_NFC", "1", 1), 0);
  select_applet(private_select, sizeof(private_select), SW_FILE_NOT_FOUND);
  select_applet(standard_select, sizeof(standard_select), SW_NO_ERROR);
  // The simulated NFC reader drains 61xx, using NFC for every continuation.
  DWORD nfc_len = exchange(get_info, sizeof(get_info), nfc_info, sizeof(nfc_info));
  assert_int_equal(status(nfc_info, nfc_len), SW_NO_ERROR);
  assert_int_equal(nfc_len, usb_len);
  assert_memory_equal(nfc_info, usb_info, usb_len);
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
  const struct CMUnitTest tests[] = {cmocka_unit_test(test_transport_routing), cmocka_unit_test(test_transport_errors)};
  int ret = cmocka_run_group_tests(tests, NULL, NULL);
  unlink(path);
  unlink(config_path);
  rmdir(directory);
  return ret;
}
