// SPDX-License-Identifier: Apache-2.0
// Included in the pinned-release adapter; the real USB core handles every
// SETUP/data/status stage. Only endpoint registers/FIFO completion are modeled.
static void portable_webusb_init(void) {
  device_applet_session_clear();
  // The release CCID fixture installs ADMIN, not CTAP. Rust's fixture installs
  // the full product; provision the same fresh CTAP state before native HID.
  assert_int_equal(ctap_install(1), 0);
  if (portable_ctap_retries8) {
    // Explicit fixture state, not a replacement for a production read result.
    assert_int_equal(set_pin_retries(8), 0);
    assert_int_equal(get_pin_retries(), 8);
  }
  usb_device_init();
  usb_device.dev_state = USBD_STATE_CONFIGURED;
  usb_device.dev_config = 1;
  assert_int_equal(USBD_CANOKEY.Init(&usb_device, 1), USBD_OK);
  USBD_CANOKEY_Service();
  assert_true(USBD_CANOKEY_Ready());
  portable_ep0_pending = false;
}

static void portable_webusb_step(const char *line) {
  const bool service = strncmp(line, "DEFER ", 6) != 0;
  if (!service) line += 6;
  const char *value = strchr(line, ' ');
  assert_non_null(value);
  ++value;
  uint8_t bytes[64];
  const size_t characters = strcspn(value, "\r\n");
  const bool tick = strncmp(line, "TICK ", 5) == 0;
  if (!tick) {
    assert_true(characters % 2 == 0 && characters <= 2 * sizeof(bytes));
    for (size_t i = 0; i < characters / 2; ++i) {
      unsigned byte;
      assert_int_equal(sscanf(value + 2 * i, "%2x", &byte), 1);
      bytes[i] = byte;
    }
  }
  if (strncmp(line, "CLASS_HID ", 10) == 0 || strncmp(line, "CLASS_CCID ", 11) == 0) {
    const bool hid = strncmp(line, "CLASS_HID ", 10) == 0;
    const uint8_t addr = hid ? EP_OUT(ctap_hid) : EP_OUT(ccid);
    const size_t length = characters / 2;
    assert_true(length != 0 && (!hid || length == HID_RPT_SIZE));
    EPType *ep = dummy_get_ep_by_addr(addr);
    // A reset may leave no armed FIFO. Still deliver the stale completion to
    // the real USB/class gate; it must not read a released receive buffer.
    if (ep->xfer_buff) {
      assert_true(length <= ep->xfer_cap);
      memcpy(ep->xfer_buff, bytes, length);
    } else {
      assert_false(USBD_CANOKEY_Ready() && usb_device.dev_state == USBD_STATE_CONFIGURED);
    }
    ep->xfer_count = length;
    const USBD_StatusTypeDef result = USBD_LL_DataOutStage(&usb_device, addr, ep->xfer_buff);
    assert_true(result == USBD_OK || result == USBD_BUSY);
  } else if (strncmp(line, "HID ", 4) == 0) {
    assert_true(portable_include_hid);
    assert_int_equal(characters / 2, HID_RPT_SIZE);
    assert_true(CTAPHID_OutEvent(bytes));
  } else if (strncmp(line, "CCID ", 5) == 0) {
    assert_true(characters != 0);
    assert_int_equal(CCID_OutEvent(bytes, characters / 2), USBD_OK);
  } else if (strncmp(line, "SETUP ", 6) == 0) {
    assert_int_equal(characters, 16);
    // Hardware accepts a new SETUP by stopping the old data stage and clearing
    // both EP0 stalls before the production USB core sees the request.
    portable_ep0_pending = false;
    USBD_LL_ClearStallEP(&usb_device, 0);
    USBD_LL_ClearStallEP(&usb_device, 0x80);
    assert_int_equal(USBD_LL_SetupStage(&usb_device, bytes), USBD_OK);
  } else if (strncmp(line, "OUT ", 4) == 0) {
    EPType *ep = dummy_get_ep_by_addr(0);
    const size_t length = characters / 2;
    assert_true(length <= ep->xfer_cap);
    if (length) {
      assert_non_null(ep->xfer_buff);
      memcpy(ep->xfer_buff, bytes, length);
    }
    ep->xfer_count = length;
    uint8_t *next = ep->xfer_buff ? ep->xfer_buff + length : NULL;
    assert_int_equal(USBD_LL_DataOutStage(&usb_device, 0, next), USBD_OK);
  } else if (strncmp(line, "IN ", 3) == 0) {
    assert_true(portable_ep0_pending);
    portable_ep0_pending = false;
    uint8_t *next = dummy_get_ep_by_addr(0x80)->xfer_buff;
    assert_int_equal(USBD_LL_DataInStage(&usb_device, 0, next), USBD_OK);
  } else if (tick) {
    uint32_t milliseconds;
    assert_int_equal(sscanf(value, "%u", &milliseconds), 1);
    set_test_tick(device_get_tick() + milliseconds);
  } else if (strncmp(line, "RESET ", 6) == 0) {
    // Model hardware FIFO/stall reset separately from the unchanged USB
    // stack's lifecycle callback. No applet cleanup is substituted here.
    portable_ep0_pending = false;
    assert_int_equal(USBD_LL_Init(&usb_device), USBD_OK);
    assert_int_equal(USBD_LL_Reset(&usb_device), USBD_OK);
  } else {
    assert_true(strncmp(line, "POLL ", 5) == 0);
  }
  // The production loop services deferred lifecycle cleanup before dispatch.
  // Bulk replies remain a separate endpoint observation, not a rewritten
  // WebUSB result or a substituted applet/session policy.
  if (service) device_loop();
  printf("WIRE ");
  if (USBD_LL_IsStallEP(&usb_device, 0) || USBD_LL_IsStallEP(&usb_device, 0x80)) {
    printf("STALL");
  } else if (portable_ep0_pending) {
    for (size_t i = 0; i < portable_ep0_length; ++i) printf("%02x", portable_ep0_bytes[i]);
  }
  putchar('\n');
  if (portable_include_hid) {
    printf("HID ");
    for (size_t i = 0; i < portable_hid_length; ++i) printf("%02x", portable_hid_bytes[i]);
    portable_hid_length = 0;
    putchar('\n');
  }
  printf("BULK ");
  for (size_t i = 0; i < portable_length; ++i) printf("%02x", portable_response[i]);
  putchar('\n');
  portable_length = 0;
  portable_ccid_complete();
}
