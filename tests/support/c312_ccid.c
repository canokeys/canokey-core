// SPDX-License-Identifier: Apache-2.0
// Host adapter included after the unchanged pinned C test_apdu.c. Only the
// dummy USB transmit hook is intercepted; production CCID/router/applets run.
static uint8_t portable_response[CCID_CMD_HEADER_SIZE + 258];
static size_t portable_length;
static bool portable_ep0_pending;
static uint8_t portable_ep0_bytes[USB_MAX_EP0_SIZE];
static size_t portable_ep0_length;
static bool portable_include_hid;
static bool portable_ctap_retries8;
// Drain HID IN during each event: the C sender waits synchronously between
// reports, whereas Rust resumes its sender after endpoint completion.
static size_t portable_hid_length;
enum { PORTABLE_HID_REPORTS = 1 + 128 }; // Initial report plus seven-bit SEQ.
static uint8_t portable_hid_bytes[PORTABLE_HID_REPORTS * HID_RPT_SIZE];
static void portable_ccid_complete(void) {
  // Complete the response including its optional terminating zero packet.
  for (unsigned i = 0; !CCID_Response_IsIdle() && i < 2; ++i)
    assert_int_equal(USBD_CCID_DataIn(&usb_device), USBD_OK);
  assert_true(CCID_Response_IsIdle());
}
#include "c312_webusb.c"

USBD_StatusTypeDef portable_dummy_transmit(USBD_HandleTypeDef *pdev, uint8_t ep_num,
                                         const uint8_t *pbuf, uint16_t size);

USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep_num,
                                  const uint8_t *pbuf, uint16_t size) {
  if (ep_num == EP_IN(ccid) && size != 0) {
    assert_true(size <= sizeof(portable_response));
    assert_int_equal(portable_length, 0);
    memcpy(portable_response, pbuf, size);
    portable_length = size;
  }
  if ((ep_num & 0x7f) == 0) {
    portable_ep0_pending = true;
    portable_ep0_length = MIN(size, USB_MAX_EP0_SIZE);
    if (portable_ep0_length) memcpy(portable_ep0_bytes, pbuf, portable_ep0_length);
  }
  if (portable_include_hid && ep_num == EP_IN(ctap_hid)) {
    assert_int_equal(size, HID_RPT_SIZE);
    assert_true(portable_hid_length + size <= sizeof(portable_hid_bytes));
    memcpy(portable_hid_bytes + portable_hid_length, pbuf, size);
    portable_hid_length += size;
    USBD_StatusTypeDef result = portable_dummy_transmit(pdev, ep_num, pbuf, size);
    assert_int_equal(USBD_CTAPHID_DataIn(), USBD_OK);
    return result;
  }
  return portable_dummy_transmit(pdev, ep_num, pbuf, size);
}

static void portable_ccid_loop(void) {
  // Interactive crypto checks consume each real wire reply before constructing
  // the next request. Preserve packet output when stdout is a pipe.
  setvbuf(stdout, NULL, _IOLBF, 0);
  // Match the pinned CIU short-enum key/PKE ABI, not the host enum default.
  enum { PORTABLE_REQUEST_BYTES = 1296 };
  assert_int_equal(pke_buffer_size(), PORTABLE_REQUEST_BYTES);
  ccid_transport_fixture();
  bool nfc_started = false;
  bool webusb_started = false;
  char line[2 * 64 + 32];
  while (fgets(line, sizeof(line), stdin)) {
    if (strcmp(line, "USB\n") == 0 || strcmp(line, "USB-RETRIES8\n") == 0) {
      assert_false(webusb_started);
      portable_include_hid = true;
      portable_ctap_retries8 = strcmp(line, "USB-RETRIES8\n") == 0;
      portable_webusb_init();
      webusb_started = true;
      continue;
    }
    if (strcmp(line, "WEBUSB\n") == 0) {
      assert_false(webusb_started);
      portable_webusb_init();
      webusb_started = true;
      continue;
    }
    if (strncmp(line, "SETUP ", 6) == 0 && !webusb_started) {
      portable_webusb_init();
      webusb_started = true;
    }
    if (webusb_started) {
      portable_webusb_step(line);
      continue;
    }
    const bool service = strncmp(line, "DEFER ", 6) != 0;
    if (!service) memmove(line, line + 6, strlen(line + 6) + 1);
    const bool irq_operation = strncmp(line, "IRQ ", 4) == 0;
    bool nfc_operation = irq_operation || strncmp(line, "NFC ", 4) == 0 || strncmp(line, "HALT ", 5) == 0;
    if (nfc_operation && !nfc_started) {
      // Same clean release fixture initialization, without its implicit SELECT.
      device_applet_session_clear();
      init_apdu_buffer();
      assert_int_equal(ctap_install(1), 0);
      set_nfc_state(1);
      nfc_test_init();
      nfc_started = true;
    }
    if (nfc_started) nfc_test_tx_len = 0;
    if (strncmp(line, "TICK ", 5) == 0) {
      uint32_t milliseconds;
      assert_int_equal(sscanf(line + 5, "%u", &milliseconds), 1);
      set_test_tick(device_get_tick() + milliseconds);
    } else if (strncmp(line, "POLL ", 5) == 0) {
      assert_true(nfc_started);
    } else if (strncmp(line, "HALT ", 5) == 0) {
      nfc_test_halt();
    } else {
      const size_t prefix = nfc_operation ? 4 : 5;
      assert_true(nfc_operation || strncmp(line, "CCID ", 5) == 0);
      const size_t characters = strcspn(line + prefix, "\r\n");
      assert_true(characters != 0 && characters % 2 == 0 && characters <= 2 * 64);
      uint8_t packet[64];
      for (size_t i = 0; i < characters / 2; ++i) {
        unsigned byte;
        assert_int_equal(sscanf(line + prefix + 2 * i, "%2x", &byte), 1);
        packet[i] = (uint8_t)byte;
      }
      if (nfc_operation) {
        size_t length = characters / 2;
        const uint8_t *frame = packet;
        if (irq_operation) {
          // Raw latched MAIN/FIFO/AUX IRQ and live RF_STATUS, then FIFO bytes.
          assert_true(length >= sizeof(nfc_test_irq) + 1);
          memcpy(nfc_test_irq, packet, sizeof(nfc_test_irq));
          nfc_test_rf_status = packet[sizeof(nfc_test_irq)];
          frame += sizeof(nfc_test_irq) + 1;
          length -= sizeof(nfc_test_irq) + 1;
        } else {
          nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
        }
        assert_true(length <= sizeof(nfc_test_rx));
        memcpy(nfc_test_rx, frame, length);
        nfc_test_rx_len = length;
        nfc_test_handler();
      } else {
        assert_int_equal(CCID_OutEvent(packet, characters / 2), USBD_OK);
      }
    }
    if (nfc_started) {
      if (service) nfc_test_loop();
      printf("WIRE ");
      for (size_t i = 0; i < nfc_test_tx_len; ++i) printf("%02x", nfc_test_tx[i]);
      putchar('\n');
      continue;
    }
    CCID_Loop();
    printf("WIRE ");
    for (size_t i = 0; i < portable_length; ++i) printf("%02x", portable_response[i]);
    putchar('\n');
    portable_length = 0;
    portable_ccid_complete();
  }
}
