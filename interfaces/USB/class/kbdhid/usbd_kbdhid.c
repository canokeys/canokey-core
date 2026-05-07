// SPDX-License-Identifier: Apache-2.0
#include <device.h>
#include <kbdhid.h>
#include <usb_device.h>
#include <usbd_ctlreq.h>
#include <usbd_kbdhid.h>

static USBD_KBDHID_HandleTypeDef hid_handle;

// clang-format off
static const uint8_t report_desc[KBDHID_REPORT_DESC_SIZE] = {
    0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
    0x09, 0x06,        // Usage (Keyboard)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x01,        //   Report ID (1)
    0x05, 0x07,        //   Usage Page (Kbrd/Keypad)
    0x19, 0xE0,        //   Usage Minimum (0xE0)
    0x29, 0xE7,        //   Usage Maximum (0xE7)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x08,        //   Report Count (8)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x08,        //   Report Size (8)
    0x81, 0x03,        //   Input (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x05,        //   Report Count (5)
    0x75, 0x01,        //   Report Size (1)
    0x05, 0x08,        //   Usage Page (LEDs)
    0x19, 0x01,        //   Usage Minimum (Num Lock)
    0x29, 0x05,        //   Usage Maximum (Kana)
    0x91, 0x02,        //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x03,        //   Report Size (3)
    0x91, 0x03,        //   Output (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x95, 0x05,        //   Report Count (5)
    0x75, 0x08,        //   Report Size (8)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x65,        //   Logical Maximum (101)
    0x05, 0x07,        //   Usage Page (Kbrd/Keypad)
    0x19, 0x00,        //   Usage Minimum (0x00)
    0x29, 0x65,        //   Usage Maximum (0x65)
    0x81, 0x00,        //   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
    0x05, 0x0C,        // Usage Page (Consumer)
    0x09, 0x01,        // Usage (Consumer Control)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x02,        //   Report ID (2)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x08,        //   Report Size (1)
    0x95, 0x01,        //   Report Count (1)
    0x0A, 0xAE, 0x01,  //   Usage (AL Keyboard Layout)
    0x81, 0x06,        //   Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
};

static const uint8_t USBD_KBDHID_Desc[] = {
    0x09,                    /* bLength: KBD HID Descriptor size */
    KBDHID_DESCRIPTOR_TYPE,  /* bDescriptorType: KBD HID */
    0x11, 0x01,              /* bKBD_HID: KBD HID Class Spec release number */
    0x00,                    /* bCountryCode: Hardware target country */
    0x01,                    /* bNumDescriptors: 1 */
    KBDHID_REPORT_DESC,      /* bDescriptorType */
    KBDHID_REPORT_DESC_SIZE, /* wItemLength: Length of Report */
    0x00,
};
// clang-format on

uint8_t USBD_KBDHID_Init(USBD_HandleTypeDef *pdev) {
  hid_handle.state = KBDHID_IDLE;
  KBDHID_Init();
  if (EP_OUT(kbd_hid) != 0xFF) {
    USBD_LL_OpenEP(pdev, EP_IN(kbd_hid), USBD_EP_TYPE_INTR, EP_SIZE(kbd_hid));
    USBD_LL_OpenEP(pdev, EP_OUT(kbd_hid), USBD_EP_TYPE_INTR, EP_SIZE(kbd_hid));
    USBD_LL_PrepareReceive(pdev, EP_OUT(kbd_hid), hid_handle.report_buf, USBD_KBDHID_REPORT_BUF_SIZE);
  }
  return USBD_OK;
}

uint8_t USBD_KBDHID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  uint16_t len = 0;
  const uint8_t *pbuf = NULL;

  switch (req->bmRequest & USB_REQ_TYPE_MASK) {
  case USB_REQ_TYPE_CLASS:
    switch (req->bRequest) {
    case KBDHID_REQ_SET_IDLE:
      hid_handle.idle_state = (uint8_t)(req->wValue >> 8);
      break;

    default:
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    break;

  case USB_REQ_TYPE_STANDARD:
    switch (req->bRequest) {
    case USB_REQ_GET_DESCRIPTOR:
      if (req->wValue >> 8 == KBDHID_REPORT_DESC) {
        len = (uint16_t)MIN(sizeof(report_desc), req->wLength);
        pbuf = report_desc;
      } else if (req->wValue >> 8 == KBDHID_DESCRIPTOR_TYPE) {
        pbuf = USBD_KBDHID_Desc;
        len = (uint16_t)MIN(sizeof(USBD_KBDHID_Desc), req->wLength);
      } else {
        USBD_CtlError(pdev, req);
        break;
      }
      USBD_CtlSendData(pdev, pbuf, len, 0);
      break;

    default:
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
  }
  return USBD_OK;
}

uint8_t USBD_KBDHID_DataIn() {
  hid_handle.state = KBDHID_IDLE;
  return USBD_OK;
}

uint8_t USBD_KBDHID_DataOut(USBD_HandleTypeDef *pdev) {
  //   KBDHID_OutEvent(hid_handle.report_buf);
  USBD_LL_PrepareReceive(pdev, EP_OUT(kbd_hid), hid_handle.report_buf, USBD_KBDHID_REPORT_BUF_SIZE);
  return USBD_OK;
}

uint8_t USBD_KBDHID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len) {
  volatile KBDHID_StateTypeDef *state = &hid_handle.state;

  if (pdev->dev_state == USBD_STATE_CONFIGURED && EP_OUT(kbd_hid) != 0xFF) {
    int retry = 0;
    while (*state != KBDHID_IDLE) {
      // if reports are not being processed on host, we may get stuck here
      if (++retry > 50) return USBD_BUSY;
      device_delay(1);
    }
    hid_handle.state = KBDHID_BUSY;
    USBD_LL_Transmit(pdev, EP_IN(kbd_hid), report, len);
  }
  return USBD_OK;
}

uint8_t USBD_KBDHID_IsIdle() { return hid_handle.state == KBDHID_IDLE; }
