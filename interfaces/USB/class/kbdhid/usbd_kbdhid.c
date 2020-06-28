// SPDX-License-Identifier: Apache-2.0
#include <device.h>
#include <kbdhid.h>
#include <usb_device.h>
#include <usbd_ctlreq.h>
#include <usbd_kbdhid.h>

static USBD_KBDHID_HandleTypeDef hid_handle;

// clang-format off
static const uint8_t report_desc[KBDHID_REPORT_DESC_SIZE] = {
    0x05, 0x01,    // USAGE_PAGE (Generic Desktop)
    0x09, 0x06,    // USAGE (Keyboard)
    0xa1, 0x01,    // COLLECTION (Application)
    0x05, 0x07,    //   USAGE_PAGE (Keyboard)
    0x19, 0xe0,    //   USAGE_MINIMUM (Keyboard LeftControl)
    0x29, 0xe7,    //   USAGE_MAXIMUM (Keyboard Right GUI)
    0x15, 0x00,    //   LOGICAL_MINIMUM (0)
    0x25, 0x01,    //   LOGICAL_MAXIMUM (1)
    0x75, 0x01,    //   REPORT_SIZE (1)
    0x95, 0x08,    //   REPORT_COUNT (8)
    0x81, 0x02,    //   INPUT (Data,Var,Abs) // 8x1b modifier keys
    0x95, 0x01,    //   REPORT_COUNT (1)
    0x75, 0x08,    //   REPORT_SIZE (8)
    0x81, 0x03,    //   INPUT (Cnst,Var,Abs) // 1x8b constants
    0x95, 0x05,    //   REPORT_COUNT (5)
    0x75, 0x01,    //   REPORT_SIZE (1)
    0x05, 0x08,    //   USAGE_PAGE (LEDs)
    0x19, 0x01,    //   USAGE_MINIMUM (Num Lock)
    0x29, 0x05,    //   USAGE_MAXIMUM (Kana)
    0x91, 0x02,    //   OUTPUT (Data,Var,Abs)
    0x95, 0x01,    //   REPORT_COUNT (1)
    0x75, 0x03,    //   REPORT_SIZE (3)
    0x91, 0x03,    //   OUTPUT (Cnst,Var,Abs)
    0x95, 0x06,    //   REPORT_COUNT (6)
    0x75, 0x08,    //   REPORT_SIZE (8)
    0x15, 0x00,    //   LOGICAL_MINIMUM (0)
    0x25, 0x65,    //   LOGICAL_MAXIMUM (101)
    0x05, 0x07,    //   USAGE_PAGE (Keyboard)
    0x19, 0x00,    //   USAGE_MINIMUM (Reserved (no event indicated))
    0x29, 0x65,    //   USAGE_MAXIMUM (Keyboard Application)
    0x81, 0x00,    //   INPUT (Data,Ary,Abs) // 6x8b key codes
    0xc0           // END_COLLECTION
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
    while (*state != KBDHID_IDLE)
      device_delay(1);
    hid_handle.state = KBDHID_BUSY;
    USBD_LL_Transmit(pdev, EP_IN(kbd_hid), report, len);
  }
  return USBD_OK;
}

uint8_t USBD_KBDHID_IsIdle() { return hid_handle.state == KBDHID_IDLE; }
