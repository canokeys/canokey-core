#include <ctaphid.h>
#include <device.h>
#include <usbd_ctaphid.h>
#include <usbd_ctlreq.h>

static USBD_CTAPHID_HandleTypeDef hid_handle;

// clang-format off
static const uint8_t ReportDesc[] = {
    0x06, 0xD0, 0xF1, // USAGE_PAGE (CTAP Usage Page)
    0x09, 0x01,       // USAGE (CTAP HID)
    0xA1, 0x01,       // COLLECTION (Application)
    0x09, 0x20,       //   USAGE (Usage Data In)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x81, 0x02,       //   INPUT (Data,Var,Abs)
    0x09, 0x21,       //   USAGE (Usage Data Out)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x91, 0x02,       //   OUTPUT (Data,Var,Abs)
    0xC0              // END_COLLECTION
};

static const uint8_t USBD_CTAPHID_Desc[] = {
    0x09,                    /* bLength: CTAP HID Descriptor size */
    CTAPHID_DESCRIPTOR_TYPE, /* bDescriptorType: CTAP HID */
    0x11, 0x01,              /* bCTAP_HID: CTAP HID Class Spec release number */
    0x00,                    /* bCountryCode: Hardware target country */
    0x01,                    /* bNumDescriptors: 1 */
    0x22,                    /* bDescriptorType */
    CTAPHID_REPORT_DESC_SIZE,/* wItemLength: Length of Report */
    0x00,
};
// clang-format on

uint8_t USBD_CTAPHID_Init(USBD_HandleTypeDef *pdev) {
  hid_handle.state = CTAPHID_IDLE;
  CTAPHID_Init();
  USBD_LL_PrepareReceive(pdev, CTAPHID_EPOUT_ADDR, hid_handle.report_buf, USBD_CTAPHID_REPORT_BUF_SIZE);
  return USBD_OK;
}

uint8_t USBD_CTAPHID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  uint16_t len = 0;
  const uint8_t *pbuf = NULL;

  switch (req->bmRequest & USB_REQ_TYPE_MASK) {
  case USB_REQ_TYPE_CLASS:
    switch (req->bRequest) {

    case CTAPHID_REQ_SET_PROTOCOL:
      hid_handle.protocol = (uint8_t)(req->wValue);
      break;

    case CTAPHID_REQ_GET_PROTOCOL:
      USBD_CtlSendData(pdev, (uint8_t *)&hid_handle.protocol, 1, 0);
      break;

    case CTAPHID_REQ_SET_IDLE:
      hid_handle.idle_state = (uint8_t)(req->wValue >> 8);
      break;

    case CTAPHID_REQ_GET_IDLE:
      USBD_CtlSendData(pdev, (uint8_t *)&hid_handle.idle_state, 1, 0);
      break;

    case CTAPHID_REQ_SET_REPORT:
      hid_handle.is_report_available = 1;
      break;

    default:
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    break;

  case USB_REQ_TYPE_STANDARD:
    switch (req->bRequest) {
    case USB_REQ_GET_DESCRIPTOR:
      if (req->wValue >> 8 == CTAPHID_REPORT_DESC) {
        len = (uint16_t)MIN(sizeof(ReportDesc), req->wLength);
        pbuf = ReportDesc;
      } else if (req->wValue >> 8 == CTAPHID_DESCRIPTOR_TYPE) {
        pbuf = USBD_CTAPHID_Desc;
        len = (uint16_t)MIN(sizeof(USBD_CTAPHID_Desc), req->wLength);
      } else {
        USBD_CtlError(pdev, req);
        break;
      }
      USBD_CtlSendData(pdev, pbuf, len, 0);
      break;

    case USB_REQ_GET_INTERFACE:
      USBD_CtlSendData(pdev, (uint8_t *)&hid_handle.alt_setting, 1, 0);
      break;

    case USB_REQ_SET_INTERFACE:
      hid_handle.alt_setting = (uint8_t)(req->wValue);
      break;
    }
  }
  return USBD_OK;
}

uint8_t USBD_CTAPHID_DataIn() {
  hid_handle.state = CTAPHID_IDLE;
  return USBD_OK;
}

uint8_t USBD_CTAPHID_DataOut(USBD_HandleTypeDef *pdev) {
  CTAPHID_OutEvent(hid_handle.report_buf);
  USBD_LL_PrepareReceive(pdev, CTAPHID_EPOUT_ADDR, hid_handle.report_buf, USBD_CTAPHID_REPORT_BUF_SIZE);
  return USBD_OK;
}

uint8_t USBD_CTAPHID_SendReport(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len) {
  volatile CTAPHID_StateTypeDef *state = &hid_handle.state;

  if (pdev->dev_state == USBD_STATE_CONFIGURED) {
    while (*state != CTAPHID_IDLE)
      device_delay(1);
    hid_handle.state = CTAPHID_BUSY;
    USBD_LL_Transmit(pdev, CTAPHID_EPIN_ADDR, report, len);
  }
  return USBD_OK;
}
