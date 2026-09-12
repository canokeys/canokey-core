// SPDX-License-Identifier: Apache-2.0
#include <usbd_canokey.h>
#include <device-config.h>
#if ENABLE_IFACE_CCID
#include <usbd_ccid.h>
#endif
#if ENABLE_IFACE_CTAPHID
#include <usbd_ctaphid.h>
#endif
#if ENABLE_IFACE_KBDHID
#include <usbd_kbdhid.h>
#endif
#if ENABLE_IFACE_WEBUSB
#include <webusb.h>
#endif

static uint8_t USBD_CANOKEY_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_CANOKEY_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_CANOKEY_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
static uint8_t USBD_CANOKEY_EP0_TxSent(USBD_HandleTypeDef *pdev);
static uint8_t USBD_CANOKEY_EP0_RxReady(USBD_HandleTypeDef *pdev);
static uint8_t USBD_CANOKEY_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t USBD_CANOKEY_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum);

const USBD_ClassTypeDef USBD_CANOKEY = {
    USBD_CANOKEY_Init,        USBD_CANOKEY_DeInit, USBD_CANOKEY_Setup,   USBD_CANOKEY_EP0_TxSent,
    USBD_CANOKEY_EP0_RxReady, USBD_CANOKEY_DataIn, USBD_CANOKEY_DataOut,
};

static uint8_t USBD_CANOKEY_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx) {
  UNUSED(cfgidx);

#if ENABLE_IFACE_CTAPHID
  USBD_CTAPHID_Init(pdev);
#endif
#if ENABLE_IFACE_KBDHID
  if (device_config_is_pass_enabled()) USBD_KBDHID_Init(pdev);
#endif
#if ENABLE_IFACE_CCID
  USBD_CCID_Init(pdev);
#endif
#if ENABLE_IFACE_WEBUSB
  USBD_WEBUSB_Init(pdev);
#endif
  USBD_LL_Init_Done();

  return 0;
}

static uint8_t USBD_CANOKEY_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx) {
  UNUSED(pdev);
  UNUSED(cfgidx);

  return 0;
}

static uint8_t USBD_CANOKEY_EP0_TxSent(USBD_HandleTypeDef *pdev) {
#if ENABLE_IFACE_WEBUSB
  return USBD_WEBUSB_TxSent(pdev);
#else
  UNUSED(pdev);
  return USBD_OK;
#endif
}

static uint8_t USBD_CANOKEY_EP0_RxReady(USBD_HandleTypeDef *pdev) {
#if ENABLE_IFACE_WEBUSB
  return USBD_WEBUSB_RxReady(pdev);
#else
  UNUSED(pdev);
  return USBD_OK;
#endif
}

static uint8_t USBD_CANOKEY_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  uint8_t recipient = req->bmRequest & USB_REQ_RECIPIENT_MASK;
  uint8_t req_type = req->bmRequest & USB_REQ_TYPE_MASK;
  uint8_t desc_type = req->wValue >> 8;
  uint8_t is_hid_get_descriptor = req_type == USB_REQ_TYPE_STANDARD && req->bRequest == USB_REQ_GET_DESCRIPTOR &&
                                  (desc_type == 0x21 || desc_type == 0x22);

#if ENABLE_IFACE_CTAPHID
  if (((recipient == USB_REQ_RECIPIENT_INTERFACE || is_hid_get_descriptor) && req->wIndex == USBD_CANOKEY_CTAPHID_IF) ||
      (recipient == USB_REQ_RECIPIENT_ENDPOINT && (req->wIndex == EP_IN(ctap_hid) || req->wIndex == EP_OUT(ctap_hid))))
    return USBD_CTAPHID_Setup(pdev, req);
#endif
#if ENABLE_IFACE_KBDHID
  if (device_config_is_pass_enabled() &&
      (((recipient == USB_REQ_RECIPIENT_INTERFACE || is_hid_get_descriptor) && req->wIndex == USBD_CANOKEY_KBDHID_IF) ||
       (recipient == USB_REQ_RECIPIENT_ENDPOINT && (req->wIndex == EP_IN(kbd_hid) || req->wIndex == EP_OUT(kbd_hid)))))
    return USBD_KBDHID_Setup(pdev, req);
#endif
#if ENABLE_IFACE_WEBUSB
  if (recipient == USB_REQ_RECIPIENT_INTERFACE && req->wIndex == USBD_CANOKEY_WEBUSB_IF)
    return USBD_WEBUSB_Setup(pdev, req);
#endif

  ERR_MSG("Unknown request\n");
  USBD_CtlError(pdev, req);
  return USBD_FAIL;
}

static uint8_t USBD_CANOKEY_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum) {
  UNUSED(pdev);
  UNUSED(epnum);

#if ENABLE_IFACE_CTAPHID
  if (epnum == (0x7F & EP_IN(ctap_hid))) return USBD_CTAPHID_DataIn();
#endif
#if ENABLE_IFACE_KBDHID
  if (device_config_is_pass_enabled() && epnum == (0x7F & EP_IN(kbd_hid))) return USBD_KBDHID_DataIn();
#endif
#if ENABLE_IFACE_CCID
  if (epnum == (0x7F & EP_IN(ccid))) return USBD_CCID_DataIn(pdev);
#endif

  return USBD_FAIL;
}

static uint8_t USBD_CANOKEY_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum) {
  UNUSED(pdev);
  UNUSED(epnum);

#if ENABLE_IFACE_CTAPHID
  if (epnum == EP_OUT(ctap_hid)) return USBD_CTAPHID_DataOut(pdev);
#endif
#if ENABLE_IFACE_KBDHID
  if (device_config_is_pass_enabled() && epnum == EP_OUT(kbd_hid)) return USBD_KBDHID_DataOut(pdev);
#endif
#if ENABLE_IFACE_CCID
  if (epnum == EP_OUT(ccid)) return USBD_CCID_DataOut(pdev);
#endif

  return USBD_FAIL;
}
