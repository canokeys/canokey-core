#include <usbd_canokey.h>
#include <usbd_ccid.h>
#include <usbd_ctaphid.h>
#include <usbd_kbdhid.h>
#include <webusb.h>

static uint8_t USBD_CANOKEY_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_CANOKEY_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx);
static uint8_t USBD_CANOKEY_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req);
static uint8_t USBD_CANOKEY_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t USBD_CANOKEY_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum);
static uint8_t USBD_CANOKEY_EP0_TxSent(USBD_HandleTypeDef *pdev);

const USBD_ClassTypeDef USBD_CANOKEY = {
    USBD_CANOKEY_Init,   USBD_CANOKEY_DeInit,  USBD_CANOKEY_Setup, USBD_CANOKEY_EP0_TxSent, NULL,
    USBD_CANOKEY_DataIn, USBD_CANOKEY_DataOut,
};

static uint8_t USBD_CANOKEY_Init(USBD_HandleTypeDef *pdev, uint8_t cfgidx) {
  UNUSED(cfgidx);

  USBD_CTAPHID_Init(pdev);
  USBD_KBDHID_Init(pdev);
  USBD_CCID_Init(pdev);
  USBD_WEBUSB_Init(pdev);

  return 0;
}

static uint8_t USBD_CANOKEY_DeInit(USBD_HandleTypeDef *pdev, uint8_t cfgidx) {
  UNUSED(pdev);
  UNUSED(cfgidx);

  return 0;
}

static uint8_t USBD_CANOKEY_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  uint8_t recipient = req->bmRequest & USB_REQ_RECIPIENT_MASK;
  DBG_MSG("Recipient: %X, Index: %X\n", recipient, req->wIndex);

  if ((recipient == USB_REQ_RECIPIENT_INTERFACE && req->wIndex == USBD_CANOKEY_CTAPHID_IF) ||
      (recipient == USB_REQ_RECIPIENT_ENDPOINT && (req->wIndex == EP_IN(ctap_hid) || req->wIndex == EP_OUT(ctap_hid))))
    return USBD_CTAPHID_Setup(pdev, req);
  if ((recipient == USB_REQ_RECIPIENT_INTERFACE && req->wIndex == USBD_CANOKEY_KBDHID_IF) ||
      (recipient == USB_REQ_RECIPIENT_ENDPOINT && (req->wIndex == EP_IN(kbd_hid) || req->wIndex == EP_OUT(kbd_hid))))
    return USBD_KBDHID_Setup(pdev, req);
  if (recipient == USB_REQ_RECIPIENT_INTERFACE && req->wIndex == USBD_CANOKEY_WEBUSB_IF)
    return USBD_WEBUSB_Setup(pdev, req);

  ERR_MSG("Unknown request\n");
  USBD_CtlError(pdev, req);
  return USBD_FAIL;
}

static uint8_t USBD_CANOKEY_DataIn(USBD_HandleTypeDef *pdev, uint8_t epnum) {
  if (epnum == (0x7F & EP_IN(ctap_hid))) return USBD_CTAPHID_DataIn();
  if (epnum == (0x7F & EP_IN(kbd_hid))) return USBD_KBDHID_DataIn();
  if (epnum == (0x7F & EP_IN(ccid))) return USBD_CCID_DataIn(pdev);

  return USBD_FAIL;
}

static uint8_t USBD_CANOKEY_DataOut(USBD_HandleTypeDef *pdev, uint8_t epnum) {
  if (epnum == EP_OUT(ctap_hid)) return USBD_CTAPHID_DataOut(pdev);
  if (epnum == EP_OUT(kbd_hid)) return USBD_KBDHID_DataOut(pdev);
  if (epnum == EP_OUT(ccid)) return USBD_CCID_DataOut(pdev);

  return USBD_FAIL;
}

static uint8_t USBD_CANOKEY_EP0_TxSent(USBD_HandleTypeDef *pdev) {
  if (pdev->ep0_sender == WEBUSB_EP0_SENDER) return USBD_WEBUSB_TxSent(pdev);
  return USBD_OK;
}
