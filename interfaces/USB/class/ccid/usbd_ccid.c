#include <ccid.h>
#include <device.h>
#include <usb_device.h>
#include <usbd_ccid.h>
#include <usbd_ctlreq.h>

static uint8_t ccid_out_buf[64];
static volatile uint8_t bulk_in_state;

uint8_t USBD_CCID_Init(USBD_HandleTypeDef *pdev) {
  bulk_in_state = CCID_STATE_IDLE;
  USBD_LL_OpenEP(pdev, EP_IN(ccid), USBD_EP_TYPE_BULK, EP_SIZE(ccid));
  USBD_LL_OpenEP(pdev, EP_OUT(ccid), USBD_EP_TYPE_BULK, EP_SIZE(ccid));
  CCID_Init();
  USBD_LL_PrepareReceive(pdev, EP_OUT(ccid), ccid_out_buf, EP_SIZE(ccid));
  return 0;
}

uint8_t USBD_CCID_DataIn(USBD_HandleTypeDef *pdev) {
  if (bulk_in_state == CCID_STATE_DATA_IN_WITH_ZLP) {
    bulk_in_state = CCID_STATE_DATA_IN;
    uint8_t addr = EP_OUT(ccid);
    USBD_LL_Transmit(pdev, addr, NULL, 0);
  } else {
    bulk_in_state = CCID_STATE_IDLE;
  }
  return USBD_OK;
}

uint8_t USBD_CCID_DataOut(USBD_HandleTypeDef *pdev) {
  uint8_t addr = EP_OUT(ccid);
  uint8_t size = EP_SIZE(ccid);
  uint8_t *data_buf = ccid_out_buf;

  uint8_t data_len = USBD_GetRxCount(pdev, addr);
  CCID_OutEvent(data_buf, data_len);
  USBD_LL_PrepareReceive(pdev, addr, data_buf, size);

  return USBD_OK;
}

uint8_t CCID_Response_SendData(USBD_HandleTypeDef *pdev, const uint8_t *buf, uint16_t len,
                               uint8_t is_time_extension_request) {
  USBD_StatusTypeDef ret = USBD_OK;
  if (pdev->dev_state == USBD_STATE_CONFIGURED) {
#ifndef TEST
    while (bulk_in_state != CCID_STATE_IDLE)
      if (is_time_extension_request)
        return ret;
      else
        device_delay(1);
#endif
    uint8_t addr = EP_OUT(ccid);
    uint8_t ep_size = EP_SIZE(ccid);
    bulk_in_state = len % ep_size == 0 ? CCID_STATE_DATA_IN_WITH_ZLP : CCID_STATE_DATA_IN;
    ret = USBD_LL_Transmit(pdev, addr, buf, len);
  }
  return ret;
}
