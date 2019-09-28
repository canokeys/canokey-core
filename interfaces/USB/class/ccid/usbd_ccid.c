#include <ccid.h>
#include <device.h>
#include <usbd_ccid.h>
#include <usbd_ctlreq.h>

static uint8_t out_data_buff[CCID_EPOUT_SIZE];
static volatile uint8_t bulk_in_state;

uint8_t USBD_CCID_Init(USBD_HandleTypeDef *pdev) {
  bulk_in_state = CCID_STATE_IDLE;
  CCID_Init();
  USBD_LL_PrepareReceive(pdev, CCID_EPOUT_ADDR, out_data_buff, CCID_EPOUT_SIZE);
  return 0;
}

uint8_t USBD_CCID_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  ERR_MSG("Unknown setup: bmRequest %02X, bRequest %02X\n", req->bmRequest, req->bRequest);
  USBD_CtlError(pdev, req);
  return USBD_FAIL;
}

uint8_t USBD_CCID_DataIn() {
  bulk_in_state = CCID_STATE_IDLE;
  return USBD_OK;
}

uint8_t USBD_CCID_DataOut(USBD_HandleTypeDef *pdev) {
  uint8_t data_len = USBD_GetRxCount(pdev, CCID_EPOUT_ADDR);
  CCID_OutEvent(out_data_buff, data_len);
  USBD_LL_PrepareReceive(pdev, CCID_EPOUT_ADDR, out_data_buff, CCID_EPOUT_SIZE);
  return USBD_OK;
}

uint8_t CCID_Response_SendData(USBD_HandleTypeDef *pdev, const uint8_t *buf, uint16_t len) {
  USBD_StatusTypeDef ret = USBD_OK;
  if (pdev->dev_state == USBD_STATE_CONFIGURED) {
    while (bulk_in_state != CCID_STATE_IDLE)
      device_delay(1);
    bulk_in_state = CCID_STATE_DATA_IN;
    ret = USBD_LL_Transmit(pdev, CCID_EPIN_ADDR, buf, len);
  }
  return ret;
}
