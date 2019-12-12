#include <ccid.h>
#include <device.h>
#include <usb_device.h>
#include <usbd_ccid.h>
#include <usbd_ctlreq.h>

static uint8_t ccid_out_buf[CCID_EPOUT_SIZE];
static uint8_t openpgp_out_buf[OPENPGP_EPOUT_SIZE];
static volatile uint8_t bulk_in_state[2];

uint8_t USBD_CCID_Init(USBD_HandleTypeDef *pdev) {
  bulk_in_state[0] = CCID_STATE_IDLE;
  bulk_in_state[1] = CCID_STATE_IDLE;
  USBD_LL_OpenEP(pdev, EP_IN(ccid), USBD_EP_TYPE_BULK, CCID_EPIN_SIZE);
  USBD_LL_OpenEP(pdev, EP_OUT(ccid), USBD_EP_TYPE_BULK, CCID_EPOUT_SIZE);
  if (EP_OUT(openpgp) != 0xFF) {
    USBD_LL_OpenEP(pdev, EP_IN(openpgp), USBD_EP_TYPE_BULK, OPENPGP_EPIN_SIZE);
    USBD_LL_OpenEP(pdev, EP_OUT(openpgp), USBD_EP_TYPE_BULK, OPENPGP_EPOUT_SIZE);
  }
  CCID_Init();
  USBD_LL_PrepareReceive(pdev, EP_OUT(ccid), ccid_out_buf, CCID_EPOUT_SIZE);
  if (EP_OUT(openpgp) != 0xFF) {
    USBD_LL_PrepareReceive(pdev, EP_OUT(openpgp), openpgp_out_buf, OPENPGP_EPOUT_SIZE);
  }
  return 0;
}

uint8_t USBD_CCID_DataIn(USBD_HandleTypeDef *pdev, uint8_t idx) {
  if (bulk_in_state[idx] == CCID_STATE_DATA_IN_WITH_ZLP) {
    bulk_in_state[idx] = CCID_STATE_DATA_IN;
    uint8_t addr = idx == IDX_CCID ? EP_OUT(ccid) : EP_OUT(openpgp);
    USBD_LL_Transmit(pdev, addr, NULL, 0);
  } else {
    bulk_in_state[idx] = CCID_STATE_IDLE;
  }
  return USBD_OK;
}

uint8_t USBD_CCID_DataOut(USBD_HandleTypeDef *pdev, uint8_t idx) {
  uint8_t addr = idx == IDX_CCID ? EP_OUT(ccid) : EP_OUT(openpgp);
  uint8_t size = idx == IDX_CCID ? CCID_EPOUT_SIZE : OPENPGP_EPOUT_SIZE;
  uint8_t *data_buf = idx == IDX_CCID ? ccid_out_buf : openpgp_out_buf;

  uint8_t data_len = USBD_GetRxCount(pdev, addr);
  CCID_OutEvent(data_buf, data_len, idx);
  USBD_LL_PrepareReceive(pdev, addr, data_buf, size);

  return USBD_OK;
}

uint8_t CCID_Response_SendData(USBD_HandleTypeDef *pdev, const uint8_t *buf, uint16_t len, uint8_t idx,
                               uint8_t is_time_extension_request) {
  USBD_StatusTypeDef ret = USBD_OK;
  if (pdev->dev_state == USBD_STATE_CONFIGURED) {
    while (bulk_in_state[idx] != CCID_STATE_IDLE)
      device_delay(1);
    if (bulk_in_state[idx] != CCID_STATE_IDLE && is_time_extension_request) return ret;
    uint8_t addr = idx == IDX_CCID ? EP_OUT(ccid) : EP_OUT(openpgp);
    uint8_t ep_size = idx == IDX_CCID ? CCID_EPOUT_SIZE : OPENPGP_EPOUT_SIZE;
    bulk_in_state[idx] = len % ep_size == 0 ? CCID_STATE_DATA_IN_WITH_ZLP : CCID_STATE_DATA_IN;
    ret = USBD_LL_Transmit(pdev, addr, buf, len);
  }
  return ret;
}
