// SPDX-License-Identifier: Apache-2.0
#include <ccid.h>
#include <device.h>
#include <usbd_canokey.h>
#include <usb_device.h>
#include <usbd_ccid.h>

#define CCID_BULK_IN_IDLE_TIMEOUT_MS 2000u

// CCID_Response_SendData maps these compact kind values to endpoint states.
_Static_assert(CCID_TX_TIME_EXTENSION == 1 && CCID_TX_AUXILIARY == 2 &&
                   CCID_STATE_DATA_IN_AUXILIARY == CCID_STATE_DATA_IN_TIME_EXTENSION + 1,
               "CCID TX kinds and IN states must retain their arithmetic mapping");

static uint8_t ccid_out_buf[64];
static volatile uint32_t bulk_in_state;
// REARM retains no packet; REPLAY retains ccid_out_buf until consumption.
enum { RX_ARMED, RX_REARM, RX_REPLAY };
static volatile uint8_t rx_state;

uint8_t USBD_CCID_Init(USBD_HandleTypeDef *pdev) {
  bulk_in_state = CCID_STATE_IDLE;
  rx_state = RX_ARMED;
  USBD_LL_OpenEP(pdev, EP_IN(ccid), USBD_EP_TYPE_BULK, EP_SIZE(ccid));
  USBD_LL_OpenEP(pdev, EP_OUT(ccid), USBD_EP_TYPE_BULK, EP_SIZE(ccid));
  CCID_Init();
  USBD_LL_PrepareReceive(pdev, EP_OUT(ccid), ccid_out_buf, EP_SIZE(ccid));
  return 0;
}

uint8_t USBD_CCID_DataIn(USBD_HandleTypeDef *pdev) {
  const uint32_t state = bulk_in_state;
  if (state == CCID_STATE_DATA_IN_WITH_ZLP) {
    bulk_in_state = CCID_STATE_DATA_IN;
    uint8_t addr = EP_IN(ccid);
    USBD_LL_Transmit(pdev, addr, NULL, 0);
  } else {
    if (state == CCID_STATE_DATA_IN_AUXILIARY)
      CCID_AuxInFinished();
    else if (state != CCID_STATE_IDLE)
      CCID_InFinished(state == CCID_STATE_DATA_IN_TIME_EXTENSION);
    bulk_in_state = CCID_STATE_IDLE;
  }
  return USBD_OK;
}

uint8_t USBD_CCID_DataOut(USBD_HandleTypeDef *pdev) {
  uint8_t addr = EP_OUT(ccid);
  uint8_t size = EP_SIZE(ccid);
  uint8_t *data_buf = ccid_out_buf;

  uint8_t data_len = USBD_GetRxCount(pdev, addr);
  if (CCID_OutEvent(data_buf, data_len) == USBD_BUSY) {
    rx_state = RX_REPLAY; // This already received packet still needs to be consumed.
    return USBD_BUSY;
  }
  if (!CCID_CanReceive()) {
    rx_state = RX_REARM;
    return USBD_BUSY;
  }
  USBD_LL_PrepareReceive(pdev, addr, data_buf, size);

  return USBD_OK;
}

void USBD_CCID_ServiceReceive(void) {
  if (rx_state == RX_ARMED || !CCID_CanReceive()) return;
  const uint8_t pending = rx_state == RX_REPLAY;
  rx_state = RX_ARMED;
  if (pending)
    USBD_CCID_DataOut(&usb_device);
  else
    USBD_LL_PrepareReceive(&usb_device, EP_OUT(ccid), ccid_out_buf, EP_SIZE(ccid));
}

uint8_t CCID_Response_SendData(USBD_HandleTypeDef *pdev, const uint8_t *buf, uint16_t len,
                               uint8_t kind) {
  if (!USBD_CANOKEY_Ready()) return USBD_BUSY;
  USBD_StatusTypeDef ret = USBD_OK;
  if (pdev->dev_state == USBD_STATE_CONFIGURED) {
    uint32_t next = kind ? CCID_STATE_DATA_IN_TIME_EXTENSION + kind - 1 :
                    len % EP_SIZE(ccid) == 0 ? CCID_STATE_DATA_IN_WITH_ZLP : CCID_STATE_DATA_IN;
    uint32_t wait_ms = 0;
    // Reserve IN atomically against the time-extension IRQ. The reservation
    // lasts through completion, including an optional terminating ZLP.
    while (device_atomic_compare_and_swap(&bulk_in_state, CCID_STATE_IDLE, next) != 0) {
      if (kind != CCID_TX_RESPONSE || wait_ms++ >= CCID_BULK_IN_IDLE_TIMEOUT_MS) return USBD_BUSY;
      device_delay(1);
    }
    ret = USBD_LL_Transmit(pdev, EP_IN(ccid), buf, len);
    if (ret != USBD_OK) bulk_in_state = CCID_STATE_IDLE;
  } else if (kind == CCID_TX_AUXILIARY) return USBD_BUSY;
  return ret;
}

uint8_t CCID_Response_IsIdle(void) { return bulk_in_state == CCID_STATE_IDLE; }
