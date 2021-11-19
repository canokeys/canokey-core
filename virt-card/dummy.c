// SPDX-License-Identifier: Apache-2.0
#include "device.h"
#include "dummy.h"
#include "usb_device.h"
#include "usbd_core.h"
#include <time.h>
#include <unistd.h>

static EPType _EP[8];

EPType *dummy_get_ep_by_addr(uint8_t addr) {
  uint8_t index = ((addr & 0x7Fu) << 1u) + ((addr & 0x80U) ? 1 : 0);
  return &_EP[index];
}

USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev) {

  for (uint8_t i = 0; i < 8; ++i) {
    _EP[i].index = i;
    _EP[i].num = (uint8_t)(i / 2);
    _EP[i].is_in = (uint8_t)(i & 1u);
    _EP[i].addr = (uint8_t)((uint8_t)(_EP[i].is_in << 7u) | _EP[i].num);
    _EP[i].is_stall = 0;
    _EP[i].maxpacket = (uint32_t)((i < 4) ? 16 : 64);
    _EP[i].xfer_buff = 0;
    _EP[i].xfer_len = 0;
  }
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev) {
  USBD_LL_SetSpeed(&usb_device, USBD_SPEED_FULL);
  USBD_LL_Reset(&usb_device);
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t ep_type, uint16_t ep_mps) {
  return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) {
  EPType *ep = dummy_get_ep_by_addr(ep_addr);
  ep->is_stall = 1;
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) {
  EPType *ep = dummy_get_ep_by_addr(ep_addr);
  ep->is_stall = 0;
  return USBD_OK;
}
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) {
  EPType *ep = dummy_get_ep_by_addr(ep_addr);
  return ep->is_stall;
}
USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t *pbuf, uint16_t size) {
  EPType *ep = dummy_get_ep_by_addr(ep_addr);
  ep->xfer_buff = pbuf;
  ep->xfer_len = size;
  DBG_MSG("%#x ep->xfer_buff=%p ep->xfer_len=%d\n", ep_addr, ep->xfer_buff, ep->xfer_len);
  uint32_t len = ep->xfer_len;
  if (ep->xfer_len > ep->maxpacket) {
    len = ep->maxpacket;
  }
  ep->xfer_len -= len;
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep_num, const uint8_t *pbuf, uint16_t size) {
  EPType *ep = dummy_get_ep_by_addr((uint8_t)(ep_num | 0x80u));
  ep->xfer_buff = (uint8_t *)pbuf; // use xfer_buff as bidirectional buffer
  ep->xfer_len = size;
  uint32_t len = ep->xfer_len;
  if (ep->xfer_len > ep->maxpacket) len = ep->maxpacket;
  ep->xfer_len -= len;
  while (len-- > 0)
    ep->xfer_buff++; // transmit data here

  return USBD_OK;
}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr) {
  EPType *ep = dummy_get_ep_by_addr(ep_addr);
  return ep->xfer_count;
  return 0;
}
void device_delay(int ms) {
  struct timespec spec = {.tv_sec = ms / 1000, .tv_nsec = ms % 1000 * 1000000ll};
  nanosleep(&spec, NULL);
}
uint32_t device_get_tick(void) {
  uint64_t ms, s;
  struct timespec spec;

  clock_gettime(CLOCK_MONOTONIC, &spec);

  s = spec.tv_sec;
  ms = spec.tv_nsec / 1000000;
  return (uint32_t)(s * 1000 + ms);
}
void device_disable_irq(void) {}
void device_enable_irq(void) {}
void device_set_timeout(void (*callback)(void), uint16_t timeout) {}
void fm_write_eeprom(uint16_t addr, uint8_t *buf, uint8_t len) { return; }
