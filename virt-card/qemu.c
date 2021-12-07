// SPDX-License-Identifier: Apache-2.0
#include "apdu.h"
#include "ccid.h"
#include "device.h"
#include "fabrication.h"
#include "oath.h"
#include "usb_device.h"
#include "usbd_conf.h"
#include "usbd_core.h"
#include "usbd_desc.h"
#include "webusb.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "canokey-qemu.h"

static void* canokey_emu_state;

// mock device functions
USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev) {
  USBD_LL_SetSpeed(&usb_device, USBD_SPEED_FULL);
  USBD_LL_Reset(&usb_device);
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t ep_type, uint16_t ep_mps) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return 0; }
USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev_addr) {
  canokey_emu_set_address(canokey_emu_state, dev_addr);
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) {
  canokey_emu_stall_ep(canokey_emu_state, ep_addr);
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep, uint8_t *pbuf, uint16_t size) {
  canokey_emu_prepare_receive(canokey_emu_state, ep, pbuf, size);
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep, const uint8_t *pbuf, uint16_t size) {
  canokey_emu_transmit(canokey_emu_state, ep, pbuf, size);
  return USBD_OK;
}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return canokey_emu_get_rx_data_size(canokey_emu_state, ep_addr); }

/* Override the function defined in usb_device.c */
void usb_resources_alloc(void) {
  uint8_t iface = 0;
  uint8_t ep = 1;

  // 0xFF for disable
  // doc: interfaces/USB/device/usb_device.h
  memset(&IFACE_TABLE, 0xFF, sizeof(IFACE_TABLE));
  memset(&EP_TABLE, 0xFF, sizeof(EP_TABLE));

  EP_TABLE.ctap_hid = ep++;
  IFACE_TABLE.ctap_hid = iface++;
  EP_SIZE_TABLE.ctap_hid = 64;

  IFACE_TABLE.webusb = iface++;

  EP_TABLE.ccid = ep++;
  IFACE_TABLE.ccid = iface++;
  EP_SIZE_TABLE.ccid = 64;

  //EP_TABLE.kbd_hid = ep;
  //IFACE_TABLE.kbd_hid = iface;
  //EP_SIZE_TABLE.kbd_hid = 8;
}

void canokey_emu_device_loop() {
  device_loop(0);
}

int canokey_emu_init(void *state, const char* canokey_file) {
  canokey_emu_state = state;

  // init usb stack
  usb_device_init();

  // init file system
  if (access(canokey_file, F_OK) == 0) {
    if (card_read(canokey_file)) return 1;
  } else {
    if (card_fabrication_procedure(canokey_file)) return 1;
  }

  // emulate the NFC mode, where user-presence tests are skipped
  set_nfc_state(1);

  return 0;
}

void canokey_emu_setup(int request, int value, int index, int length) {
  uint8_t setup[8];
  setup[0] = (uint8_t)(request >> 8);
  setup[1] = (uint8_t)(request & 0xFF);
  setup[2] = (uint8_t)(value & 0xFF);
  setup[3] = (uint8_t)(value >> 8);
  setup[4] = (uint8_t)(index & 0xFF);
  setup[5] = (uint8_t)(index >> 8);
  setup[6] = (uint8_t)(length & 0xFF);
  setup[7] = (uint8_t)(length >> 8);
  USBD_LL_SetupStage(&usb_device, setup);
}

void canokey_emu_data_out(uint8_t ep, uint8_t *data) {
  USBD_LL_DataOutStage(&usb_device, ep, data);
  /* Side Note:
   * data is only used for control transfer,
   * in this case data length has been notified in setup->length
   * for other EP, the coresponding buf has already been
   * exported by prepare_receive, thus buf has been filled
   * before calling this fun
   */
}

void canokey_emu_data_in(uint8_t ep) {
  USBD_LL_DataInStage(&usb_device, ep & 0x7F, NULL); // for all interfaces, no difference on IN and OUT
}

void canokey_emu_reset() {
  USBD_LL_Reset(&usb_device);
}
// vim: sts=2 ts=2 sw=2
