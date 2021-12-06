// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libhfuzz/libhfuzz.h>

#include "admin.h"
#include "ccid.h"
#include "ctap.h"
#include "device.h"
#include "usb-dummy.h"
#include "fabrication.h"
#include "ndef.h"
#include "oath.h"
#include "openpgp.h"
#include "piv.h"
#include "usb_device.h"
#include "usbd_core.h"

typedef int applet_process_t(const CAPDU *capdu, RAPDU *rapdu);

applet_process_t *applets[] = {piv_process_apdu,   ctap_process_apdu,    oath_process_apdu,
                               admin_process_apdu, openpgp_process_apdu, ndef_process_apdu};

extern ccid_bulkin_data_t bulkin_data;
extern ccid_bulkout_data_t bulkout_data;
static applet_process_t *process_func;
static uint8_t setup_buffer[16];

static int EmulateUSBEnumeration() {
  uint8_t set_address[] = {0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  // USBD_LL_SetupStage->USBD_StdDevReq->USBD_SetAddress
  USBD_LL_SetupStage(&usb_device, set_address);

  uint8_t set_config[] = {0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  // USBD_LL_SetupStage->USBD_StdDevReq->USBD_SetConfig
  USBD_LL_SetupStage(&usb_device, set_config);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  static char lfs_root[64];
  process_func = NULL;
  setbuf(stdout, 0);
  if (*argc > 1) {
    int idx = atoi((*argv)[1]);
    if (idx >= 0 && idx < sizeof(applets) / sizeof(applets[0])) {
      process_func = applets[idx];
      printf("Applet %d Fuzzing Test\n", idx);
      sprintf(lfs_root, "/tmp/fuzz_applet%d", idx);
    }
  }
  if (!process_func) {
    printf("CCID Fuzzing Test\n");
    sprintf(lfs_root, "/tmp/fuzz_ccid");
  }
  usb_device_init();
  EmulateUSBEnumeration(); // required before any CCID transation
  set_nfc_state(1);
  if (*argc > 2 && strcmp((*argv)[2], "--keep") == 0) { // keep data in littlefs
    card_read(lfs_root);
  } else {
    unlink(lfs_root);
    card_fabrication_procedure(lfs_root);
  }
  printf("Finished initialization\n");
  return 0;
}

void EmulateUSBTrans(const uint8_t *buf, size_t len) {
  if (len < 1) return;
  uint8_t ep_num = buf[0] & 0x83;
  uint8_t is_setup = buf[0] & 0x40; // just some random bits
  len--;
  buf++;

  EPType *ep = dummy_get_ep_by_addr(ep_num);
  if (len > ep->maxpacket) len = ep->maxpacket; // constrained by hardware
  if ((ep_num & 0x80) != 0) {
    // EP IN

    DBG_MSG("%#x ep->xfer_buff=%p ep->xfer_count=%d len=%d\n", ep_num, ep->xfer_buff, ep->xfer_count, len);
    if (ep->num == 0) {
      USBD_LL_DataInStage(&usb_device, ep->num, ep->xfer_buff);
    } else {
      if (ep->xfer_len == 0)
        USBD_LL_DataInStage(&usb_device, ep->num, ep->xfer_buff);
      else
        USBD_LL_Transmit(&usb_device, ep_num, ep->xfer_buff, (uint16_t)ep->xfer_len);
    }
  } else {
    // EP OUT

    if (is_setup && ep->num == 0) {
      ep->xfer_buff = setup_buffer;
      ep->xfer_count = len;
      DBG_MSG("%#x ep->xfer_buff=%p ep->xfer_count=%d len=%d\n", ep_num, ep->xfer_buff, ep->xfer_count, len);
      memcpy(setup_buffer, buf, ep->xfer_count);
      ep->xfer_buff =+ ep->xfer_count;
      USBD_LL_SetupStage(&usb_device, setup_buffer);
    } else {
      if (len > ep->xfer_len) {
        USBD_LL_StallEP(NULL, ep->addr);
        return;
      }
      DBG_MSG("%#x ep->xfer_buff=%p ep->xfer_count=%d len=%d\n", ep_num, ep->xfer_buff, ep->xfer_count, len);
      ep->xfer_count = len;
      memcpy(ep->xfer_buff, buf, ep->xfer_count);
      ep->xfer_buff += ep->xfer_count;
      if (ep->num == 0) {
        USBD_LL_DataOutStage(&usb_device, ep->num, ep->xfer_buff);
      } else {
        if (ep->xfer_len == 0 || ep->xfer_count < ep->maxpacket)
          USBD_LL_DataOutStage(&usb_device, ep->num, ep->xfer_buff);
        else
          USBD_LL_PrepareReceive(&usb_device, ep->addr, ep->xfer_buff, (uint16_t)ep->xfer_len);
      }
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if (!process_func) { // CCID Fuzzing Test
    // if (len > APDU_BUFFER_SIZE) len = APDU_BUFFER_SIZE;
    // memcpy(bulkout_data.abData, buf, len);
    // bulkout_data.dwLength = len;
    // PC_to_RDR_XfrBlock();
    EmulateUSBTrans(buf, len);
  } else { // Applet Fuzzing Test
    uint16_t apdu_len = len & 0xffff;
    if (apdu_len > APDU_BUFFER_SIZE) apdu_len = APDU_BUFFER_SIZE;

    CAPDU capdu;
    RAPDU rapdu;
    capdu.data = bulkout_data.abData;
    rapdu.data = bulkout_data.abData;
    rapdu.len = APDU_BUFFER_SIZE;
    if (build_capdu(&capdu, buf, apdu_len) < 0) {
      return 0;
    }
    // realloc data to let the sanitizer find out buffer overflow
    if (capdu.lc > 0) {
      uint8_t *new_data = malloc(capdu.lc);
      memcpy(new_data, capdu.data, capdu.lc);
      capdu.data = new_data;
    } else {
      // should never read data when lc=0
      capdu.data = NULL;
    }
    PRINT_HEX(buf, apdu_len);
    capdu.le = MIN(capdu.le, APDU_BUFFER_SIZE);
    process_func(&capdu, &rapdu);

    if (capdu.lc > 0) {
      free(capdu.data);
    }
  }
  return 0;
}
