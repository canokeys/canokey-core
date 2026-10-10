// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static applet_process_t *const applets[] = {piv_process_apdu,   ctap_process_apdu,    oath_process_apdu,
                                            admin_process_apdu, openpgp_process_apdu, ndef_process_apdu};

extern ccid_bulkin_data_t bulkin_data;
static applet_process_t *process_func;
static uint8_t setup_buffer[16];

static void emulate_usb_enumeration(void) {
  uint8_t set_address[] = {0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  // USBD_LL_SetupStage->USBD_StdDevReq->USBD_SetAddress
  USBD_LL_SetupStage(&usb_device, set_address);

  uint8_t set_config[] = {0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  // USBD_LL_SetupStage->USBD_StdDevReq->USBD_SetConfig
  USBD_LL_SetupStage(&usb_device, set_config);
}

// Target selection via environment keeps the AFL++ command line engine-only:
//   CANOKEY_FUZZ_APPLET=0..5  fuzz one applet (PIV, CTAP, OATH, Admin,
//                             OpenPGP, NDEF); empty/unset fuzzes the CCID
//                             transport layer
//   CANOKEY_FUZZ_KEEP=1       keep the LittleFS state instead of
//                             re-fabricating the card
static void fuzz_initialize(void) {
  static char lfs_root[64];
  process_func = NULL;
  setbuf(stdout, 0);
  const char *idx_str = getenv("CANOKEY_FUZZ_APPLET");
  if (idx_str != NULL && *idx_str != '\0') {
    int idx = atoi(idx_str);
    if (idx >= 0 && idx < (int)(sizeof(applets) / sizeof(applets[0]))) {
      process_func = applets[idx];
      printf("Applet %d Fuzzing Test\n", idx);
      snprintf(lfs_root, sizeof(lfs_root), "/tmp/fuzz_applet%d", idx);
    }
  }
  if (!process_func) {
    printf("CCID Fuzzing Test\n");
    snprintf(lfs_root, sizeof(lfs_root), "/tmp/fuzz_ccid");
  }
  usb_device_init();
  emulate_usb_enumeration(); // required before any CCID transaction
  set_nfc_state(1);
  const char *keep = getenv("CANOKEY_FUZZ_KEEP");
  int ret;
  if (keep != NULL && strcmp(keep, "1") == 0) { // keep data in littlefs
    ret = card_read(lfs_root);
  } else {
    unlink(lfs_root);
    ret = card_fabrication_procedure(lfs_root);
  }
  if (ret != 0) {
    fprintf(stderr, "Failed to initialize fuzzing storage\n");
    exit(1);
  }
  printf("Finished initialization\n");
}

static void emulate_usb_transaction(const uint8_t *buf, size_t len) {
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
      if (len > sizeof(setup_buffer)) len = sizeof(setup_buffer);
      ep->xfer_count = len;
      ep->xfer_cap = 0; // any later data stage must go through PrepareReceive
      DBG_MSG("%#x ep->xfer_buff=%p ep->xfer_count=%d len=%d\n", ep_num, ep->xfer_buff, ep->xfer_count, len);
      memcpy(setup_buffer, buf, ep->xfer_count);
      ep->xfer_buff += ep->xfer_count;
      USBD_LL_SetupStage(&usb_device, setup_buffer);
    } else {
      // xfer_cap tracks the writable window of the buffer the stack prepared;
      // without it, repeated writes would run past the end of that buffer.
      if (len > ep->xfer_len || len > ep->xfer_cap) {
        USBD_LL_StallEP(NULL, ep->addr);
        return;
      }
      DBG_MSG("%#x ep->xfer_buff=%p ep->xfer_count=%d len=%d\n", ep_num, ep->xfer_buff, ep->xfer_count, len);
      ep->xfer_count = len;
      if (ep->xfer_count > 0) {
        // A zero-length OUT packet can arrive before any receive buffer was
        // prepared (xfer_buff is still NULL); never do memcpy(NULL, buf, 0).
        memcpy(ep->xfer_buff, buf, ep->xfer_count);
        ep->xfer_buff += ep->xfer_count;
      }
      ep->xfer_cap -= ep->xfer_count;
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

static void fuzz_one_input(const uint8_t *buf, size_t len) {
  if (!process_func) { // CCID Fuzzing Test
    emulate_usb_transaction(buf, len);
  } else { // Applet Fuzzing Test
    uint16_t apdu_len = len & 0xffff;
    if (apdu_len > APDU_BUFFER_SIZE) apdu_len = APDU_BUFFER_SIZE;

    CAPDU capdu;
    RAPDU rapdu;
    capdu.data = bulkin_data.abData;
    rapdu.data = bulkin_data.abData;
    rapdu.len = APDU_BUFFER_SIZE;
    if (build_capdu(&capdu, buf, apdu_len) < 0) {
      return;
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
}

#define FUZZ_INPUT_CAPACITY (1U << 20)

static size_t read_fuzz_input(uint8_t *buf, size_t capacity) {
  size_t len = 0;
  while (len < capacity) {
    ssize_t count = read(STDIN_FILENO, buf + len, capacity - len);
    if (count > 0) {
      len += (size_t)count;
      continue;
    }
    if (count == 0) break;
    if (errno == EINTR) continue;
    perror("read fuzz input");
    exit(EXIT_FAILURE);
  }
  return len;
}

int main(void) {
  static uint8_t input[FUZZ_INPUT_CAPACITY];

  fuzz_initialize();

  // The virtual card is stateful. Start AFL's forkserver after initialization
  // so every input sees the same card state in an isolated child process.
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  fuzz_one_input(input, read_fuzz_input(input, sizeof(input)));
  return 0;
}
