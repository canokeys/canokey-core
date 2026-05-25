// SPDX-License-Identifier: Apache-2.0

#include "apdu.h"
#include "applets.h"
#include "ccid.h"
#include "ctaphid.h"
#include "device.h"
#include "fabrication.h"
#include <ifdhandler.h>
#include <reader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

const static UCHAR ATR[] = {0x3B, 0xF7, 0x11, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x65,
                            0x43, 0x61, 0x6E, 0x6F, 0x6B, 0x65, 0x79, 0x99};
static int applet_init = 0;

extern ccid_bulkin_data_t bulkin_data;
extern ccid_bulkout_data_t bulkout_data;

static uint8_t send_hid_report(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len) { return 0; }

static uint8_t is_native_u2f_extended_apdu(const uint8_t *buf, DWORD len) {
  if (len < 7 || buf[0] != 0x00 || buf[4] != 0x00) return 0;

  switch (buf[1]) {
  case 0x01: // U2F_REGISTER
  case 0x02: // U2F_AUTHENTICATE
  case 0x03: // U2F_VERSION
    return 1;
  case 0xA4: // U2F_SELECT, distinct from ISO SELECT by P1/P2
    return !(buf[2] == 0x04 && buf[3] == 0x00);
  default:
    return 0;
  }
}

static uint8_t is_fido_pcsc_apdu(const uint8_t *buf, DWORD len) {
  if (len >= 4 && buf[0] == 0x80) return 1; // CTAP2 CBOR / NFC GET RESPONSE
  return is_native_u2f_extended_apdu(buf, len);
}

static uint8_t transmit_xfrblock(DWORD Lun, const uint8_t *tx, DWORD tx_len) {
  // Core CCID maintains a single global bulk endpoint state; the virt-card is
  // single-slot, so we ignore Lun beyond stamping it into bSlot.
  uint8_t *abData = tx_len <= SHORT_ABDATA_SIZE ? bulkout_data.abDataShort : shared_io_buffer;
  memcpy(abData, tx, tx_len);
  bulkout_data.dwLength = tx_len;
  bulkout_data.bSlot = (uint8_t)Lun;
  bulkout_data.bSeq = 0;
  bulkout_data.bSpecific_0 = 0;
  bulkout_data.bSpecific_1 = 0;
  bulkout_data.bSpecific_2 = 0;
  return PC_to_RDR_XfrBlock();
}

RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel) {
  printf("IFDHCreateChannel %ld %ld\n", Lun, Channel);
  if (!applet_init) {
    CTAPHID_Init(send_hid_report);
    CCID_Init();
    card_fabrication_procedure("/tmp/lfs-root");
    applet_init = 1;
  }
  return IFD_SUCCESS;
}

RESPONSECODE IFDHCloseChannel(DWORD Lun) {
  printf("IFDHCloseChannel %ld\n", Lun);
  return IFD_SUCCESS;
}

static RESPONSECODE card_state_change(DWORD Lun, int timeout) {
  struct timespec spec = {.tv_sec = timeout / 1000, .tv_nsec = timeout % 1000 * 1000000ll};
  nanosleep(&spec, NULL);
  return IFD_RESPONSE_TIMEOUT;
}

RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value) {
  printf("IFDHGetCapabilities %ld %#lx\n", Lun, Tag);
  switch (Tag) {
  case TAG_IFD_ATR:
  case SCARD_ATTR_ATR_STRING:
    *Length = sizeof(ATR);
    memcpy(Value, ATR, *Length);
    break;
  case TAG_IFD_SIMULTANEOUS_ACCESS:
    *Length = 1;
    Value[0] = 1;
    break;
  case TAG_IFD_SLOTS_NUMBER:
    *Length = 1;
    Value[0] = 1;
    break;
  case TAG_IFD_POLLING_THREAD_KILLABLE:
    *Length = 1;
    Value[0] = 1;
    break;
  case TAG_IFD_POLLING_THREAD_WITH_TIMEOUT:
    *Length = sizeof(void *);
    *(void **)Value = (void *)card_state_change;
    break;

  default:
    return IFD_ERROR_TAG;
    break;
  }
  return IFD_SUCCESS;
}

RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value) {

  printf("IFDHSetCapabilities %ld %#lx %ld\n", Lun, Tag, Length);
  return IFD_ERROR_TAG;
}

RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3) {

  printf("IFDHSetProtocolParameters %ld %ld %#x\n", Lun, Protocol, Flags);
  if (Protocol != SCARD_PROTOCOL_T1) return IFD_PROTOCOL_NOT_SUPPORTED;
  return IFD_SUCCESS;
}

RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength) {
  printf("IFDHPowerICC %ld Action=%#lx\n", Lun, Action);
  if (Action == IFD_POWER_UP || Action == IFD_RESET) {
    init_apdu_buffer();
    device_init();
    if (applets_install() < 0) return IFD_COMMUNICATION_ERROR;
    *AtrLength = sizeof(ATR);
    memcpy(Atr, ATR, *AtrLength);
  } else if (Action == IFD_POWER_DOWN) {
  } else {
    return IFD_NOT_SUPPORTED;
  }
  return IFD_SUCCESS;
}

RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer,
                               PDWORD RxLength, PSCARD_IO_HEADER RecvPci) {

  printf("IFDHTransmitToICC %ld T=%ld\n", Lun, SendPci.Protocol);
  RecvPci->Protocol = SendPci.Protocol;
  // SCARD_IO_HEADER::Length is not used according to document

  if (TxLength > ABDATA_SIZE) {
    printf("warning TxLength(%lu) too large\n", TxLength);
    *RxLength = 0;
    return IFD_ERROR_INSUFFICIENT_BUFFER;
  }
  const uint8_t aggregate_get_response = is_nfc() && is_fido_pcsc_apdu(TxBuffer, TxLength);
  uint8_t ret = transmit_xfrblock(Lun, TxBuffer, TxLength);
  if (ret != SLOT_NO_ERROR) {
    *RxLength = 0;
    printf("warning: PC_to_RDR_XfrBlock returns %#x\n", ret);
  } else {
    DWORD total_len = 0;
    for (;;) {
      (void)Lun;
      if (bulkin_data.dwLength < 2) {
        *RxLength = 0;
        return IFD_COMMUNICATION_ERROR;
      }

      const uint16_t sw = (uint16_t)(bulkin_data.abData[bulkin_data.dwLength - 2] << 8) |
                          bulkin_data.abData[bulkin_data.dwLength - 1];
      const DWORD data_len = bulkin_data.dwLength - 2;
      const uint8_t has_more = aggregate_get_response && (sw & 0xFF00) == 0x6100;
      const DWORD copy_len = has_more ? data_len : bulkin_data.dwLength;

      if (total_len + copy_len > *RxLength) {
        printf("response too large: total=%lu next=%lu cap=%lu\n", total_len, copy_len, *RxLength);
        *RxLength = 0;
        return IFD_ERROR_INSUFFICIENT_BUFFER;
      }
      memcpy(RxBuffer + total_len, bulkin_data.abData, copy_len);
      total_len += copy_len;

      if (!has_more) {
        *RxLength = total_len;
        break;
      }

      static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
      ret = transmit_xfrblock(Lun, get_response, sizeof(get_response));
      if (ret != SLOT_NO_ERROR) {
        *RxLength = 0;
        printf("warning: PC_to_RDR_XfrBlock(GET RESPONSE) returns %#x\n", ret);
        break;
      }
    }
  }

  return ret == SLOT_NO_ERROR ? IFD_SUCCESS : IFD_COMMUNICATION_ERROR;
}

RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer,
                         DWORD RxLength, LPDWORD pdwBytesReturned) {

  *pdwBytesReturned = 0;
  return IFD_ERROR_NOT_SUPPORTED;
}

RESPONSECODE IFDHICCPresence(DWORD Lun) { return IFD_ICC_PRESENT; }
