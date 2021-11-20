// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <meta.h>

#define TAG_USB_SUPPORT 0x01
#define TAG_SN 0x02
#define TAG_USB_ENABLED 0x03
#define TAG_NFC_SUPPORT 0x0D
#define TAG_NFC_ENABLED 0x0E

int meta_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  switch (INS) {
  case META_INS_SELECT:
    if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    memcpy(RDATA, "5.5.0", 5);  // a fake version
    LL = 5;
    break;

  case META_INS_READ_META:
    if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    RDATA[0] = 22;
    RDATA[1] = TAG_USB_SUPPORT; // FIDO2|OATH|PIV|OPENPGP|U2F
    RDATA[2] = 2;
    RDATA[3] = 0x02;
    RDATA[4] = 0x3A;
    RDATA[5] = TAG_SN;
    RDATA[6] = 4;
    fill_sn(RDATA + 7);
    RDATA[11] = TAG_USB_ENABLED; // FIDO2|OATH|PIV|OPENPGP|U2F
    RDATA[12] = 2;
    RDATA[13] = 0x02;
    RDATA[14] = 0x3A;
    RDATA[15] = TAG_NFC_SUPPORT; // FIDO2|OATH|PIV|OPENPGP|U2F
    RDATA[16] = 2;
    RDATA[17] = 0x02;
    RDATA[18] = 0x3A;
    RDATA[19] = TAG_NFC_ENABLED; // FIDO2|OATH|PIV|OPENPGP|U2F
    RDATA[20] = 2;
    RDATA[21] = 0x02;
    RDATA[22] = 0x3A;
    LL = 23;
    break;

  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  return 0;
}
