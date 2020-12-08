// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <memzero.h>
#include <udef.h>

//#define CC_FILE "E103" // file identifier also 0xE103
#define ATTR_CC 0xCC
#define NDEF_FILE "NDEF"

static const uint8_t init_cc[] = {
0x00, 0x0F, // len
0x20,// version, 2.0
0x00, 0x0F, // mle, default now, hareware info needed
0x00, 0x01, // mlc, default now, hardware info needed
// the following are tlv data
0x04, // t
0x06, // l
0x00, 0x01, // v, not determined now
0xFF, 0xFE, // max_size, not determined now
0x00, // read access without any security
0x00 // write access without any security
};

#define CC_R(cc) (cc[13])
#define CC_W(cc) (cc[14])

static ndef_cc_t current_cc[15];

static enum {NONE, CC, NDEF} selected;

void ndef_poweroff(void) {
  selected = NONE;
}

int ndef_create_init_ndef() {
  uint8_t empty[] = {0x00, 0x03, 0xD0, 0x00, 0x00}; // specified in Type 4 doc
  if (write_file(NDEF_FILE, empty, 0, sizeof(empty), 1) < -1) return -1;
  return 0;
}

int ndef_install(uint8_t reset) {
  ndef_poweroff();
  if (reset || get_file_size(CC_FILE) != sizeof(current_cc)
            || get_file_size(NDEF_FILE) <= 0) {
    current_cc = init_cc;
    if (write_attr(NDEF_FILE, ATTR_CC, &current_cc, sizeof(current_cc)) < 0) return -1;
    if (ndef_create_init_ndef() < 0) return -1;
  } else {
    if (read_attr(NDEF_FILE, ATTR_CC, &current_cc, sizeof(current_cc)) < 0) return -1;
    // should check sanity, by standard
  }
  return 0;
}

int ndef_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x0C) EXCEPT(SW_WRONG_P1P2);
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] == 0xE1 && DATA[1] == 0x03)
      selected = CC;
  else if (DATA[0] == 0x00 && DATA[1] == 0x01)
      selected = NDEF;
      // TODO: detect possible collision in file name
  else
      EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  int ret;
  switch (INS) {
  case NDEF_INS_SELECT:
    ndef_select(capdu, rapdu);
    break;
  case NDEF_INS_READ_BINARY:
    break;
  case NDEF_INS_UPDATE:
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
