// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <ndef.h>

#define CC_FILE "E103" // file identifier also 0xE103
#define NDEF_FILE "NDEF"
#define NDEF_MSG_MAX_LENGTH 1022
#define NDEF_FILE_MAX_LENGTH (NDEF_MSG_MAX_LENGTH + 2)
#define CC_LENGTH 15

static uint8_t current_cc[CC_LENGTH];
static const uint8_t default_cc[CC_LENGTH] = {
    0x00, 0x0F,                                         // len
    0x20,                                               // version, 2.0
    HI(NDEF_FILE_MAX_LENGTH), LO(NDEF_FILE_MAX_LENGTH), // mle
    HI(NDEF_FILE_MAX_LENGTH), LO(NDEF_FILE_MAX_LENGTH), // mlc
    // the following are tlv data
    0x04,                                               // t
    0x06,                                               // l
    0x00, 0x01,                                         // file id
    HI(NDEF_FILE_MAX_LENGTH), LO(NDEF_FILE_MAX_LENGTH), // max_size
    0x00,                                               // read access without any security
    0x00                                                // write access without any security
};

#define CC_R (current_cc[13])
#define CC_W (current_cc[14])

static enum { NONE, CC, NDEF } selected;

void ndef_poweroff(void) { selected = NONE; }

int ndef_get_read_only(void) {
  return CC_W == 0xFF ? 1 : 0;
}

int ndef_toggle_read_only(const CAPDU *capdu, RAPDU *rapdu) {
  switch (P1) {
  case 0x00: // read and write
    CC_W = 0x00;
    break;
  case 0x01: // read only
    CC_W = 0xFF;
    break;
  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  if (write_file(CC_FILE, &current_cc, 0, sizeof(current_cc), 1) < 0) return -1;
  return 0;
}

int ndef_create_init_ndef() {
  const char *init_data = "\x00\x11\xD1\x01\x0D\x55\x04""canokeys.org";
  if (write_file(NDEF_FILE, init_data, 0, 19, 1) < -1) return -1;
  if (truncate_file(NDEF_FILE, NDEF_FILE_MAX_LENGTH) < -1) return -1; // Fill the file with zeros
  return 0;
}

int ndef_install(const uint8_t reset) {
  ndef_poweroff();
  if (reset || get_file_size(CC_FILE) != sizeof(current_cc) || get_file_size(NDEF_FILE) <= 0) {
    memcpy(current_cc, default_cc, sizeof(current_cc));
    if (ndef_create_init_ndef() < 0) return -1;
    if (write_file(CC_FILE, &current_cc, 0, sizeof(current_cc), 1) < 0) return -1;
  } else {
    if (read_file(CC_FILE, &current_cc, 0, sizeof(current_cc)) < 0) return -1;
    // should check sanity, by standard
  }
  return 0;
}

int ndef_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 == 0x04 && P2 == 0x00) return 0;
  if (P1 != 0x00 || P2 != 0x0C) EXCEPT(SW_WRONG_P1P2);
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] == 0xE1 && DATA[1] == 0x03)
    selected = CC;
  else if (DATA[0] == 0x00 && DATA[1] == 0x01)
    selected = NDEF;
  else
    EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

int ndef_read_binary(const CAPDU *capdu, RAPDU *rapdu) {
  const uint16_t offset = (uint16_t)(P1 << 8) | P2;
  if (offset > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);
  if (LE > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);

  switch (selected) {
  case CC:
    if (offset + LE > CC_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (read_file(CC_FILE, RDATA, offset, LE) < 0) return -1;
    LL = LE;
    break;
  case NDEF:
    if (CC_R != 0x00) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (offset + LE > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (read_file(NDEF_FILE, RDATA, offset, LE) < 0) return -1;
    LL = LE;
    break;
  case NONE:
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  }
  return 0;
}

int ndef_update(const CAPDU *capdu, RAPDU *rapdu) {
  const uint16_t offset = (uint16_t)(P1 << 8) | P2;
  if (offset > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);
  if (LC > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);

  switch (selected) {
  case CC:
    // do not allow change CC, only modified via admin
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  case NDEF:
    if (CC_W != 0x00) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (offset + LC > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (write_file(NDEF_FILE, DATA, offset, LC, 0) < 0) return -1;
    break;
  case NONE:
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  }
  return 0;
}

int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  int ret;
  switch (INS) {
  case NDEF_INS_SELECT:
    ret = ndef_select(capdu, rapdu);
    break;
  case NDEF_INS_READ_BINARY:
    ret = ndef_read_binary(capdu, rapdu);
    break;
  case NDEF_INS_UPDATE:
    ret = ndef_update(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
