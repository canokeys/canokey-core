// SPDX-License-Identifier: Apache-2.0
#include <ndef.h>

#if ENABLE_NFC

#include <common.h>

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
static int16_t ndef_write_remaining = -1;
static uint16_t ndef_write_offset;

typedef struct {
  const char *path;
  uint16_t offset;
} ndef_response_source_t;

static ndef_response_source_t ndef_response_source;

static void ndef_write_reset(void) {
  ndef_write_remaining = -1;
  ndef_write_offset = 0;
}

static int ndef_response_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  const ndef_response_source_t *source = (const ndef_response_source_t *)ctx;
  return read_file(source->path, buf, source->offset + (uint16_t)offset, len);
}

void ndef_poweroff(void) {
  selected = NONE;
  ndef_write_reset();
}

int ndef_is_read_only(void) { return CC_W == 0xFF ? 1 : 0; }

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
  const char *init_data = "\x00\x11\xD1\x01\x0D\x55\x04"
                          "canokeys.org";
  if (write_file(NDEF_FILE, init_data, 0, 19, 1) < 0) return -1;
  if (truncate_file(NDEF_FILE, NDEF_FILE_MAX_LENGTH) < 0) return -1; // Fill the file with zeros
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
  ndef_write_reset();
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
    if (LE > APDU_COMMAND_BUFFER_SIZE) {
      ndef_response_source.path = NDEF_FILE;
      ndef_response_source.offset = offset;
      apdu_response_source_set(LE, SW_NO_ERROR, ndef_response_source_read, NULL, &ndef_response_source);
      LL = 0;
    } else {
      if (read_file(NDEF_FILE, RDATA, offset, LE) < 0) return -1;
      LL = LE;
    }
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
    ndef_write_reset();
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  case NDEF:
    if (CC_W != 0x00) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (ndef_write_remaining < 0) {
      if (offset + LC > NDEF_FILE_MAX_LENGTH) EXCEPT(SW_WRONG_LENGTH);
      if (write_file(NDEF_FILE, DATA, offset, LC, 0) < 0) return -1;
      if ((CLA & 0x10) != 0) {
        ndef_write_offset = offset + LC;
        ndef_write_remaining = NDEF_FILE_MAX_LENGTH - ndef_write_offset;
      }
    } else {
      if (LC > ndef_write_remaining) {
        ndef_write_reset();
        EXCEPT(SW_WRONG_LENGTH);
      }
      if (write_file(NDEF_FILE, DATA, ndef_write_offset, LC, 0) < 0) return -1;
      ndef_write_offset += LC;
      ndef_write_remaining -= LC;
      if ((CLA & 0x10) == 0) ndef_write_reset();
    }
    break;
  case NONE:
    ndef_write_reset();
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  }
  return 0;
}

int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (INS != NDEF_INS_UPDATE) ndef_write_reset();

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

int ndef_process_apdu_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu) {
  return apdu_process_streaming_message(rapdu_chaining, capdu, rapdu, apdu_is_get_response(capdu), APDU_BUFFER_SIZE,
                                        ndef_process_apdu);
}

#endif // ENABLE_NFC
