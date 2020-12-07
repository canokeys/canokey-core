// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <memzero.h>
#include <udef.h>

//#define CC_FILE "E103" // file identifier also 0xE103
#define ATTR_CC 0xCC
#define NDEF_FILE "NDEF"

static const ndef_cc_t init_cc = {
.len = 0x000F,
.ver = 0x20,// 2.0
.mle = 0x000F, // default now, hareware info needed
.mlc = 0x0001, // default now, hardware info needed
.tlv = {
  .t = 0x04,
  .l = 0x06,
  .id = 0x0001, // not determined now
  .max_size = 0xFFFE, // not determined now
  .r = 0x00, // read access without any security
  .w = 0x00 // write access without any security
  }
};

static const ndef_cc_t current_cc;

void ndef_poweroff(void) {
}

int ndef_create_init_ndef() {
  return 0;
}

int ndef_install(uint8_t reset) {
  if (reset || get_file_size(CC_FILE) != sizeof(ndef_cc_t)
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

int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}
