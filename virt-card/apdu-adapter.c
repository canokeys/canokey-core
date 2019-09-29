#include "apdu-adapter.h"
#include "apdu.h"
#include "ctap.h"
#include "oath.h"
#include "openpgp.h"
#include "piv.h"
#include "common.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SHORT_LC 4
#define EXT_LC_0 4
#define EXT_LC_MSB 5
#define EXT_LC_LSB 6

enum {
  APPLET_NULL = 0,
  APPLET_FIDO,
  APPLET_OPENPGP,
  APPLET_OATH,
  APPLET_PIV,
  APPLET_ENUM_MAX
} current_applet;

static uint8_t cmd_chaining_buffer[APDU_BUFFER_SIZE], resp_chaining_buffer[APDU_BUFFER_SIZE];
CAPDU_CHAINING capdu_chaining = {
  .max_size = sizeof(cmd_chaining_buffer),
  .capdu.data = cmd_chaining_buffer,
};
RAPDU_CHAINING rapdu_chaining = {
  .rapdu.data = resp_chaining_buffer,
};

void select_u2f_from_hid(void) { current_applet = APPLET_FIDO; }

int virt_card_apdu_transceive(unsigned char *txBuf, unsigned long txLen, unsigned char *rxBuf, unsigned long *rxLen) {
  int ret;
  uint16_t Lc = 0, offData = 0;
  uint32_t Le = 254;
  bool extAPDU = false;
  bool selecting = false;
  if (txLen < 4) {
    printf("APDU too short\n");
    return -2;
  } else if (txLen == 4) {
    // Without Lc or Le
  } else if (txLen == 5) {
    // With Le
    Le = txBuf[SHORT_LC];
    if (Le == 0) Le = 0x100;
  } else if (txBuf[SHORT_LC] && txLen == 5 + txBuf[SHORT_LC]) {
    // With Lc
    Lc = txBuf[SHORT_LC];
    offData = SHORT_LC + 1;
  } else if (txBuf[SHORT_LC] && txLen == 6 + txBuf[SHORT_LC]) {
    // With Lc and Le
    Lc = txBuf[SHORT_LC];
    offData = SHORT_LC + 1;
    Le = txBuf[5 + Lc];
    if (Le == 0) Le = 0x100;
  } else if (txLen == 7) {
    // Without Lc
    if (txBuf[EXT_LC_0] != 0) {
      printf("Le prefix not zero\n");
      return -3;
    }
    Le = ((uint16_t)txBuf[EXT_LC_MSB] << 8) | txBuf[EXT_LC_LSB];
    if (Le == 0) Le = 0x10000;
    extAPDU = 1;
  } else if (txLen > 7) {
    // With Lc
    if (txBuf[EXT_LC_0] != 0) {
      printf("Lc prefix not zero\n");
      return -3;
    }
    Lc = ((uint16_t)txBuf[EXT_LC_MSB] << 8) | txBuf[EXT_LC_LSB];
    offData = EXT_LC_LSB + 1;
    if (txLen < 7 + Lc) {
      printf("Length %lu shorter than %hu+7\n", txLen, Lc);
      return -2;
    }
    if (txLen == 7 + Lc + 2) {
      // With Le
      Le = ((uint16_t)txBuf[7 + Lc] << 8) | txBuf[7 + Lc + 1];
      if (Le == 0) Le = 0x10000;
    } else if (txLen > 7 + Lc) {
      printf("incorrect APDU length %lu\n", txLen);
      return -2;
    }
    extAPDU = 1;
  } else {
    printf("Wrong length %lu\n", txLen);
    // return -2;
  }

  printf("Lc=%hu Le=%u\n", Lc, Le);

  if (*rxLen < Le + 2) {
    printf("RX Buffer is not large enough\n");
    if (*rxLen > 2) {
      Le = *rxLen - 2;
      printf("  set Le to %u\n", Le);
    } else
      return -1;
  }

  CAPDU c;
  RAPDU r = {.data = rxBuf, .len = Le};

  c.cla = txBuf[0];
  c.ins = txBuf[1];
  c.p1 = txBuf[2];
  c.p2 = txBuf[3];
  c.lc = Lc;
  c.le = Le;
  c.data = txBuf + offData;

  if((c.cla == 0x80 || c.cla == 0x00) && c.ins == 0xC0) {
    // GET RESPONSE
    ret = apdu_output(&rapdu_chaining, &r);
    goto return_result;
  } else {
    rapdu_chaining.rapdu.len = 0;
    rapdu_chaining.sent = 0;
  }

  ret = apdu_input(&capdu_chaining, &c);
  if(ret == APDU_CHAINING_NOT_LAST_BLOCK) {
    printf("chaining\n");
    r.sw = 0x9000;
    r.len = 0;
    ret = 0;
    goto return_result;
  } else if(ret == APDU_CHAINING_LAST_BLOCK) {
    // process apdu now
    c = capdu_chaining.capdu;
  } else {
    printf("apdu_input returned %d\n", ret);
    r.sw = 0x6F00;
    r.len = 0;
    ret = 0;
    goto return_result;
  }

  if (c.cla == 0x00 && c.ins == 0xA4 && c.p1 == 0x04 && c.p2 == 0x00) {
    selecting = true;
    if (c.lc == 8 && memcmp(c.data, "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8) == 0) {
      current_applet = APPLET_FIDO;
    } else if (c.lc >= 6 && memcmp(c.data, "\xD2\x76\x00\x01\x24\x01", 6) == 0) {
      current_applet = APPLET_OPENPGP;
    } else if (c.lc >= 5 && memcmp(c.data, "\xA0\x00\x00\x03\x08", 5) == 0) {
      current_applet = APPLET_PIV;
    } else if (c.lc >= 7 && memcmp(c.data, "\xa0\x00\x00\x05\x27\x21\x01", 7) == 0) {
      current_applet = APPLET_OATH;
    } else {
      // current_applet = APPLET_NULL;
      r.sw = 0x6A82;
      r.len = 0;
      ret = 0;
      goto return_result;
    }
  }

  rapdu_chaining.sent = 0;
  rapdu_chaining.rapdu.len = APDU_BUFFER_SIZE;
  c.le = APDU_BUFFER_SIZE;

  switch (current_applet) {
  default:
    printf("No applet selected yet\n");
    r.sw = 0x6F00;
    r.len = 0;
    ret = 0;
    break;
  case APPLET_OATH:
    if (selecting) {
      r.sw = 0x9000;
      r.len = 0;
      ret = 0;
    } else {
      printf("calling oath_process_apdu\n");
      ret = oath_process_apdu(&c, &r);
      printf("oath_process_apdu ret %d\n", ret);
    }
    break;
  case APPLET_FIDO:
    printf("calling ctap_process_apdu\n");
    if (c.cla == 0x00 && c.ins == 0xEE && c.lc == 0x04 && memcmp(c.data, "\x12\x56\xAB\xF0", 4) == 0) {
      printf("MAGIC REBOOT command recieved!\r\n");
      ctap_install(0);
      r.sw = 0x9000;
      r.len = 0;
      ret = 0;
    } else {
      printf("calling ctap_process_apdu\n");
      ret = ctap_process_apdu(&c, &rapdu_chaining.rapdu);
      printf("ctap_process_apdu ret %d\n", ret);
      printf("chaining.len=%hu r.len=%hu\n", rapdu_chaining.rapdu.len, r.len);
      ret = apdu_output(&rapdu_chaining, &r);
    }
    break;
  case APPLET_OPENPGP:
    printf("calling openpgp_process_apdu\n");
    ret = openpgp_process_apdu(&c, &r);
    printf("openpgp_process_apdu ret %d\n", ret);
    break;
  case APPLET_PIV:
    printf("calling piv_process_apdu\n");
    ret = piv_process_apdu(&c, &rapdu_chaining.rapdu);
    printf("piv_process_apdu ret %d\n", ret);
    printf("chaining.len=%hu r.len=%hu\n", rapdu_chaining.rapdu.len, r.len);
    ret = apdu_output(&rapdu_chaining, &r);
    break;
  }
return_result:
  if (ret == 0) {
    rxBuf[r.len] = 0xff & (r.sw >> 8);
    rxBuf[r.len + 1] = 0xff & r.sw;
    *rxLen = r.len + 2;
  }

  return ret;
}
