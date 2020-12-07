/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_NDEF_H
#define CANOKEY_CORE_INCLUDE_NDEF_H

#include <apdu.h>

typedef struct {
  uint8_t t;
  uint8_t l;
  // the following are v of tlv
  uint16_t id;
  uint16_t max_size;
  uint8_t r;
  uint8_t w;
} ndef_tlv_t;

typedef struct {
  uint16_t len;
  uint8_t ver;
  uint16_t mle;
  uint16_t mlc;
  ndef_tlv_t tlv;
} ndef_cc_t;

void ndef_poweroff(void);
int ndef_install(uint8_t reset);
int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_INCLUDE_NDEF_H
