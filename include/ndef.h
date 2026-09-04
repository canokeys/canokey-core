/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_NDEF_H
#define CANOKEY_CORE_INCLUDE_NDEF_H

#include <apdu.h>
#include <nfc.h>

#define NDEF_INS_SELECT 0xA4
#define NDEF_INS_READ_BINARY 0xB0
#define NDEF_INS_UPDATE 0xD6

#if ENABLE_NFC
void ndef_poweroff(void);
int ndef_install(uint8_t reset);
int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int ndef_process_apdu_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu);
int ndef_is_read_only(void);
int ndef_toggle_read_only(const CAPDU *capdu, RAPDU *rapdu);
#else
static inline void ndef_poweroff(void) {}
static inline int ndef_install(uint8_t reset) {
  (void)reset;
  return 0;
}
static inline int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;
  (void)rapdu;
  return 0;
}
static inline int ndef_process_apdu_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu) {
  (void)rapdu_chaining;
  (void)capdu;
  (void)rapdu;
  return 0;
}
static inline int ndef_is_read_only(void) { return 0; }
static inline int ndef_toggle_read_only(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;
  (void)rapdu;
  return 0;
}
#endif

#endif // CANOKEY_CORE_INCLUDE_NDEF_H
