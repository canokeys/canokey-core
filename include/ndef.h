/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_NDEF_H
#define CANOKEY_CORE_INCLUDE_NDEF_H

#include <apdu.h>

#define NDEF_INS_SELECT 0xA4
#define NDEF_INS_READ_BINARY 0xB0
#define NDEF_INS_UPDATE 0xD6

void ndef_poweroff(void);
int ndef_install(uint8_t reset);
int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int ndef_get_read_only(void);
int ndef_toggle_read_only(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_INCLUDE_NDEF_H
