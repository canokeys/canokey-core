/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_NDEF_H
#define CANOKEY_CORE_INCLUDE_NDEF_H

#include <apdu.h>

void ndef_poweroff(void);
int ndef_install(uint8_t reset);
int ndef_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_INCLUDE_NDEF_H
