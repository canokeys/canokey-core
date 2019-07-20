#ifndef CANOKEY_CORE_OPENPGP_OPENPGP_H
#define CANOKEY_CORE_OPENPGP_OPENPGP_H

#include <apdu.h>

#define OPENPGP_VERIFY 0x20
#define OPENPGP_CHANGE_REFERENCE_DATA 0x24
#define OPENPGP_RESET_RETRY_COUNTER 0x2C

int openpgp_initialize(void);
int openpgp_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_OPENPGP_OPENPGP_H
