#ifndef CANOKEY_CORE_ADMIN_ADMIN_H_
#define CANOKEY_CORE_ADMIN_ADMIN_H_

#include <apdu.h>

#define ADMIN_INS_WRITE_FIDO_PRIVATE_KEY 0x01
#define ADMIN_INS_WRITE_FIDO_CERT 0x02
#define ADMIN_INS_RESET_OPENPGP 0x03
#define ADMIN_INS_RESET_PIV 0x04
#define ADMIN_INS_RESET_OATH 0x05
#define ADMIN_INS_VERIFY 0x20
#define ADMIN_INS_CHANGE_PIN 0x21
#define ADMIN_INS_WRITE_SN 0x30
#define ADMIN_INS_SELECT 0xA4
#define ADMIN_INS_VENDOR_SPECIFIC 0xFF

void admin_poweroff(void);
int admin_install(void);
int admin_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_specific(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_ADMIN_ADMIN_H_
