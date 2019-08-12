#ifndef CANOKEY_CORE_INCLUDE_PIV_H_
#define CANOKEY_CORE_INCLUDE_PIV_H_

#include <apdu.h>

#define PIV_INS_SELECT 0xA4
#define PIV_INS_GET_DATA 0xCB
#define PIV_INS_VERIFY 0x20
#define PIV_INS_CHANGE_REFERENCE_DATA 0x24
#define PIV_INS_RESET_RETRY_COUNTER 0x2C
#define PIV_INS_GENERAL_AUTHENTICATE 0x87
#define PIV_INS_PUT_DATA 0xDB
#define PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR 0x47
#define PIV_INS_GET_RESPONSE 0xC0

#define PIV_INS_SET_MANAGEMENT_KEY 0xFF
#define PIV_INS_RESET 0xFB
#define PIV_INS_IMPORT_ASYMMETRIC_KEY 0xFE

int piv_install(void);
int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int piv_config(uint8_t *buf, uint16_t buffer_size);

#endif // CANOKEY_CORE_INCLUDE_PIV_H_
