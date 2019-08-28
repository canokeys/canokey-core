#ifndef CANOKEY_CORE_OATH_OATH_H_
#define CANOKEY_CORE_OATH_OATH_H_

#include <apdu.h>

#define OATH_TAG_NAME 0x71
#define OATH_TAG_NAME_LIST 0x72
#define OATH_TAG_KEY 0x73
#define OATH_TAG_CHALLENGE 0x74
#define OATH_TAG_RESPONSE 0x76

#define OATH_INS_PUT 0x01
#define OATH_INS_DELETE 0x02
#define OATH_INS_LIST 0x03
#define OATH_INS_CALCULATE 0x04
#define OATH_INS_CALCULATE_ALL 0x05
#define OATH_INS_SEND_REMAINING 0x06

#define OATH_ALG_MASK 0x0F
#define OATH_ALG_SHA1 0x01
#define OATH_ALG_SHA256 0x02

#define OATH_TYPE_MASK 0xF0
#define OATH_TYPE_TOTP 0x20

int oath_install(uint8_t reset);
int oath_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_OATH_OATH_H_
