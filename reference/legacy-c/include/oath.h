/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_OATH_OATH_H_
#define CANOKEY_CORE_OATH_OATH_H_

#include <apdu.h>

#define ATTR_KEY 0x02
#define ATTR_HANDLE 0x03

#define OATH_TAG_NAME 0x71
#define OATH_TAG_NAME_LIST 0x72
#define OATH_TAG_KEY 0x73
#define OATH_TAG_CHALLENGE 0x74
#define OATH_TAG_FULL_RESPONSE 0x75
#define OATH_TAG_RESPONSE 0x76
#define OATH_TAG_NO_RESP 0x77
#define OATH_TAG_PROPERTY 0x78
#define OATH_TAG_VERSION 0x79
#define OATH_TAG_COUNTER 0x7A
#define OATH_TAG_ALGORITHM 0x7B
#define OATH_TAG_REQ_TOUCH 0x7C

#define OATH_INS_PUT 0x01
#define OATH_INS_DELETE 0x02
#define OATH_INS_SET_CODE 0x03
#define OATH_INS_RENAME 0x05
#define OATH_INS_LIST 0xA1
#define OATH_INS_CALCULATE 0xA2
#define OATH_INS_VALIDATE 0xA3
#define OATH_INS_SELECT 0xA4
#define OATH_INS_SEND_REMAINING 0xA5
#define OATH_INS_SET_DEFAULT 0x55

#define OATH_ALG_MASK 0x0F
#define OATH_ALG_SHA1 0x01
#define OATH_ALG_SHA256 0x02
#define OATH_ALG_SHA512 0x03

#define OATH_TYPE_MASK 0xF0
#define OATH_TYPE_HOTP 0x10
#define OATH_TYPE_TOTP 0x20

#define OATH_PROP_INC 0x01
#define OATH_PROP_TOUCH 0x02
#define OATH_PROP_ALL_FLAGS 0x03 // OR of flags above

#define MAX_NAME_LEN 64
#define MAX_KEY_LEN 66 // 64 + 2 for algo & digits
#define MAX_CHALLENGE_LEN 8
#define HANDLE_LEN 8
#define KEY_LEN 16

typedef struct {
  uint8_t name_len;
  uint8_t name[MAX_NAME_LEN];
  uint8_t key_len;
  // Byte 0 is type(higher half)/algorithm(lower half).
  // Byte 1 is number of digits.
  // Remaining is the secret.
  uint8_t key[MAX_KEY_LEN];
  uint8_t prop;
  uint8_t challenge[MAX_CHALLENGE_LEN];
} __packed OATH_RECORD;

void oath_poweroff(void);
int oath_install(uint8_t reset);
int oath_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int oath_calculate_by_offset(size_t file_offset, uint8_t result[4]);

#endif // CANOKEY_CORE_OATH_OATH_H_
