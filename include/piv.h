/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_PIV_H_
#define CANOKEY_CORE_INCLUDE_PIV_H_

#include <apdu.h>

#define PIV_INS_VERIFY                       0x20
#define PIV_INS_CHANGE_REFERENCE_DATA        0x24
#define PIV_INS_RESET_RETRY_COUNTER          0x2C
#define PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR 0x47
#define PIV_INS_GENERAL_AUTHENTICATE         0x87
#define PIV_INS_SELECT                       0xA4
#define PIV_INS_GET_DATA_RESPONSE            0xC0
#define PIV_INS_GET_DATA                     0xCB
#define PIV_INS_PUT_DATA                     0xDB
#define PIV_INS_GET_METADATA                 0xF7
#define PIV_INS_GET_SERIAL                   0xF8
#define PIV_INS_RESET                        0xFB
#define PIV_INS_GET_VERSION                  0xFD
#define PIV_INS_IMPORT_ASYMMETRIC_KEY        0xFE
#define PIV_INS_SET_MANAGEMENT_KEY           0xFF

#define PIV_INS_ALGORITHM_EXTENSION          0xEE

typedef struct {
  uint8_t enabled;
  uint8_t ed25519;
  uint8_t rsa3072;
  uint8_t rsa4096;
  uint8_t x25519;
  uint8_t secp256k1;
  uint8_t sm2;
} __packed piv_algorithm_extension_config_t;

int piv_install(uint8_t reset);
void piv_poweroff(void);
int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_INCLUDE_PIV_H_
