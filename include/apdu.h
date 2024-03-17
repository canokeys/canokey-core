/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE__APDU_H
#define CANOKEY_CORE__APDU_H

#include "common.h"

typedef struct {
  uint8_t *data;
  uint8_t cla;
  uint8_t ins;
  uint8_t p1;
  uint8_t p2;
  uint32_t le; // Le can be 65536 bytes long as per ISO7816-3
  uint16_t lc;
} __packed CAPDU;

typedef struct {
  uint8_t *data;
  uint16_t len;
  uint16_t sw;
} __packed RAPDU;

// Command status responses

#define SW_NO_ERROR 0x9000
#define SW_TERMINATED 0x6285
#define SW_PIN_RETRIES 0x63C0
#define SW_ERR_NOT_PERSIST 0x6400
#define SW_ERR_PERSIST 0x6500
#define SW_WRONG_LENGTH 0x6700
#define SW_UNABLE_TO_PROCESS 0x6900
#define SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
#define SW_AUTHENTICATION_BLOCKED 0x6983
#define SW_DATA_INVALID 0x6984
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_COMMAND_NOT_ALLOWED 0x6986
#define SW_WRONG_DATA 0x6A80
#define SW_FILE_NOT_FOUND 0x6A82
#define SW_NOT_ENOUGH_SPACE 0x6A84
#define SW_WRONG_P1P2 0x6A86
#define SW_REFERENCE_DATA_NOT_FOUND 0x6A88
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_CHECKING_ERROR 0x6F00
#define SW_ERROR_WHILE_RECEIVING 0x6600

// Macros

#define CLA capdu->cla
#define INS capdu->ins
#define P1 capdu->p1
#define P2 capdu->p2
#define LC capdu->lc
#define LE capdu->le
#define DATA capdu->data
#define RDATA rapdu->data
#define SW rapdu->sw
#define LL rapdu->len

#define EXCEPT(sw_code)                                                                                                \
  do {                                                                                                                 \
    SW = sw_code;                                                                                                      \
    return 0;                                                                                                          \
  } while (0)

// Chainings

#define APDU_CHAINING_NOT_LAST_BLOCK 0x01
#define APDU_CHAINING_LAST_BLOCK 0x02
#define APDU_CHAINING_OVERFLOW 0x03

typedef struct {
  CAPDU capdu;
  uint8_t in_chaining;
} CAPDU_CHAINING;

typedef struct {
  RAPDU rapdu;
  uint16_t sent;
} RAPDU_CHAINING;

extern uint8_t *global_buffer;

enum {
  BUFFER_OWNER_NONE = 1,
  BUFFER_OWNER_CCID,
  BUFFER_OWNER_WEBUSB,
  BUFFER_OWNER_USBD, // store the configuration descriptor during a control transfer
};

void init_apdu_buffer(void); // implement in ccid.c for reusing the ccid buffer
int acquire_apdu_buffer(uint8_t owner);
int release_apdu_buffer(uint8_t owner);

int build_capdu(CAPDU *capdu, const uint8_t *cmd, uint16_t len);
int apdu_input(CAPDU_CHAINING *ex, const CAPDU *sh);
int apdu_output(RAPDU_CHAINING *ex, RAPDU *sh);
void process_apdu(CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE__APDU_H
