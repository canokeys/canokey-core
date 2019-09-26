#ifndef CANOKEY_CORE__APDU_H
#define CANOKEY_CORE__APDU_H

#include <stdint.h>

typedef struct {
  uint8_t *data;
  uint8_t cla;
  uint8_t ins;
  uint8_t p1;
  uint8_t p2;
  uint32_t le; // Le can be 65536 bytes long as per ISO7816-3
  uint16_t lc;
} __attribute__((packed)) CAPDU;

typedef struct {
  uint8_t *data;
  uint32_t len;
  uint16_t sw;
} __attribute__((packed)) RAPDU;

// Command status responses

#define SW_NO_ERROR 0x9000
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
#define SW_PIN_RETRIES 0x63C0

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

#define EXCEPT(sw_code)                                                        \
  do {                                                                         \
    SW = sw_code;                                                              \
    return 0;                                                                  \
  } while (0)

void apdu_fill_with_command(CAPDU *capdu, char *cmd);
int build_capdu(CAPDU *capdu, const uint8_t *cmd, uint16_t len);

#endif // CANOKEY_CORE__APDU_H
