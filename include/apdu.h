#ifndef CANOKEY_CORE__APDU_H
#define CANOKEY_CORE__APDU_H

#include <stdint.h>

typedef struct {
  uint8_t cla;
  uint8_t ins;
  uint8_t p1;
  uint8_t p2;
  uint32_t le; // Le can be 65536 bytes long as per ISO7816-3
  uint16_t lc;
  uint8_t data[];
} __attribute__((packed)) CAPDU;

typedef struct {
  uint32_t len;
  uint16_t sw;
  uint8_t data[];
} __attribute__((packed)) RAPDU;

// Command status responses

#define SW_NO_ERROR 0x9000
#define SW_WRONG_DATA 0x6A80
#define SW_WRONG_P1P2 0x6A86
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_COMMAND_NOT_ALLOWED 0x6986
#define SW_INS_NOT_SUPPORTED 0x6D00
#define SW_CLA_NOT_SUPPORTED 0x6E00
#define SW_WRONG_LENGTH 0x6700

#endif //CANOKEY_CORE__APDU_H
