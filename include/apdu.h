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
  uint8_t extended;
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
#define APDU_CHAINING_ERROR 0x04

typedef struct {
  CAPDU capdu;
  uint8_t in_chaining;
} CAPDU_CHAINING;

typedef struct {
  RAPDU rapdu;
  uint16_t sent;
} RAPDU_CHAINING;

typedef int (*APDU_MESSAGE_HANDLER)(const CAPDU *capdu, RAPDU *rapdu);
typedef int (*APDU_RESPONSE_SOURCE_READ)(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len);
typedef void (*APDU_RESPONSE_SOURCE_CLOSE)(void *ctx);

extern uint8_t *shared_io_buffer;

enum {
  BUFFER_OWNER_NONE,
  BUFFER_OWNER_CCID,
  BUFFER_OWNER_WEBUSB,
  BUFFER_OWNER_USBD, // store USB descriptors during a control transfer
  BUFFER_OWNER_CTAPHID,
};

void init_apdu_buffer(void);
int acquire_apdu_buffer(uint8_t owner);
int release_apdu_buffer(uint8_t owner);

int build_capdu(CAPDU *capdu, const uint8_t *cmd, uint16_t len);
int apdu_input(CAPDU_CHAINING *ex, const CAPDU *sh);
int apdu_output(RAPDU_CHAINING *ex, RAPDU *sh);
uint8_t apdu_is_get_response(const CAPDU *capdu);
int apdu_process_streaming_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu, uint8_t is_get_response,
                                   uint16_t le_limit, APDU_MESSAGE_HANDLER handler);
void apdu_response_source_set(uint32_t total_len, uint16_t sw, APDU_RESPONSE_SOURCE_READ read,
                              APDU_RESPONSE_SOURCE_CLOSE close, void *ctx);
void apdu_response_source_clear(void);
int apdu_response_source_active(void);
int apdu_session_can_preempt(void);
// Releases any in-flight FIDO chained-APDU reassembly state (PKE staging,
// chaining flags, accumulator). Call from any path that drops the CTAP
// session out from under an in-progress chain (e.g. session expiry).
void apdu_fido_chain_reset(void);
int acquire_apdu_interface(uint8_t session_owner, uint8_t buffer_owner);
void release_apdu_interface(uint8_t session_owner, uint8_t buffer_owner);
typedef enum {
  APDU_TRANSPORT_CCID,
  APDU_TRANSPORT_WEBUSB,
  APDU_TRANSPORT_NFC,
  APDU_TRANSPORT_HID,
} apdu_transport_t;

void process_apdu_from(CAPDU *capdu, RAPDU *rapdu, apdu_transport_t transport);
void process_apdu(CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE__APDU_H
