/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _CCID_H_
#define _CCID_H_

#include <common.h>

#define ABDATA_SIZE (APDU_BUFFER_SIZE + 2)
#define SHORT_ABDATA_SIZE 8  /* Enough for most CCID messages except XfrBlock/Secure */
#define CCID_CMD_HEADER_SIZE 10
#define CCID_NUMBER_OF_SLOTS 1
#define TIME_EXTENSION_PERIOD 1500

typedef struct {
  uint8_t bMessageType; /* Offset = 0*/
  uint32_t dwLength;    /* Offset = 1, The length field (dwLength) is the length
                           of the message not including the 10-byte header.*/
  uint8_t bSlot;        /* Offset = 5*/
  uint8_t bSeq;         /* Offset = 6*/
  uint8_t bSpecific_0;  /* Offset = 7*/
  uint8_t bSpecific_1;  /* Offset = 8*/
  uint8_t bSpecific_2;  /* Offset = 9*/
  uint8_t abDataShort[SHORT_ABDATA_SIZE]; /* Offset = 10*/
} __packed ccid_bulkout_data_t;

typedef struct {
  uint8_t bMessageType;        /* Offset = 0*/
  uint32_t dwLength;           /* Offset = 1*/
  uint8_t bSlot;               /* Offset = 5, Same as Bulk-OUT message */
  uint8_t bSeq;                /* Offset = 6, Same as Bulk-OUT message */
  uint8_t bStatus;             /* Offset = 7, Slot status as defined in § 6.2.6*/
  uint8_t bError;              /* Offset = 8, Slot error  as defined in § 6.2.6*/
  uint8_t bSpecific;           /* Offset = 9*/
  uint8_t abData[ABDATA_SIZE]; /* Offset = 10*/
} __packed ccid_bulkin_data_t;

typedef struct {
  uint8_t bMessageType;        /* Offset = 0*/
  uint32_t dwLength;           /* Offset = 1*/
  uint8_t bSlot;               /* Offset = 5, Same as Bulk-OUT message */
  uint8_t bSeq;                /* Offset = 6, Same as Bulk-OUT message */
  uint8_t bStatus;             /* Offset = 7, Slot status as defined in § 6.2.6*/
  uint8_t bError;              /* Offset = 8, Slot error  as defined in § 6.2.6*/
  uint8_t bSpecific;           /* Offset = 9*/
  uint8_t abData[17];          /* Offset = 10*/
} __packed ccid_bulkin_short_t;

typedef struct {
  uint8_t bMessageType; /* Offset = 0*/
  uint32_t dwLength;    /* Offset = 1*/
  uint8_t bSlot;        /* Offset = 5, Same as Bulk-OUT message */
  uint8_t bSeq;         /* Offset = 6, Same as Bulk-OUT message */
  uint8_t bStatus;      /* Offset = 7, Slot status as defined in § 6.2.6*/
  uint8_t bError;       /* Offset = 8, Slot error  as defined in § 6.2.6*/
  uint8_t bSpecific;    /* Offset = 9*/
} __packed empty_ccid_bulkin_data_t;

/******************************************************************************/
/*  ERROR CODES for USB Bulk In Messages : bError                   */
/******************************************************************************/

#define SLOT_NO_ERROR 0x81
#define SLOTERROR_UNKNOWN 0x82

#define SLOTERROR_BAD_LENTGH 0x01
#define SLOTERROR_BAD_SLOT 0x05
#define SLOTERROR_BAD_POWERSELECT 0x07
#define SLOTERROR_BAD_PROTOCOLNUM 0x07
#define SLOTERROR_BAD_CLOCKCOMMAND 0x07
#define SLOTERROR_BAD_ABRFU_3B 0x07
#define SLOTERROR_BAD_BMCHANGES 0x07
#define SLOTERROR_BAD_BFUNCTION_MECHANICAL 0x07
#define SLOTERROR_BAD_ABRFU_2B 0x08
#define SLOTERROR_BAD_LEVELPARAMETER 0x08
#define SLOTERROR_BAD_FIDI 0x0A
#define SLOTERROR_BAD_T01CONVCHECKSUM 0x0B
#define SLOTERROR_BAD_GUARDTIME 0x0C
#define SLOTERROR_BAD_WAITINGINTEGER 0x0D
#define SLOTERROR_BAD_CLOCKSTOP 0x0E
#define SLOTERROR_BAD_IFSC 0x0F
#define SLOTERROR_BAD_NAD 0x10
#define SLOTERROR_BAD_DWLENGTH 0x08 /* Used in PC_to_RDR_XfrBlock*/

#define SLOTERROR_CMD_ABORTED 0xFF
#define SLOTERROR_ICC_MUTE 0xFE
#define SLOTERROR_XFR_PARITY_ERROR 0xFD
#define SLOTERROR_XFR_OVERRUN 0xFC
#define SLOTERROR_HW_ERROR 0xFB
#define SLOTERROR_BAD_ATR_TS 0xF8
#define SLOTERROR_BAD_ATR_TCK 0xF7
#define SLOTERROR_ICC_PROTOCOL_NOT_SUPPORTED 0xF6
#define SLOTERROR_ICC_CLASS_NOT_SUPPORTED 0xF5
#define SLOTERROR_PROCEDURE_BYTE_CONFLICT 0xF4
#define SLOTERROR_DEACTIVATED_PROTOCOL 0xF3
#define SLOTERROR_BUSY_WITH_AUTO_SEQUENCE 0xF2
#define SLOTERROR_PIN_TIMEOUT 0xF0
#define SLOTERROR_PIN_CANCELLED 0xEF
#define SLOTERROR_CMD_SLOT_BUSY 0xE0
#define SLOTERROR_CMD_NOT_SUPPORTED 0x00

#define BM_ICC_STATUS_MASK    0x03
#define BM_ICC_PRESENT_ACTIVE 0x00
#define BM_ICC_PRESENT_INACTIVE 0x01
#define BM_ICC_NO_ICC_PRESENT 0x02

#define BM_COMMAND_STATUS_OFFSET 0x06
#define BM_COMMAND_STATUS_NO_ERROR 0x00
#define BM_COMMAND_STATUS_FAILED (0x01 << BM_COMMAND_STATUS_OFFSET)
#define BM_COMMAND_STATUS_TIME_EXTN (0x02 << BM_COMMAND_STATUS_OFFSET)

#define LEN_RDR_TO_PC_SLOTSTATUS 10

typedef enum {
  CHK_PARAM_SLOT = 1,
  CHK_PARAM_DWLENGTH = (1 << 1),
  CHK_PARAM_abRFU2 = (1 << 2),
  CHK_PARAM_abRFU3 = (1 << 3),
  CHK_PARAM_CARD_PRESENT = (1 << 4),
  CHK_PARAM_ABORT = (1 << 5),
  CHK_ACTIVE_STATE = (1 << 6)
} ChkParam_t;

#define PC_TO_RDR_ICCPOWERON 0x62
#define PC_TO_RDR_ICCPOWEROFF 0x63
#define PC_TO_RDR_GETSLOTSTATUS 0x65
#define PC_TO_RDR_XFRBLOCK 0x6F
#define PC_TO_RDR_GETPARAMETERS 0x6C
#define PC_TO_RDR_RESETPARAMETERS 0x6D
#define PC_TO_RDR_SETPARAMETERS 0x61
#define PC_TO_RDR_ESCAPE 0x6B
#define PC_TO_RDR_ICCCLOCK 0x6E
#define PC_TO_RDR_T0APDU 0x6A
#define PC_TO_RDR_SECURE 0x69
#define PC_TO_RDR_MECHANICAL 0x71
#define PC_TO_RDR_ABORT 0x72
#define PC_TO_RDR_SETDATARATEANDCLOCKFREQUENCY 0x73

#define RDR_TO_PC_DATABLOCK 0x80
#define RDR_TO_PC_SLOTSTATUS 0x81
#define RDR_TO_PC_PARAMETERS 0x82
#define RDR_TO_PC_ESCAPE 0x83
#define RDR_TO_PC_DATARATEANDCLOCKFREQUENCY 0x84

uint8_t CCID_Init(void);
uint8_t CCID_OutEvent(uint8_t *data, uint8_t len);
void CCID_InFinished(uint8_t is_time_extension_request);
void CCID_Loop(void);
void CCID_TimeExtensionLoop(void);
uint8_t PC_to_RDR_XfrBlock(void); // Exported for test purposes
// void CCID_eject(void);
// void CCID_insert(void);

#endif //_CCID_H_
