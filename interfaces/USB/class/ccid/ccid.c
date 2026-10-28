// SPDX-License-Identifier: Apache-2.0
#include <apdu.h>
#include <applets.h>
#include <ccid.h>
#include <common.h>
#include <ctap.h>
#include <device.h>
#include <key.h>
#include <openpgp.h>
#include <usb_device.h>
#include <usbd_ccid.h>

#define HAS_CMD_DISCARDED 2
#define HAS_CMD_BUSY 3

#define CCID_UpdateCommandStatus(cmd_status, icc_status)                                                               \
  (bulkin_data.bStatus = ((cmd_status) | (icc_status)))
#define CCID_CardStatus() (bulkin_data.bStatus & BM_ICC_STATUS_MASK)

static uint8_t CCID_CheckCommandParams(uint8_t rfu_bytes);
static void CCID_SendResponse(ccid_bulkin_data_t *response, uint8_t type, uint8_t error, uint8_t specific);

typedef union {
  empty_ccid_bulkin_data_t time_extension;
  ccid_bulkin_short_t short_resp;
} ccid_bulkin_ephemeral_t;

#define bulkin_time_extension (bulkin_ephemeral.time_extension)
#define bulkin_short (bulkin_ephemeral.short_resp)

// Fi=372, Di=1, 372 cycles/ETU 10752 bits/s at 4.00 MHz
// BWT = 5.7s
static const uint8_t atr_ccid[] = {0x3B, 0xF7, 0x11, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x65,
                                   0x43, 0x61, 0x6E, 0x6F, 0x6B, 0x65, 0x79, 0x99};

// Time-extension and short responses are both single-packet replies and never
// need to coexist, so they can share the same storage.
static ccid_bulkin_ephemeral_t bulkin_ephemeral;
ccid_bulkin_data_t bulkin_data;
ccid_bulkout_data_t bulkout_data;
static uint32_t bulkout_length;
static uint32_t ab_data_length;
static volatile uint8_t bulkout_state;
static volatile uint8_t has_cmd;
typedef enum {
  CCID_TRANSACTION_IDLE,
  CCID_TRANSACTION_RECEIVING,
  CCID_TRANSACTION_PROCESSING,
  CCID_TRANSACTION_RESPONDING,
} ccid_transaction_state_t;
static volatile ccid_transaction_state_t transaction_state;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

enum { AUX_IDLE, AUX_DRAINING, AUX_READY, AUX_SENDING };
// One independent, header-only reply. OUT is backpressured while this header
// is queued/in use; the native counter handles even a refused 32-bit length.
static struct {
  uint32_t remaining;
  volatile uint8_t state;
  empty_ccid_bulkin_data_t response;
} auxiliary;

static uint8_t CCID_ResponseType(uint8_t command) {
  // Response classes for 0x61..0x73; unsupported commands retain SlotStatus.
  static const uint8_t types[] = {2, 0, 1, 1, 1, 1, 1, 1, 0, 1, 3, 2, 2, 1, 0, 1, 1, 1, 4};
  const unsigned index = (unsigned)command - PC_TO_RDR_SETPARAMETERS;
  return index < sizeof(types) ? RDR_TO_PC_DATABLOCK + types[index] : RDR_TO_PC_SLOTSTATUS;
}

uint8_t CCID_CanReceive(void) { return auxiliary.state < AUX_READY; }

void CCID_AuxInFinished(void) { auxiliary.state = AUX_IDLE; }

static void CCID_ServiceAuxiliary(void) {
  if (auxiliary.state != AUX_READY) return;
  auxiliary.response.bStatus = BM_COMMAND_STATUS_FAILED |
      (auxiliary.response.bSlot ? BM_ICC_NO_ICC_PRESENT : CCID_CardStatus());
  // Publish SENDING before starting IN: a completion may interrupt the call.
  auxiliary.state = AUX_SENDING;
  const uint8_t ret = CCID_Response_SendData(&usb_device, (uint8_t *)&auxiliary.response,
                                            CCID_CMD_HEADER_SIZE, CCID_TX_AUXILIARY);
  if (ret != USBD_OK) auxiliary.state = AUX_READY;
}

static void CCID_DrainAuxiliary(uint8_t len) {
  if (auxiliary.remaining <= len)
    auxiliary.state = AUX_READY;
  else
    auxiliary.remaining -= len;
}

static void CCID_QueueAuxiliary(const uint8_t *data, uint8_t len) {
  const uint8_t command = data[0];
  const uint32_t length = ccid_get_le32(data + 1);
  empty_ccid_bulkin_data_t *response = &auxiliary.response;
  // dwLength/bSpecific stay zero for the lifetime of this header-only buffer.
  response->bSlot = data[5];
  response->bSeq = data[6];
  response->bMessageType = CCID_ResponseType(command);
  response->bError = data[5] >= CCID_NUMBER_OF_SLOTS ? SLOTERROR_BAD_SLOT : SLOTERROR_CMD_SLOT_BUSY;
  const uint8_t received = len - CCID_CMD_HEADER_SIZE;
  auxiliary.remaining = length > received ? length - received : 0;
  auxiliary.state = auxiliary.remaining ? AUX_DRAINING : AUX_READY;
}

uint32_t ccid_get_le32(const uint8_t value[4]) {
  return (uint32_t)value[0] | ((uint32_t)value[1] << 8u) | ((uint32_t)value[2] << 16u) |
         ((uint32_t)value[3] << 24u);
}

void ccid_put_le32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8u);
  out[2] = (uint8_t)(value >> 16u);
  out[3] = (uint8_t)(value >> 24u);
}

void ccid_set_bulkout_length(uint32_t length) {
  bulkout_length = length;
  ccid_put_le32(bulkout_data.dwLength, length);
}

void ccid_init_apdu_buffer(void) { shared_io_buffer = bulkin_data.abData; }

static void CCID_ResetPendingCommand(void) {
  bulkout_state = CCID_STATE_IDLE;
  has_cmd = 0;
  release_apdu_buffer(BUFFER_OWNER_CCID);
  transaction_state = CCID_TRANSACTION_IDLE;
}

void CCID_AbortPendingCommand(void) {
  // A command being processed cannot be cancelled synchronously, and a queued
  // response still owns its backing buffer until the final Bulk-IN completes.
  if (transaction_state >= CCID_TRANSACTION_PROCESSING) return;
  // Slot-management requests do not own applet state. In particular, losing a
  // queued GetSlotStatus when CTAPHID releases its session makes macOS treat
  // the reader timeout as card removal and restart PIV discovery/pairing.
  if (transaction_state == CCID_TRANSACTION_RECEIVING && bulkout_data.bMessageType != PC_TO_RDR_XFRBLOCK) return;
  // A refused XfrBlock owns no applet resources. Retain its sequence number
  // and drain any remaining OUT packets so it still gets an error response.
  if (has_cmd == HAS_CMD_DISCARDED || bulkout_state == CCID_STATE_DISCARD_DATA) return;
  CCID_ResetPendingCommand();
}

uint8_t CCID_Init(void) {
  memset(&auxiliary, 0, sizeof(auxiliary));
  CCID_ResetPendingCommand();
  apdu_cmd.data = bulkin_data.abData;
  apdu_resp.data = bulkin_data.abData;
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_INACTIVE);
  return 0;
}

uint8_t CCID_OutEvent(uint8_t *data, uint8_t len) {
  if (!CCID_CanReceive()) return USBD_BUSY;
  if (auxiliary.state == AUX_DRAINING) {
    CCID_DrainAuxiliary(len);
    return USBD_OK;
  }
  uint8_t *abData = NULL;
  switch (bulkout_state) {
  case CCID_STATE_IDLE:
    if (len >= CCID_CMD_HEADER_SIZE) {
      // The descriptor advertises one busy slot. Keep the command and response
      // storage immutable until the preceding response has left Bulk-IN.
      auxiliary.state = AUX_IDLE;
      if (transaction_state != CCID_TRANSACTION_IDLE) {
        CCID_QueueAuxiliary(data, len);
        break;
      }
      transaction_state = CCID_TRANSACTION_RECEIVING;
      memcpy(&bulkout_data, data, CCID_CMD_HEADER_SIZE);
      bulkout_length = ccid_get_le32(bulkout_data.dwLength);
      ab_data_length = len - CCID_CMD_HEADER_SIZE;
      if (ab_data_length > bulkout_length)
        ab_data_length = bulkout_length; // abnormal packet received, truncate data

      if (bulkout_data.bMessageType == PC_TO_RDR_XFRBLOCK) {
        // Reject before reserving shared state: a refused length must not
        // disturb another transport or an unfinished short APDU chain.
        if (bulkout_length > CCID_MAX_XFR_BLOCK_SIZE) {
          DBG_MSG("Discard oversized XfrBlock: %u\n", bulkout_length);
        } else if (acquire_apdu_interface(DEVICE_APPLET_SESSION_CCID, BUFFER_OWNER_CCID) != 0) {
          DBG_MSG("Discard data because of applet session conflict\n");
        } else {
          abData = shared_io_buffer;
        }
      }
      // Slot-management payloads are unused; drain without touching APDU RAM.
      if (abData) memcpy(abData, data + CCID_CMD_HEADER_SIZE, ab_data_length);
      if (ab_data_length >= bulkout_length)
        has_cmd = abData ? 1 : HAS_CMD_DISCARDED;
      else { // ab_data_length < bulkout_length
        bulkout_state = abData ? CCID_STATE_RECEIVE_DATA : CCID_STATE_DISCARD_DATA;
      }
    }
    break;

  case CCID_STATE_RECEIVE_DATA:
  case CCID_STATE_DISCARD_DATA:
    len = MIN(len, bulkout_length - ab_data_length);
    if (bulkout_state == CCID_STATE_RECEIVE_DATA) {
      memcpy(shared_io_buffer + ab_data_length, data, len);
    }
    // Both accepted and refused messages must consume their entire payload.
    ab_data_length += len;
    if (ab_data_length >= bulkout_length) {
      has_cmd = bulkout_state == CCID_STATE_RECEIVE_DATA ? 1 : HAS_CMD_DISCARDED;
      bulkout_state = CCID_STATE_IDLE;
    }
    break;
  }
  return 0;
}

// Power transitions share validation and the explicit card-context reset.
static uint8_t PC_to_RDR_IccPower(uint8_t on) {
  uint8_t error = CCID_CheckCommandParams(on ? 2 : 3);
  if (error != SLOT_NO_ERROR) return error;
  if (on && bulkout_data.bSpecific_0 != 0) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    return SLOTERROR_BAD_POWERSELECT;
  }
  if (device_applet_session_reset(DEVICE_APPLET_SESSION_CCID) != 0) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    return SLOTERROR_CMD_SLOT_BUSY;
  }
  if (on) {
    _Static_assert(sizeof(bulkin_short.abData) >= sizeof(atr_ccid), "bulkin_short.abData is not large enough");
    memcpy(bulkin_short.abData, atr_ccid, sizeof(atr_ccid));
    ccid_put_le32(bulkin_short.dwLength, sizeof(atr_ccid));
  }
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, on ? BM_ICC_PRESENT_ACTIVE : BM_ICC_PRESENT_INACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_GetSlotStatus
 *         Provides the Slot status to the host
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_GetSlotStatus(void) {
  return CCID_CheckCommandParams(3);
}

/**
 * @brief  PC_to_RDR_XfrBlock
 *         Handles the Block transfer from Host.
 *         Response to this command message is the RDR_to_PC_DataBlock
 * @param  None
 * @retval uint8_t status of the command execution
 */
uint8_t PC_to_RDR_XfrBlock(void) {
  uint8_t *abData = shared_io_buffer;
  ccid_put_le32(bulkin_data.dwLength, 0);
  uint8_t error = CCID_CheckCommandParams(0);
  if (error != SLOT_NO_ERROR) return error;

  // Also enforce the transport bound for callers bypassing Bulk-OUT.
  if (bulkout_length > CCID_MAX_XFR_BLOCK_SIZE) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    return SLOTERROR_BAD_LENTGH;
  }
  DBG_MSG("O: ");
  PRINT_HEX(abData, bulkout_length);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  if (build_capdu(capdu, abData, bulkout_length) < 0 || capdu->extended) {
    // Extended encodings are unsupported even when the payload is tiny.
    LL = 0;
    SW = SW_WRONG_LENGTH;
  } else {
    device_applet_session_prepare(DEVICE_APPLET_SESSION_CCID);
    device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
    if (INS == OPENPGP_INS_IMPORT_KEY) {
      DBG_MSG("Import parsed: cla=%02X p1=%02X p2=%02X lc=%u data=%02X%02X%02X%02X\n", CLA, P1, P2, LC,
              LC > 0 ? DATA[0] : 0, LC > 1 ? DATA[1] : 0, LC > 2 ? DATA[2] : 0, LC > 3 ? DATA[3] : 0);
    }
    device_set_timeout(CCID_TimeExtensionLoop, TIME_EXTENSION_PERIOD);
    process_apdu_from(capdu, rapdu, APDU_TRANSPORT_CCID);
    device_set_timeout(NULL, 0);
    device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
  }

  ccid_put_le32(bulkin_data.dwLength, LL + 2);
  bulkin_data.abData[LL] = HI(SW);
  bulkin_data.abData[LL + 1] = LO(SW);
  DBG_MSG("I: ");
  PRINT_HEX(bulkin_data.abData, LL + 2);

  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);

  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_GetParameters
 *         Provides the ICC parameters to the host
 *         Response to this command message is the RDR_to_PC_Parameters
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_GetParameters(void) {
  return CCID_CheckCommandParams(3);
}

/**
 * @brief  CCID_CheckCommandParams
 *         Checks the specific parameters requested by the function and update
 *          status accordingly. This function is called from all
 *          PC_to_RDR functions
 * @param  rfu_bytes: Number of RFU bytes for a zero-payload slot command;
 *         zero checks only the slot (XfrBlock).
 * @retval uint8_t status
 */
static uint8_t CCID_CheckCommandParams(uint8_t rfu_bytes) {
  uint8_t error = SLOT_NO_ERROR;
  if (bulkout_data.bSlot >= CCID_NUMBER_OF_SLOTS) {
    error = SLOTERROR_BAD_SLOT;
  } else if (rfu_bytes && bulkout_length != 0) {
    error = SLOTERROR_BAD_LENTGH;
  } else if (rfu_bytes && (bulkout_data.bSpecific_1 || bulkout_data.bSpecific_2 ||
                           (rfu_bytes == 3 && bulkout_data.bSpecific_0))) {
    error = rfu_bytes == 2 ? SLOTERROR_BAD_ABRFU_2B : SLOTERROR_BAD_ABRFU_3B;
  }
  CCID_UpdateCommandStatus(error == SLOT_NO_ERROR ? BM_COMMAND_STATUS_NO_ERROR : BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
  return error;
}

// Keep background smartcard discovery responsive during a HID presence wait.
// Never dispatch an APDU or reset the card here: both would clobber CTAP state.
// All replies use the independent short buffer, not the shared APDU payload.
void CCID_ServicePresencePoll(void) {
  USBD_CCID_ServiceReceive();
  CCID_ServiceAuxiliary();
  if (transaction_state != CCID_TRANSACTION_RECEIVING) return;
  if (!has_cmd) return;
  const uint8_t type = bulkout_data.bMessageType;
  if (type == PC_TO_RDR_XFRBLOCK && has_cmd != HAS_CMD_DISCARDED) return;
  if (type != PC_TO_RDR_XFRBLOCK && type != PC_TO_RDR_GETSLOTSTATUS && type != PC_TO_RDR_GETPARAMETERS)
    has_cmd = HAS_CMD_BUSY;
  CCID_Loop();
}

void __attribute__((noinline)) CCID_Loop(void) {
  USBD_CCID_ServiceReceive();
  if (!has_cmd || transaction_state != CCID_TRANSACTION_RECEIVING) {
    CCID_ServiceAuxiliary();
    return;
  }
  transaction_state = CCID_TRANSACTION_PROCESSING;

  uint8_t errorCode = SLOTERROR_CMD_NOT_SUPPORTED;
  uint8_t response_type = CCID_ResponseType(bulkout_data.bMessageType);
  uint8_t specific = 0;
  ccid_put_le32(bulkin_short.dwLength, 0);
  ccid_bulkin_data_t *pBulkin = (ccid_bulkin_data_t *)&bulkin_short;
  if (has_cmd == HAS_CMD_BUSY) {
    errorCode = SLOTERROR_CMD_SLOT_BUSY;
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    goto respond;
  }
  switch (bulkout_data.bMessageType) {
  case PC_TO_RDR_ICCPOWERON:
  case PC_TO_RDR_ICCPOWEROFF:
    DBG_MSG("Slot power transition\n");
    errorCode = PC_to_RDR_IccPower(bulkout_data.bMessageType == PC_TO_RDR_ICCPOWERON);
    break;
  case PC_TO_RDR_GETSLOTSTATUS:
    // DBG_MSG("Slot get status\n");
    errorCode = PC_to_RDR_GetSlotStatus();
    break;
  case PC_TO_RDR_XFRBLOCK:
    if (has_cmd == HAS_CMD_DISCARDED) {
      DBG_MSG("Respond to a data-discarded message\n");
      errorCode = CCID_CheckCommandParams(0);
      if (errorCode == SLOT_NO_ERROR && bulkout_length > CCID_MAX_XFR_BLOCK_SIZE) {
        errorCode = SLOTERROR_BAD_LENTGH;
        CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
      }
      if (errorCode == SLOT_NO_ERROR) {
        ccid_put_le32(pBulkin->dwLength, 2);
        pBulkin->abData[0] = HI(SW_ERR_NOT_PERSIST);
        pBulkin->abData[1] = LO(SW_ERR_NOT_PERSIST);
      }
    } else {
      errorCode = PC_to_RDR_XfrBlock();
      pBulkin = &bulkin_data;
    }
    break;
  case PC_TO_RDR_GETPARAMETERS:
    DBG_MSG("Slot get param\n");
    errorCode = PC_to_RDR_GetParameters();
    goto parameters;
  case PC_TO_RDR_RESETPARAMETERS:
  case PC_TO_RDR_SETPARAMETERS:
  parameters: {
    // T=1: Fi/Di, LRC/direct convention, guard time, BWI/CWI, clock stop, IFSC, NAD.
    static const uint8_t parameters[] = {0x11, 0x10, 0x00, 0x15, 0x00, 0xFE, 0x00};
    specific = 1;
    if (errorCode == SLOT_NO_ERROR) ccid_put_le32(bulkin_short.dwLength, sizeof(parameters));
    memcpy(bulkin_short.abData, parameters, sizeof(parameters));
    break;
  }
  case PC_TO_RDR_ESCAPE:
    break;
  case PC_TO_RDR_SECURE:
    break;
  case PC_TO_RDR_ICCCLOCK:
  case PC_TO_RDR_T0APDU:
  case PC_TO_RDR_MECHANICAL:
  case PC_TO_RDR_ABORT:
  default:
    break;
  }

respond:
  CCID_SendResponse(pBulkin, response_type, errorCode, specific);
}

static void CCID_SendResponse(ccid_bulkin_data_t *pBulkin, uint8_t response_type, uint8_t errorCode, uint8_t specific) {
  // All response types share the same header layout. Fill it once after
  // choosing the short or APDU backing buffer and command-specific payload.
  pBulkin->bMessageType = response_type;
  pBulkin->bSlot = bulkout_data.bSlot;
  pBulkin->bSeq = bulkout_data.bSeq;
  pBulkin->bStatus = bulkin_data.bStatus;
  pBulkin->bError = errorCode;
  pBulkin->bSpecific = specific;
  const uint16_t len = (uint16_t)ccid_get_le32(pBulkin->dwLength);
  has_cmd = 0;
  transaction_state = CCID_TRANSACTION_RESPONDING;
  const uint8_t send_status = CCID_Response_SendData(&usb_device, (uint8_t *)pBulkin, len + CCID_CMD_HEADER_SIZE, 0);
  if (send_status != USBD_OK) {
    ERR_MSG("CCID send timeout: msg=%u len=%u status=%u\n", pBulkin->bMessageType, len, send_status);
    CCID_ResetPendingCommand();
  }
}

void CCID_InFinished(uint8_t is_time_extension_request) {
  if (is_time_extension_request) {
    return;
  }

  // Release the buffer after bulkin_data is transmitted
  // If the buffer has not been acquired by CCID, ownership is unchanged
  release_apdu_buffer(BUFFER_OWNER_CCID);
  transaction_state = CCID_TRANSACTION_IDLE;
}

void CCID_TimeExtensionLoop(void) {
  device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);

  if (CCID_Response_IsIdle()) {
    memset(&bulkin_time_extension, 0, sizeof(bulkin_time_extension));
    bulkin_time_extension.bMessageType = RDR_TO_PC_DATABLOCK;
    bulkin_time_extension.bStatus = BM_COMMAND_STATUS_TIME_EXTN;
    bulkin_time_extension.bError = 1;
    bulkin_time_extension.bSlot = bulkout_data.bSlot;
    bulkin_time_extension.bSeq = bulkout_data.bSeq;
    CCID_Response_SendData(&usb_device, (uint8_t *)&bulkin_time_extension, CCID_CMD_HEADER_SIZE, CCID_TX_TIME_EXTENSION);
  }

  device_set_timeout(CCID_TimeExtensionLoop, TIME_EXTENSION_PERIOD);
}

// void CCID_eject(void) {
//   DBG_MSG("EJ\n");
//   CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_NO_ICC_PRESENT);
// }

// void CCID_insert(void) {
//   DBG_MSG("INS\n");
//   CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_INACTIVE);
// }
