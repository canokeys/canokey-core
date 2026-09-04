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

#define CCID_UpdateCommandStatus(cmd_status, icc_status)                                                               \
  bulkin_short.bStatus = bulkin_data.bStatus = (cmd_status | icc_status)
#define CCID_CardStatus() (bulkin_short.bStatus & BM_ICC_STATUS_MASK)
#define CCID_IsShortCommand() (bulkout_length <= SHORT_ABDATA_SIZE)

static uint8_t CCID_CheckCommandParams(uint32_t param_type);

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
static uint16_t ab_data_length;
static volatile uint8_t bulkout_state;
static volatile uint8_t has_cmd;
typedef enum {
  CCID_TRANSACTION_IDLE,
  CCID_TRANSACTION_RECEIVING,
  CCID_TRANSACTION_PROCESSING,
  CCID_TRANSACTION_RESPONDING,
} ccid_transaction_state_t;
static volatile ccid_transaction_state_t transaction_state;
static volatile uint32_t send_data_spinlock;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static uint8_t pke_fido_request;
static uint16_t pke_fido_payload_len;
static uint8_t pke_fido_has_le;
static uint8_t pke_fido_le[2];

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

void ccid_release_pke_request(void *ctx) {
  UNUSED(ctx);
  if (pke_fido_request) {
    pke_buffer_clear();
    pke_buffer_release(PKE_BUFFER_OWNER_CTAP);
  }
  pke_fido_request = 0;
  pke_fido_payload_len = 0;
  pke_fido_has_le = 0;
  memset(pke_fido_le, 0, sizeof(pke_fido_le));
  apdu_cmd.pke_backed = 0;
}

static void CCID_ResetPendingCommand(void) {
  ccid_release_pke_request(NULL);
  bulkout_state = CCID_STATE_IDLE;
  bulkout_length = 0;
  ab_data_length = 0;
  has_cmd = 0;
  release_apdu_buffer(BUFFER_OWNER_CCID);
  transaction_state = CCID_TRANSACTION_IDLE;
}

void CCID_AbortPendingCommand(void) {
  // A command being processed cannot be cancelled synchronously, and a queued
  // response still owns its backing buffer until the final Bulk-IN completes.
  if (transaction_state >= CCID_TRANSACTION_PROCESSING) return;
  CCID_ResetPendingCommand();
}

static int CCID_AppendPkeRequest(uint32_t offset, const uint8_t *data, uint16_t len) {
  const uint32_t end = offset + len;
  const uint32_t payload_start = 7;
  const uint32_t payload_end = payload_start + pke_fido_payload_len;

  if (end > payload_start && offset < payload_end) {
    const uint32_t copy_start = MAX(offset, payload_start);
    const uint32_t copy_end = MIN(end, payload_end);
    if (pke_buffer_write(copy_start - payload_start, data + copy_start - offset, copy_end - copy_start) < 0) return -1;
  }

  if (pke_fido_has_le) {
    for (uint32_t pos = payload_end; pos < payload_end + sizeof(pke_fido_le); ++pos) {
      if (pos >= offset && pos < end) pke_fido_le[pos - payload_end] = data[pos - offset];
    }
  }
  return 0;
}

static int CCID_BeginPkeRequest(const uint8_t *cmd, uint16_t len) {
  if (len < 7 || cmd[0] != 0x80 || cmd[1] != CTAP_INS_MSG || cmd[4] != 0) return -1;

  const uint16_t lc = (uint16_t)((cmd[5] << 8) | cmd[6]);
  if (lc == 0 || lc > pke_buffer_size()) return -1;
  if (bulkout_length != (uint32_t)7 + lc && bulkout_length != (uint32_t)9 + lc) return -1;
  if (pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP) < 0) return -1;
  if (pke_buffer_clear() < 0) {
    pke_buffer_release(PKE_BUFFER_OWNER_CTAP);
    return -1;
  }

  pke_fido_request = 1;
  pke_fido_payload_len = lc;
  pke_fido_has_le = bulkout_length == (uint32_t)9 + lc;
  apdu_cmd.data = shared_io_buffer;
  apdu_cmd.cla = cmd[0];
  apdu_cmd.ins = cmd[1];
  apdu_cmd.p1 = cmd[2];
  apdu_cmd.p2 = cmd[3];
  apdu_cmd.lc = lc;
  apdu_cmd.le = pke_fido_has_le ? 0 : 0x10000;
  apdu_cmd.extended = 1;
  apdu_cmd.pke_backed = 1;
  return CCID_AppendPkeRequest(0, cmd, len);
}

uint8_t CCID_Init(void) {
  CCID_ResetPendingCommand();
  send_data_spinlock = 0;
  bulkout_state = CCID_STATE_IDLE;
  has_cmd = 0;
  apdu_cmd.data = bulkin_data.abData;
  apdu_resp.data = bulkin_data.abData;
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_INACTIVE);
  return 0;
}

uint8_t CCID_OutEvent(uint8_t *data, uint8_t len) {
  uint8_t *abData = NULL;
  uint8_t pkeData = 0;
  switch (bulkout_state) {
  case CCID_STATE_IDLE:
    if (len == 0)
      bulkout_state = CCID_STATE_IDLE;
    else if (len >= CCID_CMD_HEADER_SIZE) {
      // The descriptor advertises one busy slot. Keep the command and response
      // storage immutable until the preceding response has left Bulk-IN.
      if (transaction_state != CCID_TRANSACTION_IDLE) break;
      transaction_state = CCID_TRANSACTION_RECEIVING;
      memcpy(&bulkout_data, data, CCID_CMD_HEADER_SIZE);
      bulkout_length = ccid_get_le32(bulkout_data.dwLength);
      bulkin_data.bSlot = bulkout_data.bSlot;
      bulkin_data.bSeq = bulkout_data.bSeq;
      bulkin_short.bSlot = bulkout_data.bSlot;
      bulkin_short.bSeq = bulkout_data.bSeq;
      ab_data_length = len - CCID_CMD_HEADER_SIZE;
      if (ab_data_length > bulkout_length)
        ab_data_length = bulkout_length; // abnormal packet received, truncate data

      if (bulkout_data.bMessageType == PC_TO_RDR_XFRBLOCK) {
        // always acquire the APDU buffer for XFRBLOCK, because the buffer is used during APDU process and response
        if (acquire_apdu_interface(DEVICE_APPLET_SESSION_CCID, BUFFER_OWNER_CCID) != 0) {
          DBG_MSG("Discard data because of applet session conflict\n");
        } else if (bulkout_length > ABDATA_SIZE) {
          if (bulkout_length <= CCID_MAX_XFR_BLOCK_SIZE &&
              CCID_BeginPkeRequest(data + CCID_CMD_HEADER_SIZE, ab_data_length) == 0) {
            pkeData = 1;
          } else {
            DBG_MSG("Discard oversized XfrBlock: %u\n", bulkout_length);
            ccid_release_pke_request(NULL);
            release_apdu_interface(DEVICE_APPLET_SESSION_CCID, BUFFER_OWNER_CCID);
          }
        } else {
          abData = CCID_IsShortCommand() ? bulkout_data.abDataShort : shared_io_buffer;
        }
      } else if (CCID_IsShortCommand()) {
        // abDataShort is large enough for most commands
        abData = bulkout_data.abDataShort;
      } else {
        // this should not happen
        ERR_MSG("Discard data of MSG %u\n", bulkout_data.bMessageType);
      }
      if (abData) memcpy(abData, data + CCID_CMD_HEADER_SIZE, ab_data_length);
      if (ab_data_length >= bulkout_length)
        has_cmd = (abData || pkeData) ? 1 : 2;
      else { // ab_data_length < bulkout_length
        bulkout_state = (abData || pkeData) ? CCID_STATE_RECEIVE_DATA : CCID_STATE_DISCARD_DATA;
      }
    }
    break;

  case CCID_STATE_RECEIVE_DATA:
    device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
    if (pke_fido_request) {
      if (ab_data_length + len > bulkout_length) len = bulkout_length - ab_data_length;
      if (CCID_AppendPkeRequest(ab_data_length, data, len) < 0) {
        ccid_release_pke_request(NULL);
        release_apdu_interface(DEVICE_APPLET_SESSION_CCID, BUFFER_OWNER_CCID);
        ab_data_length += len;
        if (ab_data_length >= bulkout_length) {
          bulkout_state = CCID_STATE_IDLE;
          has_cmd = HAS_CMD_DISCARDED;
        } else {
          bulkout_state = CCID_STATE_DISCARD_DATA;
        }
      } else {
        ab_data_length += len;
        if (ab_data_length >= bulkout_length) {
          bulkout_state = CCID_STATE_IDLE;
          has_cmd = 1;
        }
      }
      break;
    }
    abData = CCID_IsShortCommand() ? bulkout_data.abDataShort : shared_io_buffer;
    if (ab_data_length + len < bulkout_length) {
      memcpy(abData + ab_data_length, data, len);
      ab_data_length += len;
    } else {
      if (ab_data_length + len > bulkout_length)
        len = bulkout_length - ab_data_length; // abnormal packet received, truncate data
      memcpy(abData + ab_data_length, data, len);
      bulkout_state = CCID_STATE_IDLE;
      has_cmd = 1;
    }
    break;

  case CCID_STATE_DISCARD_DATA:
    if (ab_data_length + len < bulkout_length) {
      ab_data_length += len;
    } else {
      bulkout_state = CCID_STATE_IDLE;
      has_cmd = 2;
    }
    break;
  }
  return 0;
}

/**
 * @brief  PC_to_RDR_IccPowerOn
 *         PC_TO_RDR_ICCPOWERON message execution, apply voltage and get ATR
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_IccPowerOn(void) {
  ccid_put_le32(bulkin_short.dwLength, 0);
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU2);
  if (error != 0) return error;

  uint8_t voltage = bulkout_data.bSpecific_0;
  if (voltage != 0x00) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    return SLOTERROR_BAD_POWERSELECT;
  }

  if (device_applet_session_reset(DEVICE_APPLET_SESSION_CCID) != 0) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    return SLOTERROR_CMD_SLOT_BUSY;
  }

  _Static_assert(sizeof(bulkin_short.abData) >= sizeof(atr_ccid), "bulkin_short.abData is not large enough");
  memcpy(bulkin_short.abData, atr_ccid, sizeof(atr_ccid));
  ccid_put_le32(bulkin_short.dwLength, sizeof(atr_ccid));
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_IccPowerOff
 *         Icc VCC is switched Off
 * @param  None
 * @retval uint8_t error: status of the command execution
 */
static uint8_t PC_to_RDR_IccPowerOff(void) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_abRFU3 | CHK_PARAM_DWLENGTH);
  if (error != 0) return error;

  if (device_applet_session_reset(DEVICE_APPLET_SESSION_CCID) != 0) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
    return SLOTERROR_CMD_SLOT_BUSY;
  }

  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_INACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_GetSlotStatus
 *         Provides the Slot status to the host
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_GetSlotStatus(void) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU3);
  if (error != 0) return error;
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, CCID_CardStatus());
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_XfrBlock
 *         Handles the Block transfer from Host.
 *         Response to this command message is the RDR_to_PC_DataBlock
 * @param  None
 * @retval uint8_t status of the command execution
 */
uint8_t PC_to_RDR_XfrBlock(void) {
  uint8_t *abData = CCID_IsShortCommand() ? bulkout_data.abDataShort : shared_io_buffer;
  ccid_put_le32(bulkin_data.dwLength, 0);
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT);
  if (error != 0) return error;

  if (!pke_fido_request) {
    DBG_MSG("O: ");
    PRINT_HEX(abData, bulkout_length);
  }

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
  const uint8_t request_uses_pke = pke_fido_request;
  if (request_uses_pke && pke_fido_has_le) {
    apdu_cmd.le = (uint32_t)((pke_fido_le[0] << 8) | pke_fido_le[1]);
    if (apdu_cmd.le == 0) apdu_cmd.le = 0x10000;
  }
  if (!request_uses_pke && build_capdu(&apdu_cmd, abData, bulkout_length) < 0) {
    // abandon malformed apdu
    LL = 0;
    SW = SW_WRONG_LENGTH;
  } else {
    if (INS == OPENPGP_INS_IMPORT_KEY) {
      DBG_MSG("Import parsed: cla=%02X p1=%02X p2=%02X lc=%u data=%02X%02X%02X%02X\n", CLA, P1, P2, LC,
              LC > 0 ? DATA[0] : 0, LC > 1 ? DATA[1] : 0, LC > 2 ? DATA[2] : 0, LC > 3 ? DATA[3] : 0);
    }
    device_set_timeout(CCID_TimeExtensionLoop, TIME_EXTENSION_PERIOD);
    process_apdu_from(capdu, rapdu, APDU_TRANSPORT_CCID);
    device_set_timeout(NULL, 0);
    device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
  }
  if (request_uses_pke) ccid_release_pke_request(NULL);

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
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU3);
  if (error != 0) return error;
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, CCID_CardStatus());
  return SLOT_NO_ERROR;
}

/**
 * @brief  RDR_to_PC_DataBlock
 *         Provide the data block response to the host
 *         Response for PC_to_RDR_IccPowerOn, PC_to_RDR_XfrBlock
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_DataBlock(uint8_t errorCode, uint8_t isShort) {
  ccid_bulkin_data_t *pBulkin = &bulkin_data;
  if (isShort) pBulkin = (ccid_bulkin_data_t *)&bulkin_short;
  pBulkin->bMessageType = RDR_TO_PC_DATABLOCK;
  pBulkin->bError = errorCode;
  pBulkin->bSpecific = 0;
}

/**
 * @brief  RDR_to_PC_SlotStatus
 *         Provide the Slot status response to the host
 *          Response for PC_to_RDR_IccPowerOff
 *                PC_to_RDR_GetSlotStatus
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_SlotStatus(uint8_t errorCode) {
  bulkin_short.bMessageType = RDR_TO_PC_SLOTSTATUS;
  ccid_put_le32(bulkin_short.dwLength, 0);
  bulkin_short.bError = errorCode;
  bulkin_short.bSpecific = 0;
}

/**
 * @brief  RDR_to_PC_Parameters
 *         Provide the data block response to the host
 *         Response for PC_to_RDR_GetParameters
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_Parameters(uint8_t errorCode) {
  bulkin_short.bMessageType = RDR_TO_PC_PARAMETERS;
  bulkin_short.bError = errorCode;

  if (errorCode == SLOT_NO_ERROR)
    ccid_put_le32(bulkin_short.dwLength, 7);
  else
    ccid_put_le32(bulkin_short.dwLength, 0);

  bulkin_short.abData[0] = 0x11; // Fi=372, Di=1
  bulkin_short.abData[1] = 0x10; // Checksum: LRC, Convention: direct, ignored by CCID
  bulkin_short.abData[2] = 0x00; // No extra guard time
  bulkin_short.abData[3] = 0x15; // BWI = 1, CWI = 5
  bulkin_short.abData[4] = 0x00; // Stopping the Clock is not allowed
  bulkin_short.abData[5] = 0xFE; // IFSC = 0xFE
  bulkin_short.abData[6] = 0x00; // NAD

  bulkin_short.bSpecific = 0x01;
}

/**
 * @brief  RDR_to_PC_Escape
 *         Provide the Escape response to the host
 *          Response for PC_to_RDR_Escape
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_Escape(uint8_t errorCode) {
  bulkin_short.bMessageType = RDR_TO_PC_ESCAPE;
  ccid_put_le32(bulkin_short.dwLength, 0);
  bulkin_short.bError = errorCode;
  bulkin_short.bSpecific = 0;
}

/**
 * @brief  CCID_CheckCommandParams
 *         Checks the specific parameters requested by the function and update
 *          status accordingly. This function is called from all
 *          PC_to_RDR functions
 * @param  uint32_t param_type : Parameter enum to be checked by calling
 * function
 * @retval uint8_t status
 */
static uint8_t CCID_CheckCommandParams(uint32_t param_type) {
  uint32_t parameter = param_type;

  if (parameter & CHK_PARAM_SLOT) {
    if (bulkout_data.bSlot >= CCID_NUMBER_OF_SLOTS) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
      return SLOTERROR_BAD_SLOT;
    }
  }

  if (parameter & CHK_PARAM_DWLENGTH) {
    if (bulkout_length != 0) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
      return SLOTERROR_BAD_LENTGH;
    }
  }

  if (parameter & CHK_PARAM_abRFU2) {
    if ((bulkout_data.bSpecific_1 != 0) || (bulkout_data.bSpecific_2 != 0)) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
      return SLOTERROR_BAD_ABRFU_2B;
    }
  }

  if (parameter & CHK_PARAM_abRFU3) {
    if ((bulkout_data.bSpecific_0 != 0) || (bulkout_data.bSpecific_1 != 0) || (bulkout_data.bSpecific_2 != 0)) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, CCID_CardStatus());
      return SLOTERROR_BAD_ABRFU_3B;
    }
  }

  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, CCID_CardStatus());
  return 0;
}

void __attribute__((noinline)) CCID_Loop(void) {
  if (!has_cmd) return;
  transaction_state = CCID_TRANSACTION_PROCESSING;

  uint8_t errorCode;
  ccid_bulkin_data_t *pBulkin = (ccid_bulkin_data_t *)&bulkin_short;
  switch (bulkout_data.bMessageType) {
  case PC_TO_RDR_ICCPOWERON:
    DBG_MSG("Slot power on\n");
    errorCode = PC_to_RDR_IccPowerOn();
    RDR_to_PC_DataBlock(errorCode, 1);
    break;
  case PC_TO_RDR_ICCPOWEROFF:
    DBG_MSG("Slot power off\n");
    errorCode = PC_to_RDR_IccPowerOff();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_GETSLOTSTATUS:
    // DBG_MSG("Slot get status\n");
    errorCode = PC_to_RDR_GetSlotStatus();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_XFRBLOCK:
    if (has_cmd == HAS_CMD_DISCARDED) {
      DBG_MSG("Respond to a data-discarded message\n");
      ccid_put_le32(pBulkin->dwLength, 2);
      pBulkin->abData[0] = HI(SW_ERR_NOT_PERSIST);
      pBulkin->abData[1] = LO(SW_ERR_NOT_PERSIST);
      RDR_to_PC_DataBlock(SLOT_NO_ERROR, 1);
    } else {
      errorCode = PC_to_RDR_XfrBlock();
      RDR_to_PC_DataBlock(errorCode, 0);
      pBulkin = &bulkin_data;
    }
    break;
  case PC_TO_RDR_GETPARAMETERS:
    DBG_MSG("Slot get param\n");
    errorCode = PC_to_RDR_GetParameters();
    RDR_to_PC_Parameters(errorCode);
    break;
  case PC_TO_RDR_RESETPARAMETERS:
  case PC_TO_RDR_SETPARAMETERS:
    RDR_to_PC_Parameters(SLOTERROR_CMD_NOT_SUPPORTED);
    break;
  case PC_TO_RDR_ESCAPE:
    RDR_to_PC_Escape(SLOTERROR_CMD_NOT_SUPPORTED);
    break;
  case PC_TO_RDR_SECURE:
    ccid_put_le32(pBulkin->dwLength, 0);
    RDR_to_PC_DataBlock(SLOTERROR_CMD_NOT_SUPPORTED, 1);
    break;
  case PC_TO_RDR_ICCCLOCK:
  case PC_TO_RDR_T0APDU:
  case PC_TO_RDR_MECHANICAL:
  case PC_TO_RDR_ABORT:
  default:
    RDR_to_PC_SlotStatus(SLOTERROR_CMD_NOT_SUPPORTED);
    break;
  }

  const uint16_t len = (uint16_t)ccid_get_le32(pBulkin->dwLength);
  has_cmd = 0;
  transaction_state = CCID_TRANSACTION_RESPONDING;
  device_spinlock_lock(&send_data_spinlock, true);
  const uint8_t send_status = CCID_Response_SendData(&usb_device, (uint8_t *)pBulkin, len + CCID_CMD_HEADER_SIZE, 0);
  device_spinlock_unlock(&send_data_spinlock);
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

  if (device_spinlock_lock(&send_data_spinlock, false) == 0) { // try lock
    bulkin_time_extension.bMessageType = RDR_TO_PC_DATABLOCK;
    ccid_put_le32(bulkin_time_extension.dwLength, 0);
    bulkin_time_extension.bSlot = bulkout_data.bSlot;
    bulkin_time_extension.bSeq = bulkout_data.bSeq;
    bulkin_time_extension.bStatus = BM_COMMAND_STATUS_TIME_EXTN;
    bulkin_time_extension.bError = 1; // Request another 1 BTWs (5.7s)
    bulkin_time_extension.bSpecific = 0;
    CCID_Response_SendData(&usb_device, (uint8_t *)&bulkin_time_extension, CCID_CMD_HEADER_SIZE, 1);
    device_spinlock_unlock(&send_data_spinlock);
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
