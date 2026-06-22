// SPDX-License-Identifier: Apache-2.0
#include <apdu.h>
#include <applets.h>
#include <ccid.h>
#include <common.h>
#include <device.h>
#include <key.h>
#include <openpgp.h>
#include <usb_device.h>
#include <usbd_ccid.h>

#define HAS_CMD_DISCARDED 2

#define CCID_UpdateCommandStatus(cmd_status, icc_status)                                                               \
  bulkin_short.bStatus = bulkin_data.bStatus = (cmd_status | icc_status)
#define CCID_CardStatus() (bulkin_short.bStatus & BM_ICC_STATUS_MASK)
#define CCID_IsShortCommand() (bulkout_data.dwLength <= SHORT_ABDATA_SIZE)

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
static uint16_t ab_data_length;
static volatile uint8_t bulkout_state;
static volatile uint8_t has_cmd;
static volatile uint32_t send_data_spinlock;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
void ccid_init_apdu_buffer(void) { shared_io_buffer = bulkin_data.abData; }

uint8_t CCID_Init(void) {
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
  switch (bulkout_state) {
  case CCID_STATE_IDLE:
    if (len == 0)
      bulkout_state = CCID_STATE_IDLE;
    else if (len >= CCID_CMD_HEADER_SIZE) {
      memcpy(&bulkout_data, data, CCID_CMD_HEADER_SIZE);
      bulkout_data.dwLength = letoh32(bulkout_data.dwLength);
      bulkin_data.bSlot = bulkout_data.bSlot;
      bulkin_data.bSeq = bulkout_data.bSeq;
      bulkin_short.bSlot = bulkout_data.bSlot;
      bulkin_short.bSeq = bulkout_data.bSeq;
      ab_data_length = len - CCID_CMD_HEADER_SIZE;
      if (ab_data_length > bulkout_data.dwLength)
        ab_data_length = bulkout_data.dwLength; // abnormal packet received, truncate data

      if (bulkout_data.bMessageType == PC_TO_RDR_XFRBLOCK) {
        // always acquire the APDU buffer for XFRBLOCK, because the buffer is used during APDU process and response
        if (acquire_apdu_interface(DEVICE_APPLET_SESSION_CCID, BUFFER_OWNER_CCID) != 0) {
          DBG_MSG("Discard data because of applet session conflict\n");
        } else if (bulkout_data.dwLength > ABDATA_SIZE) {
          DBG_MSG("Discard oversized XfrBlock: %u\n", bulkout_data.dwLength);
          release_apdu_interface(DEVICE_APPLET_SESSION_CCID, BUFFER_OWNER_CCID);
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
      if (ab_data_length >= bulkout_data.dwLength)
        has_cmd = abData ? 1 : 2;
      else { // ab_data_length < bulkout_data.dwLength
        bulkout_state = abData ? CCID_STATE_RECEIVE_DATA : CCID_STATE_DISCARD_DATA;
      }
    }
    break;

  case CCID_STATE_RECEIVE_DATA:
    device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
    abData = CCID_IsShortCommand() ? bulkout_data.abDataShort : shared_io_buffer;
    if (ab_data_length + len < bulkout_data.dwLength) {
      memcpy(abData + ab_data_length, data, len);
      ab_data_length += len;
    } else {
      if (ab_data_length + len > bulkout_data.dwLength)
        len = bulkout_data.dwLength - ab_data_length; // abnormal packet received, truncate data
      memcpy(abData + ab_data_length, data, len);
      bulkout_state = CCID_STATE_IDLE;
      has_cmd = 1;
    }
    break;

  case CCID_STATE_DISCARD_DATA:
    if (ab_data_length + len < bulkout_data.dwLength) {
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
  bulkin_short.dwLength = 0;
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
  bulkin_short.dwLength = sizeof(atr_ccid);
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
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT);
  if (error != 0) return error;

  DBG_MSG("O: ");
  PRINT_HEX(abData, bulkout_data.dwLength);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  device_applet_session_touch(DEVICE_APPLET_SESSION_CCID);
  if (build_capdu(&apdu_cmd, abData, bulkout_data.dwLength) < 0) {
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
  }

  bulkin_data.dwLength = LL + 2;
  bulkin_data.abData[LL] = HI(SW);
  bulkin_data.abData[LL + 1] = LO(SW);
  DBG_MSG("I: ");
  PRINT_HEX(bulkin_data.abData, bulkin_data.dwLength);

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
  bulkin_short.dwLength = 0;
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
    bulkin_short.dwLength = 7;
  else
    bulkin_short.dwLength = 0;

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
  bulkin_short.dwLength = 0;
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
    if (bulkout_data.dwLength != 0) {
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

void CCID_Loop(void) {
  if (!has_cmd) return;

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
      pBulkin->dwLength = 2;
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
    pBulkin->dwLength = 0;
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

  uint16_t len = pBulkin->dwLength;
  pBulkin->dwLength = htole32(pBulkin->dwLength);
  device_spinlock_lock(&send_data_spinlock, true);
  const uint8_t send_status = CCID_Response_SendData(&usb_device, (uint8_t *)pBulkin, len + CCID_CMD_HEADER_SIZE, 0);
  device_spinlock_unlock(&send_data_spinlock);
  if (send_status != USBD_OK) {
    ERR_MSG("CCID send timeout: msg=%u len=%u status=%u\n", pBulkin->bMessageType, len, send_status);
    release_apdu_buffer(BUFFER_OWNER_CCID);
  }
  has_cmd = 0;
}

void CCID_InFinished(uint8_t is_time_extension_request) {
  if (is_time_extension_request) {
    return;
  }

  // Release the buffer after bulkin_data is transmitted
  // If the buffer has not been acquired by CCID, ownership is unchanged
  release_apdu_buffer(BUFFER_OWNER_CCID);
}

void CCID_TimeExtensionLoop(void) {
  if (device_spinlock_lock(&send_data_spinlock, false) == 0) { // try lock
    bulkin_time_extension.bMessageType = RDR_TO_PC_DATABLOCK;
    bulkin_time_extension.dwLength = 0;
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
