#include <ccid.h>
#include <common.h>
#include <openpgp.h>
#include <piv.h>
#include <u2f.h>
#include <usb_device.h>
#include <usbd_ccid.h>

#define CCID_UpdateCommandStatus(cmd_status, icc_status) bulkin_data.bStatus = (cmd_status | icc_status)

static const uint8_t atr[] = {0x3B, 0xFC, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x59, 0x75,
                              0x62, 0x69, 0x6B, 0x65, 0x79, 0x4E, 0x45, 0x4F, 0x72, 0x33, 0xE1};
static const uint8_t PIV_AID[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t OPENPGP_AID[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static const uint8_t FIDO2_AID[] = {0xA0, 0x00, 0x00, 0x05, 0x47, 0x2F, 0x00, 0x01};

enum {
  APPLET_NULL,
  APPLET_OPENPGP,
  APPLET_PIV,
  APPLET_U2F,
  APPLET_ENUM_END,
} current_applet;

static const uint8_t *const AID[] = {
    [APPLET_NULL] = NULL,
    [APPLET_OPENPGP] = OPENPGP_AID,
    [APPLET_PIV] = PIV_AID,
    [APPLET_U2F] = FIDO2_AID,
};

static const uint8_t AID_Size[] = {
    [APPLET_NULL] = 0,
    [APPLET_OPENPGP] = sizeof(OPENPGP_AID),
    [APPLET_PIV] = sizeof(PIV_AID),
    [APPLET_U2F] = sizeof(FIDO2_AID),
};

ccid_bulkin_data_t bulkin_data;
ccid_bulkout_data_t bulkout_data;
static uint16_t ab_data_length;
static uint8_t bulk_out_state;
static volatile uint8_t has_cmd;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

static uint8_t CCID_CheckCommandParams(uint32_t param_type);

uint8_t CCID_Init(void) {
  bulk_out_state = CCID_STATE_IDLE;
  has_cmd = 0;
  bulkout_data.abData = bulkin_data.abData;
  apdu_cmd.data = bulkin_data.abData;
  apdu_resp.data = bulkin_data.abData;
  current_applet = APPLET_NULL;
  return 0;
}

uint8_t CCID_OutEvent(uint8_t *data, uint8_t len) {
  switch (bulk_out_state) {
  case CCID_STATE_IDLE:
    if (len == 0)
      bulk_out_state = CCID_STATE_IDLE;
    else if (len >= CCID_CMD_HEADER_SIZE) {
      ab_data_length = len - CCID_CMD_HEADER_SIZE;
      memcpy(&bulkout_data, data, CCID_CMD_HEADER_SIZE);
      memcpy(bulkout_data.abData, data + CCID_CMD_HEADER_SIZE, ab_data_length);
      bulkout_data.dwLength = __builtin_bswap32(bulkout_data.dwLength);
      bulkin_data.bSlot = bulkout_data.bSlot;
      bulkin_data.bSeq = bulkout_data.bSeq;
      if (ab_data_length == bulkout_data.dwLength)
        has_cmd = 1;
      else if (ab_data_length < bulkout_data.dwLength) {
        if (bulkout_data.dwLength > ABDATA_SIZE)
          bulk_out_state = CCID_STATE_IDLE;
        else
          bulk_out_state = CCID_STATE_RECEIVE_DATA;
      } else
        bulk_out_state = CCID_STATE_IDLE;
    }
    break;

  case CCID_STATE_RECEIVE_DATA:
    if (ab_data_length + len < bulkout_data.dwLength) {
      memcpy(bulkout_data.abData + ab_data_length, data, len);
      ab_data_length += len;
    } else if (ab_data_length + len == bulkout_data.dwLength) {
      memcpy(bulkout_data.abData + ab_data_length, data, len);
      bulk_out_state = CCID_STATE_IDLE;
      has_cmd = 1;
    } else
      bulk_out_state = CCID_STATE_IDLE;
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
  bulkin_data.dwLength = 0;
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU2);
  if (error != 0) return error;
  uint8_t voltage = bulkout_data.bSpecific_0;
  if (voltage != 0x00) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
    return SLOTERROR_BAD_POWERSELECT;
  }
  current_applet = APPLET_NULL;
  memcpy(bulkin_data.abData, atr, sizeof(atr));
  bulkin_data.dwLength = sizeof(atr);
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
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_XfrBlock
 *         Handles the Block transfer from Host.
 *         Response to this command message is the RDR_to_PC_DataBlock
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_XfrBlock(void) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_ACTIVE_STATE);
  if (error != 0) return error;

  if (bulkout_data.dwLength > ABDATA_SIZE) return SLOTERROR_BAD_DWLENGTH;

  PRINT_HEX(bulkout_data.abData, bulkout_data.dwLength);
  if (build_capdu(&apdu_cmd, bulkout_data.abData, bulkout_data.dwLength) < 0) {
    bulkin_data.dwLength = 2;
    bulkin_data.abData[0] = 0x67;
    bulkin_data.abData[1] = 0x00;
    goto end;
  }
  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;
  if (CLA == 0x00 && INS == 0xA4 && P1 == 0x04 && P2 == 0x00) {
    uint8_t i;
    for (i = APPLET_NULL + 1; i != APPLET_ENUM_END; ++i) {
      if (LC >= AID_Size[i] && memcmp(DATA, AID[i], AID_Size[i]) == 0) {
        current_applet = i;
        break;
      }
    }
    if (i == APPLET_ENUM_END) {
      bulkin_data.dwLength = 2;
      bulkin_data.abData[0] = 0x6A;
      bulkin_data.abData[1] = 0x82;
      goto end;
    }
  }
  switch (current_applet) {
  case APPLET_OPENPGP:
    openpgp_process_apdu(capdu, rapdu);
    break;
  case APPLET_PIV:
    piv_process_apdu(capdu, rapdu);
    break;
  case APPLET_U2F:
    ctap_process_apdu(capdu, rapdu);
    break;
  default:
    LL = 0;
    SW = SW_COMMAND_NOT_ALLOWED;
  }
  bulkin_data.dwLength = LL + 2;
  bulkin_data.abData[LL] = HI(SW);
  bulkin_data.abData[LL + 1] = LO(SW);
  PRINT_HEX(bulkin_data.abData, bulkin_data.dwLength);

end:
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
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  RDR_to_PC_DataBlock
 *         Provide the data block response to the host
 *         Response for PC_to_RDR_IccPowerOn, PC_to_RDR_XfrBlock
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_DataBlock(uint8_t errorCode) {
  bulkin_data.bMessageType = RDR_TO_PC_DATABLOCK;
  bulkin_data.bError = errorCode;
  bulkin_data.bSpecific = 0;
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
  bulkin_data.bMessageType = RDR_TO_PC_SLOTSTATUS;
  bulkin_data.dwLength = 0;
  bulkin_data.bError = errorCode;
  bulkin_data.bSpecific = 0;
}

/**
 * @brief  RDR_to_PC_Parameters
 *         Provide the data block response to the host
 *         Response for PC_to_RDR_GetParameters
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_Parameters(uint8_t errorCode) {
  bulkin_data.bMessageType = RDR_TO_PC_PARAMETERS;
  bulkin_data.bError = errorCode;

  if (errorCode == SLOT_NO_ERROR)
    bulkin_data.dwLength = 7;
  else
    bulkin_data.dwLength = 0;

  bulkin_data.abData[0] = 0x11;
  bulkin_data.abData[1] = 0x10;
  bulkin_data.abData[2] = 0x00;
  bulkin_data.abData[3] = 0x15;
  bulkin_data.abData[4] = 0x00;
  bulkin_data.abData[5] = 0xFE;
  bulkin_data.abData[6] = 0x00;

  bulkin_data.bSpecific = 0x01;
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
  bulkin_data.bStatus = BM_ICC_PRESENT_ACTIVE | BM_COMMAND_STATUS_NO_ERROR;
  uint32_t parameter = param_type;

  if (parameter & CHK_PARAM_SLOT) {
    if (bulkout_data.bSlot >= CCID_NUMBER_OF_SLOTS) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_NO_ICC_PRESENT);
      return SLOTERROR_BAD_SLOT;
    }
  }

  if (parameter & CHK_PARAM_DWLENGTH) {
    if (bulkout_data.dwLength != 0) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_LENTGH;
    }
  }

  if (parameter & CHK_PARAM_abRFU2) {
    if ((bulkout_data.bSpecific_1 != 0) || (bulkout_data.bSpecific_2 != 0)) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_ABRFU_2B;
    }
  }

  if (parameter & CHK_PARAM_abRFU3) {
    if ((bulkout_data.bSpecific_0 != 0) || (bulkout_data.bSpecific_1 != 0) || (bulkout_data.bSpecific_2 != 0)) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_ABRFU_3B;
    }
  }

  return 0;
}

void CCID_Loop(void) {
  if (!has_cmd) return;
  has_cmd = 0;

  uint8_t errorCode;

  switch (bulkout_data.bMessageType) {
  case PC_TO_RDR_ICCPOWERON:
    errorCode = PC_to_RDR_IccPowerOn();
    RDR_to_PC_DataBlock(errorCode);
    break;
  case PC_TO_RDR_ICCPOWEROFF:
    errorCode = PC_to_RDR_IccPowerOff();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_GETSLOTSTATUS:
    errorCode = PC_to_RDR_GetSlotStatus();
    RDR_to_PC_SlotStatus(errorCode);
    break;
  case PC_TO_RDR_XFRBLOCK:
    errorCode = PC_to_RDR_XfrBlock();
    RDR_to_PC_DataBlock(errorCode);
    break;
  case PC_TO_RDR_GETPARAMETERS:
    errorCode = PC_to_RDR_GetParameters();
    RDR_to_PC_Parameters(errorCode);
    break;
  default:
    RDR_to_PC_SlotStatus(SLOTERROR_CMD_NOT_SUPPORTED);
    break;
  }

  uint16_t len = bulkin_data.dwLength;
  bulkin_data.dwLength = __builtin_bswap32(bulkin_data.dwLength);
  CCID_Response_SendData(&usb_device, (uint8_t *)&bulkin_data, len + CCID_CMD_HEADER_SIZE);
}
