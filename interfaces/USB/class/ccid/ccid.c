#include <admin.h>
#include <ccid.h>
#include <common.h>
#include <oath.h>
#include <openpgp.h>
#include <piv.h>
#include <usb_device.h>
#include <usbd_ccid.h>

#define CCID_UpdateCommandStatus(cmd_status, icc_status) bulkin_data[idx].bStatus = (cmd_status | icc_status)

static uint8_t CCID_CheckCommandParams(uint32_t param_type, uint8_t idx);

static const uint8_t atr[] = {0x3B, 0xFC, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x59, 0x75,
                              0x62, 0x69, 0x6B, 0x65, 0x79, 0x4E, 0x45, 0x4F, 0x72, 0x33, 0xE1};
static const uint8_t PIV_AID[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t OATH_AID[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01};
static const uint8_t ADMIN_AID[] = {0xF0, 0x00, 0x00, 0x00, 0x00};

static enum {
  APPLET_NULL,
  APPLET_PIV,
  APPLET_OATH,
  APPLET_ADMIN,
  APPLET_ENUM_END,
} current_applet;

static const uint8_t *const AID[] = {
    [APPLET_NULL] = NULL,
    [APPLET_PIV] = PIV_AID,
    [APPLET_OATH] = OATH_AID,
    [APPLET_ADMIN] = ADMIN_AID,
};

static const uint8_t AID_Size[] = {
    [APPLET_NULL] = 0,
    [APPLET_PIV] = sizeof(PIV_AID),
    [APPLET_OATH] = sizeof(OATH_AID),
    [APPLET_ADMIN] = sizeof(ADMIN_AID),
};

// We use a separate interface to deal with openpgp since it opens ICC exclusive
static ccid_bulkin_data_t bulkin_data[2];
static ccid_bulkout_data_t bulkout_data[2];
static uint16_t ab_data_length[2];
static volatile uint8_t bulkout_state[2];
static volatile uint8_t has_cmd[2];
static CAPDU apdu_cmd[2];
static RAPDU apdu_resp[2];
static uint8_t chaining_buffer[APDU_BUFFER_SIZE];
static CAPDU_CHAINING capdu_chaining = {
    .max_size = sizeof(chaining_buffer),
    .capdu.data = chaining_buffer,
};
static RAPDU_CHAINING rapdu_chaining = {
    .rapdu.data = chaining_buffer,
};

uint8_t CCID_Init(void) {
  current_applet = APPLET_NULL;
  bulkout_state[0] = CCID_STATE_IDLE;
  bulkout_state[1] = CCID_STATE_IDLE;
  has_cmd[0] = 0;
  has_cmd[1] = 0;
  bulkout_data[0].abData = bulkin_data[0].abData;
  bulkout_data[1].abData = bulkin_data[1].abData;
  apdu_cmd[0].data = bulkin_data[0].abData;
  apdu_cmd[1].data = bulkin_data[1].abData;
  apdu_resp[0].data = bulkin_data[0].abData;
  apdu_resp[1].data = bulkin_data[1].abData;
  return 0;
}

uint8_t CCID_OutEvent(uint8_t *data, uint8_t len, uint8_t idx) {
  switch (bulkout_state[idx]) {
  case CCID_STATE_IDLE:
    if (len == 0)
      bulkout_state[idx] = CCID_STATE_IDLE;
    else if (len >= CCID_CMD_HEADER_SIZE) {
      ab_data_length[idx] = len - CCID_CMD_HEADER_SIZE;
      memcpy(&bulkout_data[idx], data, CCID_CMD_HEADER_SIZE);
      memcpy(bulkout_data[idx].abData, data + CCID_CMD_HEADER_SIZE, ab_data_length[idx]);
      bulkout_data[idx].dwLength = letoh32(bulkout_data[idx].dwLength);
      bulkin_data[idx].bSlot = bulkout_data[idx].bSlot;
      bulkin_data[idx].bSeq = bulkout_data[idx].bSeq;
      if (ab_data_length[idx] == bulkout_data[idx].dwLength)
        has_cmd[idx] = 1;
      else if (ab_data_length[idx] < bulkout_data[idx].dwLength) {
        if (bulkout_data[idx].dwLength > ABDATA_SIZE)
          bulkout_state[idx] = CCID_STATE_IDLE;
        else
          bulkout_state[idx] = CCID_STATE_RECEIVE_DATA;
      } else
        bulkout_state[idx] = CCID_STATE_IDLE;
    }
    break;

  case CCID_STATE_RECEIVE_DATA:
    if (ab_data_length[idx] + len < bulkout_data[idx].dwLength) {
      memcpy(bulkout_data[idx].abData + ab_data_length[idx], data, len);
      ab_data_length[idx] += len;
    } else if (ab_data_length[idx] + len == bulkout_data[idx].dwLength) {
      memcpy(bulkout_data[idx].abData + ab_data_length[idx], data, len);
      bulkout_state[idx] = CCID_STATE_IDLE;
      has_cmd[idx] = 1;
    } else
      bulkout_state[idx] = CCID_STATE_IDLE;
  }
  return 0;
}

static void poweroff(uint8_t applet) {
  switch (applet) {
  case APPLET_PIV:
    piv_poweroff();
    break;
  case APPLET_OATH:
    oath_poweroff();
    break;
  case APPLET_ADMIN:
    admin_poweroff();
    break;
  default:
    break;
  }
}

/**
 * @brief  PC_to_RDR_IccPowerOn
 *         PC_TO_RDR_ICCPOWERON message execution, apply voltage and get ATR
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_IccPowerOn(uint8_t idx) {
  bulkin_data[idx].dwLength = 0;
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU2, idx);
  if (error != 0) return error;
  uint8_t voltage = bulkout_data[idx].bSpecific_0;
  if (voltage != 0x00) {
    CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
    return SLOTERROR_BAD_POWERSELECT;
  }
  memcpy(bulkin_data[idx].abData, atr, sizeof(atr));
  bulkin_data[idx].dwLength = sizeof(atr);
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_ACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_IccPowerOff
 *         Icc VCC is switched Off
 * @param  None
 * @retval uint8_t error: status of the command execution
 */
static uint8_t PC_to_RDR_IccPowerOff(uint8_t idx) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_abRFU3 | CHK_PARAM_DWLENGTH, idx);
  if (error != 0) return error;
  if (idx == IDX_OPENPGP)
    openpgp_poweroff();
  else
    poweroff(current_applet);
  CCID_UpdateCommandStatus(BM_COMMAND_STATUS_NO_ERROR, BM_ICC_PRESENT_INACTIVE);
  return SLOT_NO_ERROR;
}

/**
 * @brief  PC_to_RDR_GetSlotStatus
 *         Provides the Slot status to the host
 * @param  None
 * @retval uint8_t status of the command execution
 */
static uint8_t PC_to_RDR_GetSlotStatus(uint8_t idx) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU3, idx);
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
static uint8_t PC_to_RDR_XfrBlock(uint8_t idx) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_ACTIVE_STATE, idx);
  if (error != 0) return error;

  DBG_MSG("O[%s]: ", idx == 0 ? "c" : "g");
  PRINT_HEX(bulkout_data[idx].abData, bulkout_data[idx].dwLength);

  CAPDU *capdu = &apdu_cmd[idx];
  RAPDU *rapdu = &apdu_resp[idx];
  if (build_capdu(&apdu_cmd[idx], bulkout_data[idx].abData, bulkout_data[idx].dwLength) < 0) {
    // abandon malformed apdu
    LL = 0;
    SW = SW_CHECKING_ERROR;
    goto send_response;
  }
  if (idx == IDX_OPENPGP) {
    openpgp_process_apdu(capdu, rapdu);
  } else {
    int ret = apdu_input(&capdu_chaining, capdu);
    if (ret == APDU_CHAINING_NOT_LAST_BLOCK) {
      LL = 0;
      SW = SW_NO_ERROR;
    } else if (ret == APDU_CHAINING_LAST_BLOCK) {
      capdu = &capdu_chaining.capdu;
      if ((CLA == 0x80 || CLA == 0x00) && INS == 0xC0) { // GET RESPONSE
        apdu_output(&rapdu_chaining, rapdu);
        goto send_response;
      }
      rapdu_chaining.sent = 0;
      if (CLA == 0x00 && INS == 0xA4 && P1 == 0x04 && P2 == 0x00) {
        // deal with select
        uint8_t i;
        for (i = APPLET_NULL + 1; i != APPLET_ENUM_END; ++i) {
          if (LC >= AID_Size[i] && memcmp(DATA, AID[i], AID_Size[i]) == 0) {
            if (i != current_applet) poweroff(current_applet);
            current_applet = i;
            break;
          }
        }
        if (i == APPLET_ENUM_END) {
          LL = 0;
          SW = SW_FILE_NOT_FOUND;
        }
      }
      switch (current_applet) {
      case APPLET_PIV:
        piv_process_apdu(capdu, &rapdu_chaining.rapdu);
        rapdu->len = LE;
        apdu_output(&rapdu_chaining, rapdu);
        break;
      case APPLET_OATH:
        oath_process_apdu(capdu, rapdu);
        break;
      case APPLET_ADMIN:
        admin_process_apdu(capdu, rapdu);
        break;
      default:
        LL = 0;
        SW = SW_FILE_NOT_FOUND;
      }
    } else {
      LL = 0;
      SW = SW_CHECKING_ERROR;
    }
  }

send_response:
  bulkin_data[idx].dwLength = LL + 2;
  bulkin_data[idx].abData[LL] = HI(SW);
  bulkin_data[idx].abData[LL + 1] = LO(SW);
  DBG_MSG("I[%s]: ", idx == 0 ? "c" : "g");
  PRINT_HEX(bulkin_data[idx].abData, bulkin_data[idx].dwLength);
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
static uint8_t PC_to_RDR_GetParameters(uint8_t idx) {
  uint8_t error = CCID_CheckCommandParams(CHK_PARAM_SLOT | CHK_PARAM_DWLENGTH | CHK_PARAM_abRFU3, idx);
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
static void RDR_to_PC_DataBlock(uint8_t errorCode, uint8_t idx) {
  bulkin_data[idx].bMessageType = RDR_TO_PC_DATABLOCK;
  bulkin_data[idx].bError = errorCode;
  bulkin_data[idx].bSpecific = 0;
}

/**
 * @brief  RDR_to_PC_SlotStatus
 *         Provide the Slot status response to the host
 *          Response for PC_to_RDR_IccPowerOff
 *                PC_to_RDR_GetSlotStatus
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_SlotStatus(uint8_t errorCode, uint8_t idx) {
  bulkin_data[idx].bMessageType = RDR_TO_PC_SLOTSTATUS;
  bulkin_data[idx].dwLength = 0;
  bulkin_data[idx].bError = errorCode;
  bulkin_data[idx].bSpecific = 0;
}

/**
 * @brief  RDR_to_PC_Parameters
 *         Provide the data block response to the host
 *         Response for PC_to_RDR_GetParameters
 * @param  uint8_t errorCode: code to be returned to the host
 * @retval None
 */
static void RDR_to_PC_Parameters(uint8_t errorCode, uint8_t idx) {
  bulkin_data[idx].bMessageType = RDR_TO_PC_PARAMETERS;
  bulkin_data[idx].bError = errorCode;

  if (errorCode == SLOT_NO_ERROR)
    bulkin_data[idx].dwLength = 7;
  else
    bulkin_data[idx].dwLength = 0;

  bulkin_data[idx].abData[0] = 0x11;
  bulkin_data[idx].abData[1] = 0x10;
  bulkin_data[idx].abData[2] = 0x00;
  bulkin_data[idx].abData[3] = 0x15;
  bulkin_data[idx].abData[4] = 0x00;
  bulkin_data[idx].abData[5] = 0xFE;
  bulkin_data[idx].abData[6] = 0x00;

  bulkin_data[idx].bSpecific = 0x01;
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
static uint8_t CCID_CheckCommandParams(uint32_t param_type, uint8_t idx) {
  bulkin_data[idx].bStatus = BM_ICC_PRESENT_ACTIVE | BM_COMMAND_STATUS_NO_ERROR;
  uint32_t parameter = param_type;

  if (parameter & CHK_PARAM_SLOT) {
    if (bulkout_data[idx].bSlot >= CCID_NUMBER_OF_SLOTS) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_NO_ICC_PRESENT);
      return SLOTERROR_BAD_SLOT;
    }
  }

  if (parameter & CHK_PARAM_DWLENGTH) {
    if (bulkout_data[idx].dwLength != 0) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_LENTGH;
    }
  }

  if (parameter & CHK_PARAM_abRFU2) {
    if ((bulkout_data[idx].bSpecific_1 != 0) || (bulkout_data[idx].bSpecific_2 != 0)) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_ABRFU_2B;
    }
  }

  if (parameter & CHK_PARAM_abRFU3) {
    if ((bulkout_data[idx].bSpecific_0 != 0) || (bulkout_data[idx].bSpecific_1 != 0) ||
        (bulkout_data[idx].bSpecific_2 != 0)) {
      CCID_UpdateCommandStatus(BM_COMMAND_STATUS_FAILED, BM_ICC_PRESENT_ACTIVE);
      return SLOTERROR_BAD_ABRFU_3B;
    }
  }

  return 0;
}

void CCID_Loop(void) {
  uint8_t idx = 0xFF;
  if (has_cmd[0]) {
    idx = 0;
    has_cmd[0] = 0;
  }
  if (has_cmd[1]) {
    idx = 1;
    has_cmd[1] = 0;
  }
  if (idx == 0xFF) return;

  uint8_t errorCode;
  switch (bulkout_data[idx].bMessageType) {
  case PC_TO_RDR_ICCPOWERON:
    DBG_MSG("Slot %s power on\n", idx == 0 ? "ccid" : "openpgp");
    errorCode = PC_to_RDR_IccPowerOn(idx);
    RDR_to_PC_DataBlock(errorCode, idx);
    break;
  case PC_TO_RDR_ICCPOWEROFF:
    DBG_MSG("Slot %s power off\n", idx == 0 ? "ccid" : "openpgp");
    errorCode = PC_to_RDR_IccPowerOff(idx);
    RDR_to_PC_SlotStatus(errorCode, idx);
    break;
  case PC_TO_RDR_GETSLOTSTATUS:
    DBG_MSG("Slot %s get status\n", idx == 0 ? "ccid" : "openpgp");
    errorCode = PC_to_RDR_GetSlotStatus(idx);
    RDR_to_PC_SlotStatus(errorCode, idx);
    break;
  case PC_TO_RDR_XFRBLOCK:
    errorCode = PC_to_RDR_XfrBlock(idx);
    RDR_to_PC_DataBlock(errorCode, idx);
    break;
  case PC_TO_RDR_GETPARAMETERS:
    DBG_MSG("Slot %s get param\n", idx == 0 ? "ccid" : "openpgp");
    errorCode = PC_to_RDR_GetParameters(idx);
    RDR_to_PC_Parameters(errorCode, idx);
    break;
  default:
    RDR_to_PC_SlotStatus(SLOTERROR_CMD_NOT_SUPPORTED, idx);
    break;
  }

  uint16_t len = bulkin_data[idx].dwLength;
  bulkin_data[idx].dwLength = htole32(bulkin_data[idx].dwLength);
  CCID_Response_SendData(&usb_device, (uint8_t *)&bulkin_data[idx], len + CCID_CMD_HEADER_SIZE, idx);
}
