#include <admin.h>
#include <apdu.h>
#include <ccid.h>
#include <oath.h>
#include <openpgp.h>
#include <piv.h>
#include <webusb.h>

enum {
  STATE_IDLE,
  STATE_RECV_CMD,
  STATE_PROCESS,
  STATE_SEND_RESP,
};

static uint8_t expected_cmd_seq, state, apdu_buffer[APDU_BUFFER_SIZE];
static uint16_t apdu_buffer_size;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static enum APPLET current_applet;

uint8_t USBD_WEBUSB_Init(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  state = STATE_IDLE;
  apdu_buffer_size = 0;
  apdu_cmd.data = apdu_buffer;
  apdu_resp.data = apdu_buffer;
  current_applet = APPLET_NULL;

  return USBD_OK;
}

uint8_t USBD_WEBUSB_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  switch (req->bRequest) {
  case WEBUSB_REQ_CMD:
    if (state == STATE_IDLE && (req->wValue & WEBUSB_REQ_FIRST_PACKET)) {
      state = STATE_RECV_CMD;
      expected_cmd_seq = 0;
      apdu_buffer_size = 0;
    } else if (state == STATE_RECV_CMD && (req->wValue & WEBUSB_REQ_MORE_PACKET))
      ++expected_cmd_seq;
    else {
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    if ((req->wValue & 0xFF) != expected_cmd_seq) {
      ERR_MSG("Wrong seq\n");
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    if (apdu_buffer_size + req->wLength > APDU_BUFFER_SIZE) {
      ERR_MSG("Overflow\n");
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    USBD_CtlPrepareRx(pdev, apdu_buffer + apdu_buffer_size, req->wLength);
    apdu_buffer_size += req->wLength;
    break;

  case WEBUSB_REQ_CALC:
    if (state == STATE_IDLE) state = STATE_PROCESS;
    USBD_CtlSendData(pdev, NULL, 0, 0);
    break;

  case WEBUSB_REQ_RESP:
    if (state == STATE_PROCESS)
      USBD_CtlSendData(pdev, NULL, 0, 0);
    else if (state == STATE_SEND_RESP) {
      uint16_t len = MIN(apdu_buffer_size, req->wLength);
      USBD_CtlSendData(pdev, apdu_buffer, len, WEBUSB_EP0_SENDER);
    } else {
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    break;

  case WEBUSB_REQ_STAT:
    do {
      static uint8_t in_progress;
      in_progress = state == STATE_PROCESS;
      USBD_CtlSendData(pdev, &in_progress, 1, WEBUSB_EP0_SENDER);
    } while (0);
    break;
  }

  return USBD_OK;
}

void WebUSB_Loop(void) {
  if (state != STATE_PROCESS) return;

  DBG_MSG("C: ");
  PRINT_HEX(apdu_buffer, apdu_buffer_size);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;
  if (build_capdu(&apdu_cmd, apdu_buffer, apdu_buffer_size) < 0) {
    // abandon malformed apdu
    LL = 0;
    SW = SW_CHECKING_ERROR;
    goto send_response;
  }

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
    piv_process_apdu(capdu, rapdu);
    break;
  case APPLET_OATH:
    oath_process_apdu(capdu, rapdu);
    break;
  case APPLET_ADMIN:
    admin_process_apdu(capdu, rapdu);
    break;
  case APPLET_OPENPGP:
    openpgp_process_apdu(capdu, rapdu);
    break;
  default:
    LL = 0;
    SW = SW_FILE_NOT_FOUND;
  }

send_response:
  apdu_buffer_size = LL + 2;
  apdu_buffer[LL] = HI(SW);
  apdu_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(apdu_buffer, apdu_buffer_size);
  state = STATE_SEND_RESP;
}

uint8_t USBD_WEBUSB_DataIn(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  state = STATE_IDLE;
  apdu_buffer_size = 0;

  return USBD_OK;
}
