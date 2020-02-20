#include <apdu.h>
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

uint8_t USBD_WEBUSB_Init(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  state = STATE_IDLE;
  apdu_buffer_size = 0;
  apdu_cmd.data = apdu_buffer;
  apdu_resp.data = apdu_buffer;

  return USBD_OK;
}

uint8_t USBD_WEBUSB_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  switch (req->bRequest) {
  case WEBUSB_REQ_CMD:
    // restart the whole process whenever WEBUSB_REQ_FIRST_PACKET received
    if (state != STATE_PROCESS && (req->wValue & WEBUSB_REQ_FIRST_PACKET)) {
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

  case WEBUSB_REQ_CALC: {
    if (state == STATE_RECV_CMD) state = STATE_PROCESS;
    static uint8_t dummy;
    dummy = 0;
    USBD_CtlSendData(pdev, &dummy, 1, WEBUSB_EP0_SENDER);
    break;
  }

  case WEBUSB_REQ_RESP:
    if (state == STATE_SEND_RESP) {
      uint16_t len = MIN(apdu_buffer_size, req->wLength);
      USBD_CtlSendData(pdev, apdu_buffer, len, WEBUSB_EP0_SENDER);
    } else {
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    break;

  case WEBUSB_REQ_STAT: {
    static uint8_t in_progress;
    if (state == STATE_PROCESS)
      in_progress = 1;
    else if (state == STATE_SEND_RESP)
      in_progress = 0;
    else
      in_progress = 2;
    USBD_CtlSendData(pdev, &in_progress, 1, WEBUSB_EP0_SENDER);
    break;
  }

  default:
    USBD_CtlError(pdev, req);
    return USBD_FAIL;
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
  } else {
    process_apdu(capdu, rapdu);
  }

  apdu_buffer_size = LL + 2;
  apdu_buffer[LL] = HI(SW);
  apdu_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(apdu_buffer, apdu_buffer_size);
  state = STATE_SEND_RESP;
}

uint8_t USBD_WEBUSB_TxSent(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  return USBD_OK;
}
