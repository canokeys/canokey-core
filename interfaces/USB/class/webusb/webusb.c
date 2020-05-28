#include <apdu.h>
#include <device.h>
#include <webusb.h>

enum {
  STATE_IDLE = -1,
  STATE_PROCESS = 1,
  STATE_SENDING_RESP = 0,
  STATE_SENT_RESP = 2,
};

static uint8_t state;
static uint16_t apdu_buffer_size;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

uint8_t USBD_WEBUSB_Init(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  state = STATE_IDLE;
  apdu_cmd.data = global_buffer;
  apdu_resp.data = global_buffer;

  return USBD_OK;
}

uint8_t USBD_WEBUSB_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  switch (req->bRequest) {
  case WEBUSB_REQ_CMD:
    if (device_spinlock_lock(&apdu_lock, false) != 0) {
      ERR_MSG("Busy\n");
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    if (req->wLength > APDU_BUFFER_SIZE) {
      ERR_MSG("Overflow\n");
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    USBD_CtlPrepareRx(pdev, global_buffer, req->wLength);
    apdu_buffer_size = req->wLength;
    break;

  case WEBUSB_REQ_RESP:
    if (state == STATE_SENDING_RESP) {
      uint16_t len = MIN(apdu_buffer_size, req->wLength);
      USBD_CtlSendData(pdev, global_buffer, len, WEBUSB_EP0_SENDER);
      state = STATE_SENT_RESP;
    } else {
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    break;

  case WEBUSB_REQ_STAT:
    USBD_CtlSendData(pdev, &state, 1, WEBUSB_EP0_SENDER);
    break;

  default:
    USBD_CtlError(pdev, req);
    return USBD_FAIL;
  }

  return USBD_OK;
}

void WebUSB_Loop(void) {
  if (state != STATE_PROCESS) return;

  DBG_MSG("C: ");
  PRINT_HEX(global_buffer, apdu_buffer_size);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  if (build_capdu(&apdu_cmd, global_buffer, apdu_buffer_size) < 0) {
    // abandon malformed apdu
    LL = 0;
    SW = SW_CHECKING_ERROR;
  } else {
    process_apdu(capdu, rapdu);
  }

  apdu_buffer_size = LL + 2;
  global_buffer[LL] = HI(SW);
  global_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(global_buffer, apdu_buffer_size);
  state = STATE_SENDING_RESP;
  device_spinlock_unlock(&apdu_lock);
}

uint8_t USBD_WEBUSB_TxSent(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  if (state == STATE_SENT_RESP) state = STATE_IDLE;

  return USBD_OK;
}

uint8_t USBD_WEBUSB_RxReady(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  state = STATE_PROCESS;

  return USBD_OK;
}
