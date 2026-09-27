// SPDX-License-Identifier: Apache-2.0
#include <apdu.h>
#include <ccid.h>
#include <device.h>
#include <webusb.h>

enum {
  STATE_IDLE = -1,
  STATE_PROCESS = 1,
  STATE_SENDING_RESP = 0,
  STATE_SENT_RESP = 2,
  STATE_RECVING = 3,
  STATE_HOLD_SESSION = 4,
};

static int8_t state;
static uint16_t apdu_buffer_size;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static uint32_t last_keepalive;

uint8_t USBD_WEBUSB_Init(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  state = STATE_IDLE;
  apdu_cmd.data = shared_io_buffer;
  apdu_resp.data = shared_io_buffer;
  last_keepalive = 0;

  return USBD_OK;
}

uint8_t USBD_WEBUSB_Setup(USBD_HandleTypeDef *pdev, USBD_SetupReqTypedef *req) {
  // CCID_eject();
  last_keepalive = device_get_tick();
  switch (req->bRequest) {
  case WEBUSB_REQ_CMD:
    if (state != STATE_IDLE && state != STATE_HOLD_SESSION) {
      ERR_MSG("Wrong state %d\n", state);
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    if (acquire_apdu_interface(DEVICE_APPLET_SESSION_WEBUSB, BUFFER_OWNER_WEBUSB) != 0) {
      ERR_MSG("Busy\n");
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    // DBG_MSG("Buf Acquired\n");
    if (req->wLength > APDU_COMMAND_BUFFER_SIZE) {
      ERR_MSG("Overflow\n");
      release_apdu_interface(DEVICE_APPLET_SESSION_WEBUSB, BUFFER_OWNER_WEBUSB);
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    USBD_CtlPrepareRx(pdev, shared_io_buffer, req->wLength);
    apdu_buffer_size = req->wLength;
    state = STATE_RECVING;
    break;

  case WEBUSB_REQ_RESP:
    if (state == STATE_SENDING_RESP) {
      if (device_applet_session_acquire(DEVICE_APPLET_SESSION_WEBUSB) != 0) {
        USBD_CtlError(pdev, req);
        return USBD_FAIL;
      }
      device_applet_session_touch(DEVICE_APPLET_SESSION_WEBUSB);
      uint16_t len = MIN(apdu_buffer_size, req->wLength);
      USBD_CtlSendData(pdev, shared_io_buffer, len, WEBUSB_EP0_SENDER);
      state = STATE_SENT_RESP;
    } else {
      USBD_CtlError(pdev, req);
      return USBD_FAIL;
    }
    break;

  case WEBUSB_REQ_STAT:
    USBD_CtlSendData(pdev, (uint8_t *)&state, 1, WEBUSB_EP0_SENDER);
    break;

  default:
    USBD_CtlError(pdev, req);
    return USBD_FAIL;
  }

  return USBD_OK;
}

void WebUSB_Loop(void) {
  if (state == STATE_HOLD_SESSION && device_applet_session_owner() != DEVICE_APPLET_SESSION_WEBUSB) {
    state = STATE_IDLE;
  } else if (device_get_tick() - last_keepalive > 2000 && state == STATE_HOLD_SESSION) {
    DBG_MSG("Release session after time-out\n");
    device_applet_session_release(DEVICE_APPLET_SESSION_WEBUSB);
    // CCID_insert();
    state = STATE_IDLE;
  }
  if (state != STATE_PROCESS) return;

  DBG_MSG("C: ");
  PRINT_HEX(shared_io_buffer, apdu_buffer_size);

  CAPDU *capdu = &apdu_cmd;
  RAPDU *rapdu = &apdu_resp;

  if (build_capdu(&apdu_cmd, shared_io_buffer, apdu_buffer_size) < 0) {
    // abandon malformed apdu
    LL = 0;
    SW = SW_WRONG_LENGTH;
  } else if (device_applet_session_acquire(DEVICE_APPLET_SESSION_WEBUSB) != 0) {
    LL = 0;
    SW = SW_CONDITIONS_NOT_SATISFIED;
  } else {
    device_applet_session_touch(DEVICE_APPLET_SESSION_WEBUSB);
    process_apdu_from(capdu, rapdu, APDU_TRANSPORT_WEBUSB);
  }

  apdu_buffer_size = LL + 2;
  shared_io_buffer[LL] = HI(SW);
  shared_io_buffer[LL + 1] = LO(SW);
  DBG_MSG("R: ");
  PRINT_HEX(shared_io_buffer, apdu_buffer_size);
  state = STATE_SENDING_RESP;
}

uint8_t USBD_WEBUSB_TxSent(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  // DBG_MSG("state = %d\n", state);
  if (state == STATE_SENT_RESP) {
    release_apdu_buffer(BUFFER_OWNER_WEBUSB);
    state = STATE_HOLD_SESSION;
  }

  return USBD_OK;
}

uint8_t USBD_WEBUSB_RxReady(USBD_HandleTypeDef *pdev) {
  UNUSED(pdev);

  //  state should be STATE_RECVING now
  state = STATE_PROCESS;

  return USBD_OK;
}
