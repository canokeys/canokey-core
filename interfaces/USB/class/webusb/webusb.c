#include <tusb.h>
#include <usb_descriptors.h>

#include <apdu.h>
#include <device.h>
#include <webusb.h>

static enum {
  STATE_IDLE = -1,
  STATE_PROCESS = 1,
  STATE_SENDING_RESP = 0,
  STATE_SENT_RESP = 2,
} state;

static uint16_t apdu_buffer_size;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

//==============================================================================
// WEBUSB functions
//==============================================================================

//==============================================================================
// Class init and loop
//==============================================================================
void webusb_init() {
  state = STATE_IDLE;
  apdu_cmd.data = global_buffer;
  apdu_resp.data = global_buffer;
}

void webusb_loop() {}

//==============================================================================
// TinyUSB stack callbacks
//==============================================================================

//--------------------------------------------------------------------+
// WebUSB use vendor class
//--------------------------------------------------------------------+
// Invoked when a control transfer occurred on an interface of this class
// Driver response accordingly to the request and the transfer stage (setup/data/ack)
// return false to stall control endpoint (e.g unsupported request)
bool tud_vendor_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *request) {
  // nothing to with DATA & ACK stage
  if (stage != CONTROL_STAGE_SETUP) return true;

  // we are only interested in vendor requests
  if (request->bmRequestType_bit.type != TUSB_REQ_TYPE_VENDOR) return false;

  // parse recipient
  DBG_MSG("tud_vendor_control_xfer_cb: recipient: %02X\r\n", request->bmRequestType_bit.recipient);
  
  switch (request->bmRequestType_bit.recipient) {
  case TUSB_REQ_RCPT_DEVICE:
    return webusb_handle_device_request(rhport, request);
  case TUSB_REQ_RCPT_INTERFACE:
    return webusb_handle_interface_request(rhport, request);
  default:
    return false;
  }
}

// Recipient = device, for BOS and URL descriptors
bool webusb_handle_device_request(uint8_t rhport, tusb_control_request_t const *request) {
  switch (request->bRequest) {
  case VENDOR_REQUEST_WEBUSB:
    // match vendor request in BOS descriptor
    // Get landing page url
    return tud_control_xfer(rhport, request, (void *)(uintptr_t)&desc_url, desc_url.bLength);

  case VENDOR_REQUEST_MICROSOFT:
    if (request->wIndex == 7) {
      // Get Microsoft OS 2.0 compatible descriptor
      uint16_t total_len;
      memcpy(&total_len, desc_ms_os_20 + 8, 2);

      return tud_control_xfer(rhport, request, (void *)(uintptr_t)desc_ms_os_20, total_len);
    } else {
      return false;
    }

  default:
    break;
  }

  // stall unknown request
  return false;
}

// Recipient = interface
bool webusb_handle_interface_request(uint8_t rhport, tusb_control_request_t const *request) {
  DBG_MSG("%s, bRequest=%d, wLength=%d\r\n", __func__, request->bRequest, request->wLength);

  switch (request->bRequest) {
  case WEBUSB_REQ_CMD:
    if (acquire_apdu_buffer(BUFFER_OWNER_WEBUSB) != 0) {
      ERR_MSG("Busy\n");
      return false;
    }
    if (request->wLength > APDU_BUFFER_SIZE) {
      ERR_MSG("Overflow\n");
      return false;
    }
    tud_control_xfer(rhport, request, global_buffer, request->wLength);
    apdu_buffer_size = request->wLength;
    return true;

  case WEBUSB_REQ_RESP:
    if (state == STATE_SENDING_RESP) {
      uint16_t len = MIN(apdu_buffer_size, request->wLength);
      tud_control_xfer(rhport, request, global_buffer, len);
      state = STATE_SENT_RESP;
    } else {
      return false;
    }
    return true;

  case WEBUSB_REQ_STAT:
    tud_control_xfer(rhport, request, &state, 1);
    return true;

  default:
    break;
  }

  // stall unknown request
  return false;
}