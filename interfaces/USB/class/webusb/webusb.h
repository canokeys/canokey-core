/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _WEBUSB_H_
#define _WEBUSB_H_

enum {
    WEBUSB_REQ_CMD = 0x00,
    WEBUSB_REQ_RESP = 0x01,
    WEBUSB_REQ_STAT = 0x02
};

bool webusb_handle_device_request(uint8_t rhport, tusb_control_request_t const *request);
bool webusb_handle_interface_request(uint8_t rhport, tusb_control_request_t const *request);

void webusb_init();

bool tud_vendor_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *request);

#endif /* _WEBUSB_H_ */