#ifndef __USB_DESCRIPTORS_H__
#define __USB_DESCRIPTORS_H__

#include <usb_device.h>

#define USBD_VID 0x20A0
#define USBD_PID 0x42D4

#define USBD_LANGID_STRING 0x09, 0x04
#define USBD_MANUFACTURER_STRING "canokeys.org"
#ifndef USBD_PRODUCT_STRING
    #define USBD_PRODUCT_STRING "CanoKey"
#endif

#define USBD_URL_STRING "console.canokeys.org"

#define USBD_HID_INTERFACE_STRING "FIDO2/U2F Keyboard"
#define USBD_CCID_INTERFACE_STRING "OpenPGP PIV OATH"
#define USBD_WEBUSB_INTERFACE_STRING "WebUSB"

#define USBD_MAX_STR_DESC_SIZE 32
enum {
  // Standard strings
  USBD_IDX_LANGID_STR       = 0x00,
  USBD_IDX_MANUFACTURER_STR = 0x01,
  USBD_IDX_PRODUCT_STR      = 0x02,
  USBD_IDX_SERIAL_STR       = 0x03,

  USBD_IDX_STD_STR_MAX      = 0x03,

  // Custom strings
  USBD_IDX_CUSTOM_STR_BASE  = 0x10,

  USBD_IDX_HID_STR          = 0x10,
  USBD_IDX_CCID_STR         = 0x11,
  USBD_IDX_WEBUSB_STR       = 0x12,

  USBD_IDX_CUSTOM_STR_MAX   = 0x12
};

#define PLACEHOLDER_IFACE_NUM 0xFF
#define PLACEHOLDER_EPIN_SIZE 0xFF
#define PLACEHOLDER_EPOUT_SIZE 0xFF
#define PLACEHOLDER_EPIN_ADDR 0xFF
#define PLACEHOLDER_EPOUT_ADDR 0x7F

// Interface ID
#define USBD_CANOKEY_HID_IF IFACE_TABLE.hid
#define USBD_CANOKEY_WEBUSB_IF IFACE_TABLE.webusb
#define USBD_CANOKEY_CCID_IF IFACE_TABLE.ccid

// HID report id
enum {
  REPORT_ID_KEYBOARD = 1,
  REPORT_ID_CTAP
};

// WebUSB vendor request
enum {
  VENDOR_REQUEST_WEBUSB = 1,
  VENDOR_REQUEST_MICROSOFT = 2
};

// MSOS 2.0 descriptor, used in tud_vendor_control_xfer_cb()
extern uint8_t const desc_ms_os_20[];
extern tusb_desc_webusb_url_t const desc_url;

#endif /* __USB_DESCRIPTORS_H__ */