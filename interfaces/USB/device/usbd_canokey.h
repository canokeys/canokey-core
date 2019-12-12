#ifndef __USB_CANOKEY_H
#define __USB_CANOKEY_H

#include <usbd_ioreq.h>
#include <usb_device.h>

#define USBD_CANOKEY_CTAPHID_IF IFACE_TABLE.ctap_hid
#define USBD_CANOKEY_WEBUSB_IF IFACE_TABLE.webusb
#define USBD_CANOKEY_CCID_IF IFACE_TABLE.ccid
#define USBD_CANOKEY_OPENPGP_IF IFACE_TABLE.openpgp
#define USBD_CANOKEY_KBD_IF IFACE_TABLE.kbd_hid

extern const USBD_ClassTypeDef USBD_CANOKEY;

#endif /* __USB_CANOKEY_H */
