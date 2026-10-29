/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USB_CANOKEY_H
#define __USB_CANOKEY_H

#include <usb_device.h>
#include <usbd_ioreq.h>

#define USBD_CANOKEY_CTAPHID_IF IFACE_CTAPHID
#define USBD_CANOKEY_WEBUSB_IF IFACE_WEBUSB
#define USBD_CANOKEY_CCID_IF IFACE_CCID
#define USBD_CANOKEY_KBDHID_IF IFACE_KBDHID

extern const USBD_ClassTypeDef USBD_CANOKEY;
/* Service from the main loop, including while waiting for first enumeration. */
void USBD_CANOKEY_Service(void);
uint8_t USBD_CANOKEY_Ready(void);

#endif /* __USB_CANOKEY_H */
