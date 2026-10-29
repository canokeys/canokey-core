/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __USB_DEVICE__H__
#define __USB_DEVICE__H__

#include <usbd_def.h>

#if ENABLE_IFACE_CTAPHID
#define IFACE_CTAPHID 0
#define EP_NUM_ctap_hid 2
#define EP_SIZE_ctap_hid 64
#else
#define IFACE_CTAPHID 0xFF
#endif

#if ENABLE_IFACE_WEBUSB
#define IFACE_WEBUSB (ENABLE_IFACE_CTAPHID)
#else
#define IFACE_WEBUSB 0xFF
#endif

#if ENABLE_IFACE_CCID
#define IFACE_CCID (ENABLE_IFACE_CTAPHID + ENABLE_IFACE_WEBUSB)
#define EP_NUM_ccid 3
#define EP_SIZE_ccid 64
#else
#define IFACE_CCID 0xFF
#endif

#if ENABLE_IFACE_KBDHID
#define IFACE_KBDHID (ENABLE_IFACE_CTAPHID + ENABLE_IFACE_WEBUSB + ENABLE_IFACE_CCID)
#define EP_NUM_kbd_hid 1
#define EP_SIZE_kbd_hid 8
#else
#define IFACE_KBDHID 0xFF
#define EP_NUM_kbd_hid 0xFF
#define EP_SIZE_kbd_hid 0
#endif

#define EP_OUT(x) (EP_NUM_##x)
#define EP_IN(x) (0x80 | EP_NUM_##x)
#define EP_SIZE(x) (EP_SIZE_##x)
#define IS_ENABLED_IFACE(i) (i != 0xFF)

/** USB device core handle. */
extern USBD_HandleTypeDef usb_device;

void usb_device_init(void);
void usb_device_deinit(void);

#endif /* __USB_DEVICE__H__ */
