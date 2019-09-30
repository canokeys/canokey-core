#ifndef __USB_DEVICE__H__
#define __USB_DEVICE__H__

#include <usbd_def.h>

/** USB device core handle. */
extern USBD_HandleTypeDef usb_device;

void usb_device_init(void);

#endif /* __USB_DEVICE__H__ */
