#ifndef __USBD_DESC__H__
#define __USBD_DESC__H__

#include <usbd_def.h>

#define USBD_VID 0x0483
#define USBD_PID 0x0007

/** Descriptor for the Usb device. */
extern const USBD_DescriptorsTypeDef usbdDescriptors;

void USBD_DescriptorInit(void);

#endif /* __USBD_DESC__H__ */
