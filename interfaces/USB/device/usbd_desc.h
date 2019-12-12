#ifndef __USBD_DESC__H__
#define __USBD_DESC__H__

#include <usbd_def.h>

/** Descriptor for the Usb device. */
extern const USBD_DescriptorsTypeDef usbdDescriptors;

void USBD_DescriptorInit(void);

#endif /* __USBD_DESC__H__ */
