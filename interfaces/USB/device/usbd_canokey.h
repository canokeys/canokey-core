#ifndef __USB_CANOKEY_H
#define __USB_CANOKEY_H

#include <usbd_ioreq.h>

#define USBD_CANOKEY_CTAPHID_IF 0
#define USBD_CANOKEY_CCID_IF 1
#define USBD_CANOKEY_OPENPGP_IF 2

extern const USBD_ClassTypeDef USBD_CANOKEY;

#endif /* __USB_CANOKEY_H */
