#ifndef __USBD_CONF__H__
#define __USBD_CONF__H__

#if !defined(DEVICE_CONFIG_FILE)
#include "device-config-default.h"
#else
#include DEVICE_CONFIG_FILE
#endif

#define USBD_MAX_NUM_INTERFACES 4
#define USBD_MAX_NUM_CONFIGURATION 1
#define USBD_SELF_POWERED 0
#define USBD_MAX_STR_DESC_SIZ 64

#endif /* __USBD_CONF__H__ */
