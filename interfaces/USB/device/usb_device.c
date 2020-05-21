#include <usb_device.h>
#include <usbd_canokey.h>
#include <usbd_core.h>
#include <usbd_desc.h>

USBD_HandleTypeDef usb_device = {};
IFACE_TABLE_t IFACE_TABLE;
EP_TABLE_t EP_TABLE;
EP_SIZE_TABLE_t EP_SIZE_TABLE;

void usb_device_init(void) {
  usb_resources_alloc();
  USBD_DescriptorInit();
  USBD_Init(&usb_device, &usbdDescriptors, 0);
  USBD_RegisterClass(&usb_device, &USBD_CANOKEY);
  USBD_Start(&usb_device);
}

void usb_device_deinit(void) {
  USBD_Stop(&usb_device);
  USBD_DeInit(&usb_device);
}

__weak void usb_resources_alloc() {}
