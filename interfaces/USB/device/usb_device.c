#include <usb_device.h>
#include <usbd_canokey.h>
#include <usbd_core.h>
#include <usbd_desc.h>

void usb_device_init(void) {
  USBD_Init(&usb_device, &usbdDescriptors, 0);
  USBD_RegisterClass(&usb_device, &USBD_CANOKEY);
  USBD_Start(&usb_device);
}
