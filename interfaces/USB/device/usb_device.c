// SPDX-License-Identifier: Apache-2.0
#include <usb_device.h>
#include <tusb.h>
#include <device.h>

IFACE_TABLE_t IFACE_TABLE;
EP_TABLE_t EP_TABLE;

void usb_device_init(void) {
    tusb_init();
    usb_resources_alloc();
//   USBD_DescriptorInit();
//   USBD_Init(&usb_device, &usbdDescriptors, 0);
//   USBD_RegisterClass(&usb_device, &USBD_CANOKEY);
//   USBD_Start(&usb_device);
}

void usb_device_deinit(void) {
//   USBD_Stop(&usb_device);
//   USBD_DeInit(&usb_device);
}

void __attribute__((weak)) usb_resources_alloc() {}

//--------------------------------------------------------------------+
// Device callbacks
//--------------------------------------------------------------------+

// Invoked when device is mounted
void tud_mount_cb(void) {
    device_mounted();
}

// Invoked when device is unmounted
void tud_umount_cb(void) {
}

// Invoked when usb bus is suspended
// remote_wakeup_en : if host allow us  to perform remote wakeup
// Within 7ms, device must draw an average of current less than 2.5 mA from bus
void tud_suspend_cb(bool remote_wakeup_en) {
  (void) remote_wakeup_en;
}

// Invoked when usb bus is resumed
void tud_resume_cb(void) {
}
