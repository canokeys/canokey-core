#include <admin.h>
#include <usb_device.h>
#include <usbd_canokey.h>
#include <usbd_core.h>
#include <usbd_desc.h>

USBD_HandleTypeDef usb_device;
IFACE_TABLE_t IFACE_TABLE;
EP_TABLE_t EP_TABLE;

void usb_resources_alloc(void) {
  uint8_t iface = 0;
  uint8_t ep = 1;

  memset(&IFACE_TABLE, 0xFF, sizeof(IFACE_TABLE));
  memset(&EP_TABLE, 0xFF, sizeof(EP_TABLE));

  EP_TABLE.ctap_hid = ep++;
  IFACE_TABLE.ctap_hid = iface++;

  IFACE_TABLE.webusb = iface++;

  EP_TABLE.ccid = ep++;
  IFACE_TABLE.ccid = iface++;
  
  if (cfg_is_gpg_interface_en()) {
    DBG_MSG("OpenPGP interface enabled, Iface %u\n", iface);
    EP_TABLE.openpgp = ep++;
    IFACE_TABLE.openpgp = iface++;
  }
  if (cfg_is_kbd_interface_en()) {
    DBG_MSG("Keyboard interface enabled, Iface %u\n", iface);
    EP_TABLE.kbd_hid = ep++;
    IFACE_TABLE.kbd_hid = iface++;
  }
  // TODO: check ep range and EP buffer size
}

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
