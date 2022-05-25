#include <admin.h>
#include <tusb.h>

#include "usb_descriptors.h"
#include "usb_device.h"

//--------------------------------------------------------------------+
// Device Descriptors
//--------------------------------------------------------------------+
tusb_desc_device_t const desc_device = {
  .bLength            = sizeof(tusb_desc_device_t),
  .bDescriptorType    = TUSB_DESC_DEVICE,
  .bcdUSB             = 0x0210,
  .bDeviceClass       = 0x00,
  .bDeviceSubClass    = 0x00,
  .bDeviceProtocol    = 0x00,
  .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

  .idVendor           = USBD_VID,
  .idProduct          = USBD_PID,
  .bcdDevice          = 0x0100,

  .iManufacturer      = 0x01,
  .iProduct           = 0x02,
  .iSerialNumber      = 0x03,

  .bNumConfigurations = 0x01
};

// Invoked when received GET DEVICE DESCRIPTOR
// Application return pointer to descriptor
uint8_t const * tud_descriptor_device_cb(void) {
  return (uint8_t const *) &desc_device;
}

//--------------------------------------------------------------------+
// Interface Descriptor
//--------------------------------------------------------------------+
uint8_t const desc_hid_report[] = {
  TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(REPORT_ID_KEYBOARD)),
  TUD_HID_REPORT_DESC_FIDO_U2F(HID_REPORT_ID(REPORT_ID_CTAP))
};

// Invoked when received GET HID REPORT DESCRIPTOR
// Application return pointer to descriptor
// Descriptor contents must exist long enough for transfer to complete
uint8_t const * tud_hid_descriptor_report_cb(uint8_t itf) {
  if (itf == 0) {
    return desc_hid_report;
  }

  return NULL;
}

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+
#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_DESC_LEN)

uint8_t desc_configuration[CONFIG_TOTAL_LEN] = {
  // Config number, interface count, string index, total length, attribute, power in mA
  // interface count and total length are updated by program
  TUD_CONFIG_DESCRIPTOR(1, 0, 0, 0, 0, 100)
};

uint8_t const desc_configuration_hid[] = {
  TUD_HID_INOUT_DESCRIPTOR(
    PLACEHOLDER_IFACE_NUM, USBD_IDX_HID_STR, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report),
    PLACEHOLDER_EPOUT_ADDR, PLACEHOLDER_EPIN_ADDR, PLACEHOLDER_EPIN_SIZE, 5)
};

static void patch_interface_descriptor(uint8_t *desc, uint8_t *desc_end, 
  uint8_t ifnum, uint8_t epin, uint8_t epout, uint8_t ep_size) {

  while (desc < desc_end) {
    switch (desc[1]) {
    case TUSB_DESC_INTERFACE:
      desc[2] = ifnum;
      break;
    case TUSB_DESC_ENDPOINT:
      if (desc[2] == PLACEHOLDER_EPIN_ADDR)
        desc[2] = epin;
      else
        desc[2] = epout;
      desc[4] = ep_size;
      break;
    }
    desc += desc[0];
  }
}

// Invoked when received GET CONFIGURATION DESCRIPTOR
// Application return pointer to descriptor
// Descriptor contents must exist long enough for transfer to complete
uint8_t const * tud_descriptor_configuration_cb(uint8_t index) {
  (void) index; // for multiple configurations

  // patch HID descriptor
  uint8_t *desc = desc_configuration + TUD_CONFIG_DESC_LEN;
  uint8_t *desc_end = desc + sizeof(desc_configuration_hid);
  memcpy(desc, desc_configuration_hid, sizeof(desc_configuration_hid));
  patch_interface_descriptor(desc, desc_end, USBD_CANOKEY_HID_IF, EP_IN(hid), EP_OUT(hid), CFG_TUD_HID_EP_BUFSIZE);

  return desc_configuration;
}

//--------------------------------------------------------------------+
// BOS Descriptor
// Microsoft OS 2.0 registry property descriptor
//--------------------------------------------------------------------+

#define BOS_TOTAL_LEN      (TUD_BOS_DESC_LEN + TUD_BOS_WEBUSB_DESC_LEN + TUD_BOS_MICROSOFT_OS_DESC_LEN)

#define MS_OS_20_DESC_LEN  0xB2

// BOS Descriptor is required for webUSB
uint8_t const desc_bos[] = {
  // total length, number of device caps
  TUD_BOS_DESCRIPTOR(BOS_TOTAL_LEN, 2),

  // Vendor Code, iLandingPage
  TUD_BOS_WEBUSB_DESCRIPTOR(VENDOR_REQUEST_WEBUSB, 1),

  // Microsoft OS 2.0 descriptor
  TUD_BOS_MS_OS_20_DESCRIPTOR(MS_OS_20_DESC_LEN, VENDOR_REQUEST_MICROSOFT)
};

uint8_t const * tud_descriptor_bos_cb(void) {
  return desc_bos;
}

uint8_t const desc_ms_os_20[] = {
  // Set header: length, type, windows version, total length
  U16_TO_U8S_LE(0x000A), U16_TO_U8S_LE(MS_OS_20_SET_HEADER_DESCRIPTOR), 
  U32_TO_U8S_LE(0x06030000), U16_TO_U8S_LE(MS_OS_20_DESC_LEN),

  // Configuration subset header
  // length, type, configuration index, reserved, configuration total length
  U16_TO_U8S_LE(0x0008), U16_TO_U8S_LE(MS_OS_20_SUBSET_HEADER_CONFIGURATION), 
  0, 0, U16_TO_U8S_LE(MS_OS_20_DESC_LEN-0x0A),

  // Function Subset header: length, type, first interface, reserved, subset length
  // TODO: check first interface number
  U16_TO_U8S_LE(0x0008), U16_TO_U8S_LE(MS_OS_20_SUBSET_HEADER_FUNCTION), 
  1, 0, U16_TO_U8S_LE(MS_OS_20_DESC_LEN-0x0A-0x08),

  // MS OS 2.0 Compatible ID descriptor: length, type, compatible ID, sub compatible ID
  U16_TO_U8S_LE(0x0014), U16_TO_U8S_LE(MS_OS_20_FEATURE_COMPATBLE_ID), 
  'W', 'I', 'N', 'U', 'S', 'B', 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sub-compatible

  // MS OS 2.0 Registry property descriptor: length, type
  U16_TO_U8S_LE(MS_OS_20_DESC_LEN-0x0A-0x08-0x08-0x14), 
  U16_TO_U8S_LE(MS_OS_20_FEATURE_REG_PROPERTY),

  // wPropertyDataType, wPropertyNameLength and PropertyName "DeviceInterfaceGUIDs"
  U16_TO_U8S_LE(0x0007), U16_TO_U8S_LE(0x002A),
  'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00, 'I', 0x00,
  'n', 0x00, 't', 0x00, 'e', 0x00, 'r', 0x00, 'f', 0x00, 'a', 0x00, 'c', 0x00,
  'e', 0x00, 'G', 0x00, 'U', 0x00, 'I', 0x00, 'D', 0x00, 's', 0x00, 0x00, 0x00,
  U16_TO_U8S_LE(0x0050), // wPropertyDataLength

	// bPropertyData: “{244eb29e-e090-4e49-81fe-1f20f8d3b8f4}”.
  '{', 0x00, '2', 0x00, '4', 0x00, '4', 0x00, 'E', 0x00, 'B', 0x00, '2', 0x00,
  '9', 0x00, 'E', 0x00, '-', 0x00, 'E', 0x00, '0', 0x00, '9', 0x00, '0', 0x00,
  '-', 0x00, '4', 0x00, 'E', 0x00, '4', 0x00, '9', 0x00, '-', 0x00, '8', 0x00,
  '1', 0x00, 'F', 0x00, 'E', 0x00, '-', 0x00, '1', 0x00, 'F', 0x00, '2', 0x00,
  '0', 0x00, 'F', 0x00, '8', 0x00, 'D', 0x00, '3', 0x00, 'B', 0x00, '8', 0x00,
  'F', 0x00, '4', 0x00, '}', 0x00, 0x00, 0x00, 0x00, 0x00
};

TU_VERIFY_STATIC(sizeof(desc_ms_os_20) == MS_OS_20_DESC_LEN, "Incorrect size");

const tusb_desc_webusb_url_t desc_url = {
  .bLength         = 3 + sizeof(USBD_URL_STRING) - 1,
  .bDescriptorType = 3, // WEBUSB URL type
  .bScheme         = 1, // 0: http, 1: https
  .url             = USBD_URL_STRING
};

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+
// array of pointer to standard string descriptors
char const* string_desc_arr_std[] = {
  (const char[]) { USBD_LANGID_STRING },  // 0: supported language
  USBD_MANUFACTURER_STRING,               // 1: Manufacturer
  USBD_PRODUCT_STRING,                    // 2: Product
  "123456",                               // 3: Serials Number Placeholder
};

// array of pointer to custom string descriptors
char const* string_desc_arr_custom[] = {
  USBD_HID_INTERFACE_STRING,
  USBD_CCID_INTERFACE_STRING,
  USBD_WEBUSB_INTERFACE_STRING
};

static uint16_t _desc_str[USBD_MAX_STR_DESC_SIZE];

// Invoked when received GET STRING DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  uint8_t chr_count;
  const char* _str;  // This will get copied to _desc_str

  if (index == USBD_IDX_LANGID_STR) {   // language ID
    memcpy(&_desc_str[1], string_desc_arr_std[0], 2);
    chr_count = 1;
    return _desc_str;
  }

  if (index == USBD_IDX_SERIAL_STR) {   // serial number
    uint8_t sn[4];
    char sn_str[9];
    fill_sn(sn);
    sprintf(sn_str, "%02X%02X%02X%02X", sn[0], sn[1], sn[2], sn[3]);
    _str = (const char*) sn_str;
  }
  
  if (index < USBD_IDX_STD_STR_MAX) {   // standard string, excluding sn
    _str = string_desc_arr_std[index];
  } else if (index >= USBD_IDX_CUSTOM_STR_BASE && index < USBD_IDX_CUSTOM_STR_MAX) {
    _str = string_desc_arr_custom[index - USBD_IDX_CUSTOM_STR_BASE];
  } else {
    return NULL;
  }

  // Cap at max chararcter count
  chr_count = strlen(_str);
  if (chr_count > USBD_MAX_STR_DESC_SIZE - 1) 
    chr_count = USBD_MAX_STR_DESC_SIZE - 1;

  // Convert ASCII string into UTF-16
  for(uint8_t i = 0; i < chr_count; i++)
    _desc_str[i+1] = _str[i];

  // first byte is length (including header), second byte is string type
  _desc_str[0] = (TUSB_DESC_STRING << 8 ) | (2 * chr_count + 2);

  return _desc_str;
}
