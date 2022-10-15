// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <stdio.h>
#include <usbd_canokey.h>
#include <usbd_ccid.h>
#include <usbd_core.h>
#include <usbd_ctaphid.h>
#include <usbd_desc.h>
#include <usbd_kbdhid.h>

#define USBD_LANGID_STRING 0x0409
#define USBD_MANUFACTURER_STRING "canokeys.org"
#ifndef USBD_PRODUCT_STRING
#define USBD_PRODUCT_STRING "CanoKey"
#endif
#define USBD_CTAPHID_INTERFACE_STRING "FIDO2/U2F"
#define USBD_CTAPHID_INTERFACE_IDX 0x10
#define USBD_CCID_INTERFACE_STRING "OpenPGP PIV OATH"
#define USBD_CCID_INTERFACE_IDX 0x11
#define USBD_WEBUSB_INTERFACE_STRING "WebUSB"
#define USBD_WEBUSB_INTERFACE_IDX 0x12
#define USBD_KBDHID_INTERFACE_STRING "Keyboard"
#define USBD_KBDHID_INTERFACE_IDX 0x13

#define PLACEHOLDER_IFACE_NUM 0xFF
#define PLACEHOLDER_EPIN_SIZE 0xFF
#define PLACEHOLDER_EPOUT_SIZE 0xFF
#define PLACEHOLDER_EPIN_ADDR 0xFF
#define PLACEHOLDER_EPOUT_ADDR 0x7F

// clang-format off
const uint8_t *USBD_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_ConfigurationDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_BOSDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_MSOS20Descriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_UsrStrDescriptor(USBD_SpeedTypeDef speed, uint8_t index, uint16_t *length);
const uint8_t *USBD_UrlDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);

const USBD_DescriptorsTypeDef usbdDescriptors = {
    USBD_DeviceDescriptor,
    USBD_ConfigurationDescriptor,
    USBD_LangIDStrDescriptor,
    USBD_ManufacturerStrDescriptor,
    USBD_ProductStrDescriptor,
    USBD_SerialStrDescriptor,
    USBD_BOSDescriptor,
    USBD_MSOS20Descriptor,
    USBD_UsrStrDescriptor,
    USBD_UrlDescriptor,
};

/** USB standard device descriptor. */
static const uint8_t USBD_FS_DeviceDesc[] = {
    0x12,                 /*bLength */
    USB_DESC_TYPE_DEVICE, /*bDescriptorType*/
    0x10,                 /*bcdUSB */
    0x02,
    0x00,                /*bDeviceClass*/
    0x00,                /*bDeviceSubClass*/
    0x00,                /*bDeviceProtocol*/
    USB_MAX_EP0_SIZE,    /*bMaxPacketSize*/
    LO(USBD_VID),        /*idVendor*/
    HI(USBD_VID),        /*idVendor*/
    LO(USBD_PID),        /*idProduct*/
    HI(USBD_PID),        /*idProduct*/
    0x00,                /*bcdDevice rel. 1.00*/
    0x01,
    USBD_IDX_MFC_STR,          /*Index of manufacturer string*/
    USBD_IDX_PRODUCT_STR,      /*Index of product string*/
    USBD_IDX_SERIAL_STR,       /*Index of serial number string*/
    USBD_MAX_NUM_CONFIGURATION /*bNumConfigurations*/
};

static const uint8_t USBD_FS_IfDesc_CTAPHID[] = {
    /************** Descriptor of CTAP HID interface ****************/
    0x09,                       /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE,    /* bDescriptorType: Interface descriptor type */
    PLACEHOLDER_IFACE_NUM,      /* bInterfaceNumber: Number of Interface */
    0x00,                       /* bAlternateSetting: Alternate setting */
    0x02,                       /* bNumEndpoints */
    0x03,                       /* bInterfaceClass: HID */
    0x00,                       /* bInterfaceSubClass: 0=no boot */
    0x00,                       /* nInterfaceProtocol: 0=none */
    USBD_CTAPHID_INTERFACE_IDX, /* iInterface: Index of string descriptor */
    /******************** Descriptor of CTAP HID *************************/
    0x09,                    /* bLength: CTAP HID Descriptor size */
    CTAPHID_DESCRIPTOR_TYPE, /* bDescriptorType: HID */
    0x11, 0x01,              /* bCTAP_HID: CTAP HID Class Spec release number */
    0x00,                    /* bCountryCode: Hardware target country */
    0x01,                    /* bNumDescriptors: 1 */
    0x22,                    /* bDescriptorType */
    CTAPHID_REPORT_DESC_SIZE,/* wItemLength: Total length of Report descriptor */
    0x00,
    /**************** Descriptor of CTAP HID endpoints ****************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,       /* bDescriptorType: */
    PLACEHOLDER_EPIN_ADDR,        /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    PLACEHOLDER_EPIN_SIZE, 0x00,  /* wMaxPacketSize: 64 Byte max */
    0x02,                         /* bInterval: Polling Interval (2 ms) */
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,       /* bDescriptorType: */
    PLACEHOLDER_EPOUT_ADDR,       /* bEndpointAddress: Endpoint Address (OUT) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    PLACEHOLDER_EPOUT_SIZE, 0x00, /* wMaxPacketSize: 64 Bytes max  */
    0x05,                         /* bInterval: Polling Interval (5 ms) */
};

static const uint8_t USBD_FS_IfDesc_KBDHID[] = {
    /************** Descriptor of KBD HID interface ****************/
    0x09,                       /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE,    /* bDescriptorType: Interface descriptor type */
    PLACEHOLDER_IFACE_NUM,      /* bInterfaceNumber: Number of Interface */
    0x00,                       /* bAlternateSetting: Alternate setting */
    0x02,                       /* bNumEndpoints */
    0x03,                       /* bInterfaceClass: HID */
    0x00,                       /* bInterfaceSubClass: 0=no boot */
    0x00,                       /* nInterfaceProtocol: 0=none */
    USBD_KBDHID_INTERFACE_IDX,  /* iInterface: Index of string descriptor */
    /******************** Descriptor of KBD HID *************************/
    0x09,                       /* bLength: KBD HID Descriptor size */
    KBDHID_DESCRIPTOR_TYPE,     /* bDescriptorType: HID */
    0x11, 0x01,                 /* bKBD_HID: KBD HID Class Spec release number */
    0x00,                       /* bCountryCode: Hardware target country */
    0x01,                       /* bNumDescriptors: 1 */
    KBDHID_REPORT_DESC,         /* bDescriptorType */
    KBDHID_REPORT_DESC_SIZE,    /* wItemLength: Total length of Report descriptor */
    0x00,
    /**************** Descriptor of KBD HID endpoints ****************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,       /* bDescriptorType: */
    PLACEHOLDER_EPIN_ADDR,        /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    PLACEHOLDER_EPIN_SIZE, 0x00,  /* wMaxPacketSize: 8 Bytes max */
    0x0A,                         /* bInterval: Polling Interval (10 ms) */
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,       /* bDescriptorType: */
    PLACEHOLDER_EPOUT_ADDR,       /* bEndpointAddress: Endpoint Address (OUT) */
    0x03,                         /* bmAttributes: Interrupt endpoint */
    PLACEHOLDER_EPOUT_SIZE, 0x00, /* wMaxPacketSize: 8 Bytes max  */
    0x05,                         /* bInterval: Polling Interval (5 ms) */
};

static const uint8_t USBD_FS_IfDesc_WEBUSB[] = {
    /************** Descriptor of WebUSB interface ****************/
    0x09,                      /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE,   /* bDescriptorType: Interface descriptor type */
    PLACEHOLDER_IFACE_NUM,     /* bInterfaceNumber: Number of Interface */
    0x00,                      /* bAlternateSetting: Alternate setting */
    0x00,                      /* bNumEndpoints */
    0xFF,                      /* bInterfaceClass: Vendor Specific */
    0xFF,                      /* bInterfaceSubClass: Vendor Specific */
    0xFF,                      /* nInterfaceProtocol: Vendor Specific */
    USBD_WEBUSB_INTERFACE_IDX, /* iInterface: Index of string descriptor */
};

static const uint8_t USBD_FS_IfDesc_CCID[] = {
    /************** Descriptor of CCID interface ****************/
    /* This interface is for PIV, oath, and admin applet */
    0x09,                       /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE,    /* bDescriptorType: Interface descriptor type */
    PLACEHOLDER_IFACE_NUM,      /* bInterfaceNumber: Number of Interface */
    0x00,                       /* bAlternateSetting: Alternate setting */
    0x02,                       /* bNumEndpoints */
    0x0B,                       /* bInterfaceClass: Chip/SmartCard */
    0x00,                       /* bInterfaceSubClass: 0=no boot */
    0x00,                       /* nInterfaceProtocol: 0=none */
    USBD_CCID_INTERFACE_IDX,    /* iInterface: Index of string descriptor */
    /******************** Descriptor of CCID *************************/
    0x36,                     /* bLength: CCID Descriptor size */
    0x21,                     /* bDescriptorType: Functional Descriptor type. */
    0x10,                     /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                     /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1, /* bMaxSlotIndex: highest available slot on this device */
    0x07,                     /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,   /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,   /* dwDefaultClock: 4MHz */
    0xA0, 0x0F, 0x00, 0x00,   /* dwMaximumClock: 4MHz */
    0x00,                     /* bNumClockSupported : no setting from PC */
    0x00, 0xB0, 0x04, 0x00,   /* dwDataRate: Default ICC I/O data rate */
    0x00, 0xB0, 0x04, 0x00,   /* dwMaxDataRate: Maximum supported ICC I/O data */
    0x00,                     /* bNumDataRatesSupported : no setting from PC */
    LO(ABDATA_SIZE),          /* dwMaxIFSD, B3 */
    HI(ABDATA_SIZE),          /* dwMaxIFSD, B2 */
    0x00, 0x00,               /* dwMaxIFSD, B1B0 */
    0x00, 0x00, 0x00, 0x00,   /* dwSynchProtocols  */
    0x00, 0x00, 0x00, 0x00,   /* dwMechanical: no special characteristics */
    0xFE, 0x00, 0x04, 0x00,   /* dwFeatures */
    LO(ABDATA_SIZE + CCID_CMD_HEADER_SIZE), /* dwMaxCCIDMessageLength, B3 */
    HI(ABDATA_SIZE + CCID_CMD_HEADER_SIZE), /* dwMaxCCIDMessageLength, B2 */
    0x00, 0x00,               /* dwMaxCCIDMessageLength, B1B0 */
    0xFF,                     /* bClassGetResponse*/
    0xFF,                     /* bClassEnvelope */
    0x00, 0x00,               /* wLcdLayout: 0000h no LCD */
    0x00,                     /* bPINSupport: no PIN */
    CCID_NUMBER_OF_SLOTS,     /* bMaxCCIDBusySlots*/
    /**************** Descriptor of CCID endpoints ****************/
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,       /* bDescriptorType: */
    PLACEHOLDER_EPIN_ADDR,        /* bEndpointAddress: Endpoint Address (IN) */
    USBD_EP_TYPE_BULK,            /* bmAttributes: Bulk endpoint */
    PLACEHOLDER_EPIN_SIZE, 0x00,  /* wMaxPacketSize: 64 Byte max */
    0x00,                         /* bInterval: Polling Interval */
    0x07,                         /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,       /* bDescriptorType: */
    PLACEHOLDER_EPOUT_ADDR,       /* bEndpointAddress: Endpoint Address (OUT) */
    USBD_EP_TYPE_BULK,            /* bmAttributes: Bulk endpoint */
    PLACEHOLDER_EPOUT_SIZE, 0x00, /* wMaxPacketSize: 64 Bytes max  */
    0x00,                         /* bInterval: Polling Interval */
};

static uint8_t USBD_FS_CfgDesc[USB_LEN_CFG_DESC +
                              sizeof(USBD_FS_IfDesc_CCID) +
                              sizeof(USBD_FS_IfDesc_WEBUSB) +
                              sizeof(USBD_FS_IfDesc_KBDHID) +
                              sizeof(USBD_FS_IfDesc_CTAPHID)] = {
    USB_LEN_CFG_DESC,            /* bLength: Configuration Descriptor size */
    USB_DESC_TYPE_CONFIGURATION, /* bDescriptorType: Configuration */
    0x00, 0x00,                  /* wTotalLength: To be filled by program */
    0x00,                        /* bNumInterfaces: To be filled by program */
    0x01,                        /* bConfigurationValue: Configuration value */
    0x00,                        /* Configuration: Index of string descriptor describing the configuration */
    0x80,                        /* bmAttributes: bus powered */
    0x32,                        /* MaxPower 100 mA: this current is used for detecting Vbus */
};

/** USB BOS descriptor. */
static const uint8_t USBD_FS_BOSDesc[] = {
    0x05,              /*bLength */
    USB_DESC_TYPE_BOS, /*bDescriptorType*/
    0x39, 0x00,        /*total length*/
    0x02,              /*Number of device capabilities*/

    /*WebUSB platform capability descriptor*/
    0x18,                   /*bLength*/
    0x10,                   /*Device Capability descriptor*/
    0x05,                   /*Platform Capability descriptor*/
    0x00,                   /*Reserved*/
    0x38, 0xB6, 0x08, 0x34, /*WebUSB GUID*/
    0xA9, 0x09, 0xA0, 0x47,
    0x8B, 0xFD, 0xA0, 0x76,
    0x88, 0x15, 0xB6, 0x65,
    0x00, 0x01,             /*Version 1.0*/
    0x01,                   /*Vendor request code*/
    0x01,                   /*iLandingPage*/

    /*Microsoft OS 2.0 Platform Capability Descriptor (MS_VendorCode == 0x02)*/
    0x1C,                   /*bLength*/
    0x10,                   /*Device Capability descriptor*/
    0x05,                   /*Platform Capability descriptor*/
    0x00,                   /*Reserved*/
    0xDF, 0x60, 0xDD, 0xD8, /*MS OS 2.0 GUID*/
    0x89, 0x45, 0xC7, 0x4C,
    0x9C, 0xD2, 0x65, 0x9D,
    0x9E, 0x64, 0x8A, 0x9F,
    0x00, 0x00, 0x03, 0x06, /*Windows version*/
    0xB2, 0x00,             /*Descriptor set length*/
    0x02,                   /*Vendor request code*/
    0x00                    /*Alternate enumeration code*/
};

static const uint8_t USBD_FS_MSOS20Desc[] = {
    // Microsoft OS 2.0 descriptor set header (table 10)
    0x0A, 0x00,             // Descriptor size (10 bytes)
    0x00, 0x00,             // MS OS 2.0 descriptor set header
    0x00, 0x00, 0x03, 0x06, // Windows version (8.1) (0x06030000)
    0xB2, 0x00,             // Size, MS OS 2.0 descriptor set

    // Microsoft OS 2.0 configuration subset header
    0x08, 0x00, // Descriptor size (8 bytes)
    0x01, 0x00, // MS OS 2.0 configuration subset header
    0x00,       // bConfigurationValue
    0x00,       // Reserved
    0xA8, 0x00, // Size, MS OS 2.0 configuration subset

    // Microsoft OS 2.0 function subset header
    0x08, 0x00, // Descriptor size (8 bytes)
    0x02, 0x00, // MS OS 2.0 function subset header
    0x01,       // First interface number
    0x00,       // Reserved
    0xA0, 0x00, // Size, MS OS 2.0 function subset

    // Microsoft OS 2.0 compatible ID descriptor (table 13)
    0x14, 0x00, // wLength
    0x03, 0x00, // MS_OS_20_FEATURE_COMPATIBLE_ID
    'W',  'I',  'N',  'U',  'S',  'B',  0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x84, 0x00, // wLength:
    0x04, 0x00, // wDescriptorType: MS_OS_20_FEATURE_REG_PROPERTY: 0x04 (Table 9)
    0x07, 0x00, // wPropertyDataType: REG_MULTI_SZ (Table 15)
    0x2A, 0x00, // wPropertyNameLength:
    // bPropertyName: "DeviceInterfaceGUID"
    'D', 0x00, 'e', 0x00, 'v', 0x00, 'i', 0x00, 'c', 0x00, 'e', 0x00, 'I', 0x00,
    'n', 0x00, 't', 0x00, 'e', 0x00, 'r', 0x00, 'f', 0x00, 'a', 0x00, 'c', 0x00,
    'e', 0x00, 'G', 0x00, 'U', 0x00, 'I', 0x00, 'D', 0x00, 's', 0x00, 0x00, 0x00,
    0x50, 0x00, // wPropertyDataLength
    // bPropertyData: "{244eb29e-e090-4e49-81fe-1f20f8d3b8f4}"
    '{', 0x00, '2', 0x00, '4', 0x00, '4', 0x00, 'E', 0x00, 'B', 0x00, '2', 0x00,
    '9', 0x00, 'E', 0x00, '-', 0x00, 'E', 0x00, '0', 0x00, '9', 0x00, '0', 0x00,
    '-', 0x00, '4', 0x00, 'E', 0x00, '4', 0x00, '9', 0x00, '-', 0x00, '8', 0x00,
    '1', 0x00, 'F', 0x00, 'E', 0x00, '-', 0x00, '1', 0x00, 'F', 0x00, '2', 0x00,
    '0', 0x00, 'F', 0x00, '8', 0x00, 'D', 0x00, '3', 0x00, 'B', 0x00, '8', 0x00,
    'F', 0x00, '4', 0x00, '}', 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t USBD_FS_URL_DESCRIPTOR[] = {
    23,   // bLength
    0x03, // bDescriptorType: URL descriptor
    0x01, // bScheme: https://
    'c', 'o', 'n', 's', 'o', 'l', 'e', '.', 'c', 'a', 'n', 'o', 'k', 'e', 'y', 's', '.', 'o', 'r', 'g'
};

/** USB lang identifier descriptor. */
static const uint8_t USBD_LangIDDesc[] = {
    USB_LEN_LANGID_STR_DESC,
    USB_DESC_TYPE_STRING,
    LO(USBD_LANGID_STRING),
    HI(USBD_LANGID_STRING)
};
// clang-format on

static void patch_interface_descriptor(uint8_t *desc, uint8_t *desc_end, uint8_t ifnum, uint8_t epin, uint8_t epout,
                                       uint8_t ep_size) {
  while (desc < desc_end) {
    switch (desc[1]) {
    case USB_DESC_TYPE_INTERFACE:
      desc[2] = ifnum;
      break;
    case USB_DESC_TYPE_ENDPOINT:
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

void USBD_DescriptorInit(void) {
  uint8_t *desc = USBD_FS_CfgDesc + USB_LEN_CFG_DESC;
  uint8_t nIface = 3;

  memcpy(desc, USBD_FS_IfDesc_CTAPHID, sizeof(USBD_FS_IfDesc_CTAPHID));
  patch_interface_descriptor(desc, desc + sizeof(USBD_FS_IfDesc_CTAPHID), USBD_CANOKEY_CTAPHID_IF, EP_IN(ctap_hid),
                             EP_OUT(ctap_hid), EP_SIZE(ctap_hid));
  desc += sizeof(USBD_FS_IfDesc_CTAPHID);

  memcpy(desc, USBD_FS_IfDesc_WEBUSB, sizeof(USBD_FS_IfDesc_WEBUSB));
  patch_interface_descriptor(desc, desc + sizeof(USBD_FS_IfDesc_WEBUSB), USBD_CANOKEY_WEBUSB_IF, 0, 0, 0);
  desc += sizeof(USBD_FS_IfDesc_WEBUSB);

  memcpy(desc, USBD_FS_IfDesc_CCID, sizeof(USBD_FS_IfDesc_CCID));
  patch_interface_descriptor(desc, desc + sizeof(USBD_FS_IfDesc_CCID), USBD_CANOKEY_CCID_IF, EP_IN(ccid), EP_OUT(ccid),
                             EP_SIZE(ccid));
  desc += sizeof(USBD_FS_IfDesc_CCID);

  if (IS_ENABLED_IFACE(USBD_CANOKEY_KBDHID_IF)) {
    nIface++;
    memcpy(desc, USBD_FS_IfDesc_KBDHID, sizeof(USBD_FS_IfDesc_KBDHID));
    patch_interface_descriptor(desc, desc + sizeof(USBD_FS_IfDesc_KBDHID), USBD_CANOKEY_KBDHID_IF, EP_IN(kbd_hid),
                               EP_OUT(kbd_hid), EP_SIZE(kbd_hid));
    desc += sizeof(USBD_FS_IfDesc_KBDHID);
  }
  uint16_t totalLen = (uint16_t)(desc - USBD_FS_CfgDesc);
  USBD_FS_CfgDesc[4] = nIface;
  USBD_FS_CfgDesc[2] = totalLen & 0xFF;
  USBD_FS_CfgDesc[3] = totalLen >> 8;
}

/* Internal string descriptor. */
uint8_t USBD_StrDesc[USBD_MAX_STR_DESC_SIZ];

const uint8_t *USBD_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_FS_DeviceDesc);
  return USBD_FS_DeviceDesc;
}

const uint8_t *USBD_ConfigurationDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_FS_CfgDesc);
  return USBD_FS_CfgDesc;
}

const uint8_t *USBD_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_LangIDDesc);
  return USBD_LangIDDesc;
}

const uint8_t *USBD_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  USBD_GetString((uint8_t *)USBD_PRODUCT_STRING, USBD_StrDesc, length);
  return USBD_StrDesc;
}

const uint8_t *USBD_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  USBD_GetString((uint8_t *)USBD_MANUFACTURER_STRING, USBD_StrDesc, length);
  return USBD_StrDesc;
}

const uint8_t *USBD_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  uint8_t sn[4];
  char sn_str[9];
  fill_sn(sn);
  sprintf(sn_str, "%02X%02X%02X%02X", sn[0], sn[1], sn[2], sn[3]);
  USBD_GetString((uint8_t *)sn_str, USBD_StrDesc, length);
  return USBD_StrDesc;
}

const uint8_t *USBD_BOSDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_FS_BOSDesc);
  memcpy(USBD_StrDesc, USBD_FS_BOSDesc, sizeof(USBD_FS_BOSDesc)); // use USBD_StrDesc to store this descriptor
  USBD_StrDesc[28] = cfg_is_webusb_landing_enable();
  return USBD_StrDesc;
}

const uint8_t *USBD_MSOS20Descriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_FS_MSOS20Desc);
  return USBD_FS_MSOS20Desc;
}

const uint8_t *USBD_UsrStrDescriptor(USBD_SpeedTypeDef speed, uint8_t index, uint16_t *length) {
  switch (index) {
  case USBD_CTAPHID_INTERFACE_IDX:
    USBD_GetString((uint8_t *)USBD_CTAPHID_INTERFACE_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
  case USBD_CCID_INTERFACE_IDX:
    USBD_GetString((uint8_t *)USBD_CCID_INTERFACE_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
  case USBD_WEBUSB_INTERFACE_IDX:
    USBD_GetString((uint8_t *)USBD_WEBUSB_INTERFACE_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
  case USBD_KBDHID_INTERFACE_IDX:
    USBD_GetString((uint8_t *)USBD_KBDHID_INTERFACE_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
  }
  *length = 0;
  return NULL;
}

const uint8_t *USBD_UrlDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_FS_URL_DESCRIPTOR);
  return USBD_FS_URL_DESCRIPTOR;
}
