#include <usbd_canokey.h>
#include <usbd_ccid.h>
#include <usbd_core.h>
#include <usbd_ctaphid.h>
#include <usbd_desc.h>

#define USBD_VID 0xABCDu
#define USBD_PID 0x0123u
#define USBD_LANGID_STRING 0x0409u
#define USBD_MANUFACTURER_STRING "Canopo"
#define USBD_PRODUCT_STRING "Canokey"
#define USBD_SERIALNUMBER_STRING "000000000000"
#define USBD_CCID_INTERFACE_STRING "CCID"
#define USBD_CCID_INTERFACE_IDX 0x10
#define USBD_OPENPGP_INTERFACE_STRING "OpenPGP Card"
#define USBD_OPENPGP_INTERFACE_IDX 0x11

// clang-format off
const uint8_t *USBD_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_ConfigurationDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_BOSDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
const uint8_t *USBD_UsrStrDescriptor(USBD_SpeedTypeDef speed, uint8_t index, uint16_t *length);

const USBD_DescriptorsTypeDef usbdDescriptors = {
    USBD_DeviceDescriptor,
    USBD_ConfigurationDescriptor,
    USBD_LangIDStrDescriptor,
    USBD_ManufacturerStrDescriptor,
    USBD_ProductStrDescriptor,
    USBD_SerialStrDescriptor,
    USBD_BOSDescriptor,
    USBD_UsrStrDescriptor
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

static const uint8_t USBD_FS_CfgDesc[] = {
    0x09,                        /* bLength: Configuration Descriptor size */
    USB_DESC_TYPE_CONFIGURATION, /* bDescriptorType: Configuration */
    0xC3, 0x00,                  /* wTotalLength: Bytes returned */
    0x03,                        /* bNumInterfaces: 3 interfaces */
    0x01,                        /* bConfigurationValue: Configuration value */
    0x00,                        /* Configuration: Index of string descriptor describing the configuration */
    0x80,                        /* bmAttributes: bus powered */
    0x32,                        /* MaxPower 100 mA: this current is used for detecting Vbus */
    /************** Descriptor of CTAP HID interface ****************/
    /* 09 */
    0x09,                    /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE, /* bDescriptorType: Interface descriptor type */
    USBD_CANOKEY_CTAPHID_IF, /* bInterfaceNumber: Number of Interface */
    0x00,                    /* bAlternateSetting: Alternate setting */
    0x02,                    /* bNumEndpoints */
    0x03,                    /* bInterfaceClass: HID */
    0x00,                    /* bInterfaceSubClass: 0=no boot */
    0x00,                    /* nInterfaceProtocol: 0=none */
    0,                       /* iInterface: Index of string descriptor */
    /******************** Descriptor of CTAP HID *************************/
    /* 18 */
    0x09,                    /* bLength: CTAP HID Descriptor size */
    CTAPHID_DESCRIPTOR_TYPE, /* bDescriptorType: HID */
    0x11, 0x01,              /* bCTAP_HID: CTAP HID Class Spec release number */
    0x00,                    /* bCountryCode: Hardware target country */
    0x01,                    /* bNumDescriptors: 1 */
    0x22,                    /* bDescriptorType */
    CTAPHID_REPORT_DESC_SIZE,/* wItemLength: Total length of Report descriptor */
    0x00,
    /**************** Descriptor of CTAP HID endpoints ****************/
    /* 27 */
    0x07,                     /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,   /* bDescriptorType: */
    CTAPHID_EPIN_ADDR,        /* bEndpointAddress: Endpoint Address (IN) */
    0x03,                     /* bmAttributes: Interrupt endpoint */
    CTAPHID_EPIN_SIZE,        /* wMaxPacketSize: 64 Byte max */
    0x00, 0x05,               /* bInterval: Polling Interval (5 ms) */
    /* 34 */
    0x07,                     /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,   /* bDescriptorType: */
    CTAPHID_EPOUT_ADDR,       /* bEndpointAddress: Endpoint Address (OUT) */
    0x03,                     /* bmAttributes: Interrupt endpoint */
    CTAPHID_EPOUT_SIZE, 0x00, /* wMaxPacketSize: 64 Bytes max  */
    0x05,                     /* bInterval: Polling Interval (5 ms) */
    /************** Descriptor of CCID interface ****************/
    /* This interface is for PIV, oath, and admin applet */
    /* 41 */
    0x09,                     /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE,  /* bDescriptorType: Interface descriptor type */
    USBD_CANOKEY_CCID_IF,     /* bInterfaceNumber: Number of Interface */
    0x00,                     /* bAlternateSetting: Alternate setting */
    0x02,                     /* bNumEndpoints */
    0x0B,                     /* bInterfaceClass: Chip/SmartCard */
    0x00,                     /* bInterfaceSubClass: 0=no boot */
    0x00,                     /* nInterfaceProtocol: 0=none */
    USBD_CCID_INTERFACE_IDX,  /* iInterface: Index of string descriptor */
    /******************** Descriptor of CCID *************************/
    /* 50 */
    0x36,                     /* bLength: CCID Descriptor size */
    0x21,                     /* bDescriptorType: Functional Descriptor type. */
    0x10,                     /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                     /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1, /* bMaxSlotIndex: highest available slot on this device */
    0x07,                     /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,   /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,   /* dwDefaultClock: 4Mhz */
    0xA0, 0x0F, 0x00, 0x00,   /* dwMaximumClock: 4Mhz */
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
    /* 104 */
    0x07,                     /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,   /* bDescriptorType: */
    CCID_EPIN_ADDR,           /* bEndpointAddress: Endpoint Address (IN) */
    USBD_EP_TYPE_BULK,        /* bmAttributes: Bulk endpoint */
    CCID_EPIN_SIZE, 0x00,     /* wMaxPacketSize: 64 Byte max */
    0x00,                     /* bInterval: Polling Interval */
    /* 111 */
    0x07,                     /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,   /* bDescriptorType: */
    CCID_EPOUT_ADDR,          /* bEndpointAddress: Endpoint Address (OUT) */
    USBD_EP_TYPE_BULK,        /* bmAttributes: Bulk endpoint */
    CCID_EPOUT_SIZE, 0x00,    /* wMaxPacketSize: 64 Bytes max  */
    0x00,                     /* bInterval: Polling Interval */
    /************** Descriptor of OPENPGP interface ****************/
    /* 118 */
    0x09,                       /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE,    /* bDescriptorType: Interface descriptor type */
    USBD_CANOKEY_OPENPGP_IF,    /* bInterfaceNumber: Number of Interface */
    0x00,                       /* bAlternateSetting: Alternate setting */
    0x02,                       /* bNumEndpoints */
    0x0B,                       /* bInterfaceClass: Chip/SmartCard */
    0x00,                       /* bInterfaceSubClass: 0=no boot */
    0x00,                       /* nInterfaceProtocol: 0=none */
    USBD_OPENPGP_INTERFACE_IDX, /* iInterface: Index of string descriptor */
    /******************** Descriptor of CCID *************************/
    /* 127 */
    0x36,                     /* bLength: CCID Descriptor size */
    0x21,                     /* bDescriptorType: Functional Descriptor type. */
    0x10,                     /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                     /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1, /* bMaxSlotIndex: highest available slot on this device */
    0x07,                     /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02, 0x00, 0x00, 0x00,   /* dwProtocols: Protocol T=1 */
    0xA0, 0x0F, 0x00, 0x00,   /* dwDefaultClock: 4Mhz */
    0xA0, 0x0F, 0x00, 0x00,   /* dwMaximumClock: 4Mhz */
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
    /* 181 */
    0x07,                     /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,   /* bDescriptorType: */
    OPENPGP_EPIN_ADDR,        /* bEndpointAddress: Endpoint Address (IN) */
    USBD_EP_TYPE_BULK,        /* bmAttributes: Bulk endpoint */
    OPENPGP_EPIN_SIZE, 0x00,  /* wMaxPacketSize: 64 Byte max */
    0x00,                     /* bInterval: Polling Interval */
    /* 188 */
    0x07,                     /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT,   /* bDescriptorType: */
    OPENPGP_EPOUT_ADDR,       /* bEndpointAddress: Endpoint Address (OUT) */
    USBD_EP_TYPE_BULK,        /* bmAttributes: Bulk endpoint */
    OPENPGP_EPOUT_SIZE, 0x00, /* wMaxPacketSize: 64 Bytes max  */
    0x00,                     /* bInterval: Polling Interval */
    /* 195 */
};

/** USB BOS descriptor. */
static const uint8_t USBD_FS_BOSDesc[] = {
    0x05,              /*bLength */
    USB_DESC_TYPE_BOS, /*bDescriptorType*/
    0x1D, 0x00,        /*total length*/
    0x01,              /*Number of device capabilities*/

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
    0x00,                   /*No landing page*/
};

/** USB lang identifier descriptor. */
static const uint8_t USBD_LangIDDesc[] = {
    USB_LEN_LANGID_STR_DESC,
    USB_DESC_TYPE_STRING,
    LO(USBD_LANGID_STRING),
    HI(USBD_LANGID_STRING)
};
// clang-format on

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
  USBD_GetString((uint8_t *)USBD_SERIALNUMBER_STRING, USBD_StrDesc, length);
  return USBD_StrDesc;
}

const uint8_t *USBD_BOSDescriptor(USBD_SpeedTypeDef speed, uint16_t *length) {
  *length = sizeof(USBD_FS_BOSDesc);
  return USBD_FS_BOSDesc;
}

const uint8_t *USBD_UsrStrDescriptor(USBD_SpeedTypeDef speed, uint8_t index, uint16_t *length) {
  switch (index) {
  case USBD_CCID_INTERFACE_IDX:
    USBD_GetString((uint8_t *)USBD_CCID_INTERFACE_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
  case USBD_OPENPGP_INTERFACE_IDX:
    USBD_GetString((uint8_t *)USBD_OPENPGP_INTERFACE_STRING, USBD_StrDesc, length);
    return USBD_StrDesc;
  }
  *length = 0;
  return NULL;
}
