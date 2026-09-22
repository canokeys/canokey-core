// SPDX-License-Identifier: Apache-2.0
#include <usbd_canokey.h>
#include <usbd_ccid.h>
#include <usbd_ctlreq.h>
#include <usbd_desc.h>
static const uint8_t device[] = {18,           1, 0, 2, 0, 0, 0, 16, LO(USBD_VID), HI(USBD_VID), LO(USBD_PID),
                                 HI(USBD_PID), 0, 1, 1, 2, 0, 1};
static const uint8_t language[] = {4, 3, 9, 4};
static const uint8_t configuration[] = {
    9,
    2,
    86,
    0,
    1,
    1,
    0,
    0x80,
    50,
    /************** Descriptor of CCID interface ****************/
    /* Minimal Rust core: no implied applet support. */
    0x09,                    /* bLength: Interface Descriptor size */
    USB_DESC_TYPE_INTERFACE, /* bDescriptorType: Interface descriptor type */
    0,                       /* bInterfaceNumber: Number of Interface */
    0x00,                    /* bAlternateSetting: Alternate setting */
    0x02,                    /* bNumEndpoints */
    0x0B,                    /* bInterfaceClass: Chip/SmartCard */
    0x00,                    /* bInterfaceSubClass: 0=no boot */
    0x00,                    /* nInterfaceProtocol: 0=none */
    0,                       /* iInterface: Index of string descriptor */
    /******************** Descriptor of CCID *************************/
    0x36,                     /* bLength: CCID Descriptor size */
    0x21,                     /* bDescriptorType: Functional Descriptor type. */
    0x10,                     /* bcdCCID(LSB): CCID Class Spec release number (1.10) */
    0x01,                     /* bcdCCID(MSB) */
    CCID_NUMBER_OF_SLOTS - 1, /* bMaxSlotIndex: highest available slot on this device */
    0x07,                     /* bVoltageSupport: 5.0V/3.3V/1.8V*/
    0x02,
    0x00,
    0x00,
    0x00, /* dwProtocols: Protocol T=1 */
    0xA0,
    0x0F,
    0x00,
    0x00, /* dwDefaultClock: 4MHz */
    0xA0,
    0x0F,
    0x00,
    0x00, /* dwMaximumClock: 4MHz */
    0x00, /* bNumClockSupported : no setting from PC */
    0x00,
    0xB0,
    0x04,
    0x00, /* dwDataRate: Default ICC I/O data rate */
    0x00,
    0xB0,
    0x04,
    0x00,    /* dwMaxDataRate: Maximum supported ICC I/O data */
    0x00,    /* bNumDataRatesSupported : no setting from PC */
    LO(261), /* dwMaxIFSD, B3 */
    HI(261), /* dwMaxIFSD, B2 */
    0x00,
    0x00, /* dwMaxIFSD, B1B0 */
    0x00,
    0x00,
    0x00,
    0x00, /* dwSynchProtocols  */
    0x00,
    0x00,
    0x00,
    0x00, /* dwMechanical: no special characteristics */
    0xFE,
    0x00,
    0x02,
    0x00,    /* dwFeatures */
    LO(271), /* dwMaxCCIDMessageLength, B3 */
    HI(271), /* dwMaxCCIDMessageLength, B2 */
    0x00,
    0x00, /* dwMaxCCIDMessageLength, B1B0 */
    0xFF, /* bClassGetResponse*/
    0xFF, /* bClassEnvelope */
    0x00,
    0x00,                 /* wLcdLayout: 0000h no LCD */
    0x00,                 /* bPINSupport: no PIN */
    CCID_NUMBER_OF_SLOTS, /* bMaxCCIDBusySlots*/
    /**************** Descriptor of CCID endpoints ****************/
    0x07,                   /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT, /* bDescriptorType: */
    EP_IN(ccid),            /* bEndpointAddress: Endpoint Address (IN) */
    USBD_EP_TYPE_BULK,      /* bmAttributes: Bulk endpoint */
    EP_SIZE(ccid),
    0x00,                   /* wMaxPacketSize: 64 Byte max */
    0x00,                   /* bInterval: Polling Interval */
    0x07,                   /* bLength: Endpoint Descriptor size */
    USB_DESC_TYPE_ENDPOINT, /* bDescriptorType: */
    EP_OUT(ccid),           /* bEndpointAddress: Endpoint Address (OUT) */
    USBD_EP_TYPE_BULK,      /* bmAttributes: Bulk endpoint */
    EP_SIZE(ccid),
    0x00, /* wMaxPacketSize: 64 Bytes max  */
    0x00, /* bInterval: Polling Interval */
};
_Static_assert(sizeof(configuration) == 86, "CCID configuration length");
static uint8_t strings[64];
static const uint8_t *dev(USBD_SpeedTypeDef s, uint16_t *n) {
  UNUSED(s);
  *n = sizeof(device);
  return device;
}
static const uint8_t *cfg(USBD_SpeedTypeDef s, uint16_t *n) {
  UNUSED(s);
  *n = sizeof(configuration);
  return configuration;
}
static const uint8_t *lang(USBD_SpeedTypeDef s, uint16_t *n) {
  UNUSED(s);
  *n = sizeof(language);
  return language;
}
static const uint8_t *string(const char *text, uint16_t *n) {
  size_t len = strlen(text);
  strings[0] = (uint8_t)(2 + 2 * len);
  strings[1] = 3;
  for (size_t i = 0; i < len; i++) {
    strings[2 + 2 * i] = (uint8_t)text[i];
    strings[3 + 2 * i] = 0;
  }
  *n = strings[0];
  return strings;
}
static const uint8_t *manufacturer(USBD_SpeedTypeDef s, uint16_t *n) {
  UNUSED(s);
  return string("canokeys.org", n);
}
static const uint8_t *product(USBD_SpeedTypeDef s, uint16_t *n) {
  UNUSED(s);
  return string("CanoKey Rust Core", n);
}
static const uint8_t *empty(USBD_SpeedTypeDef s, uint16_t *n) {
  UNUSED(s);
  *n = 0;
  return NULL;
}
static const uint8_t *user_string(USBD_SpeedTypeDef s, uint8_t i, uint16_t *n) {
  UNUSED(i);
  return empty(s, n);
}
const USBD_DescriptorsTypeDef usbdDescriptors = {dev,   cfg,   lang,  manufacturer, product,
                                                 empty, empty, empty, user_string,  empty};
static uint8_t init(USBD_HandleTypeDef *d, uint8_t c) {
  UNUSED(c);
  USBD_CCID_Init(d);
  USBD_LL_Init_Done();
  return USBD_OK;
}
static uint8_t deinit(USBD_HandleTypeDef *d, uint8_t c) {
  UNUSED(c);
  CCID_Init();
  USBD_LL_CloseEP(d, EP_IN(ccid));
  USBD_LL_CloseEP(d, EP_OUT(ccid));
  return USBD_OK;
}
static uint8_t setup(USBD_HandleTypeDef *d, USBD_SetupReqTypedef *r) {
  if (r->wIndex == 0 && (r->bmRequest & USB_REQ_TYPE_MASK) == USB_REQ_TYPE_STANDARD) {
    if (r->bRequest == USB_REQ_GET_INTERFACE) {
      static const uint8_t alternate = 0;
      return USBD_CtlSendData(d, &alternate, 1, 0);
    }
    if (r->bRequest == USB_REQ_SET_INTERFACE && r->wValue == 0) return USBD_OK;
  }
  USBD_CtlError(d, r);
  return USBD_FAIL;
}
static uint8_t ep0(USBD_HandleTypeDef *d) {
  UNUSED(d);
  return USBD_OK;
}
static uint8_t in(USBD_HandleTypeDef *d, uint8_t ep) { return ep == EP_OUT(ccid) ? USBD_CCID_DataIn(d) : USBD_FAIL; }
static uint8_t out(USBD_HandleTypeDef *d, uint8_t ep) { return ep == EP_OUT(ccid) ? USBD_CCID_DataOut(d) : USBD_FAIL; }
const USBD_ClassTypeDef USBD_CANOKEY = {init, deinit, setup, ep0, ep0, in, out};
