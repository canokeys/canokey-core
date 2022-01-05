// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * canokey-ffs.c -- user mode filesystem api for usb composite function
 *                  implementing canokey
 *
 * Copyright (C) 2010 Samsung Electronics
 *                    Author: Michal Nazarewicz <mina86@mina86.com>
 * Copyright (C) 2021 Canokeys.org
 *                    Author: Hongren (Zenithal) Zheng <zenithal@canokeys.org>
 */

#define _DEFAULT_SOURCE /* for endian.h */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// from linux-headers
#include <linux/usb/functionfs.h>

// from virt-card
#include "fabrication.h"

// from canokey-core
#include "usb_device.h"
#include "device.h"
#include "ccid.h"
#include "usbd_ccid.h"
#include "ctaphid.h"
#include "usbd_ctaphid.h"

struct ccid_descriptor {
  __u8  bLength;
  __u8  bDescriptorType;
  __le16 bcdCCID;
  __u8  bMaxSlotIndex;
  __u8  bVoltageSupport;
  __le32 dwProtocols;
  __le32 dwDefaultClock;
  __le32 dwMaximumClock;
  __u8  bNumClockSupported;
  __le32 dwDataRate;
  __le32 dwMaxDataRate;
  __u8  bNumDataRatesSupported;
  __le32 dwMaxIFSD;
  __le32 dwSynchProtocols;
  __le32 dwMechanical;
  __le32 dwFeatures;
  __le32 dwMaxCCIDMessageLength;
  __u8  bClassGetResponse;
  __u8  bClassEnvelope;
  __le16 wLcdLayout;
  __u8  bPINSupport;
  __u8  bMaxCCIDBusySlots;
} __attribute__ ((packed));

struct hid_descriptor {
    __u8  bLength;
    __u8  bDescriptorType;
    __le16 bcdHID;
    __u8  bCountryCode;
    __u8  bNumDescriptors;

    __u8  class_bDescriptorType;
    __le16 class_wDescriptorLength;
} __attribute__ ((packed));


/******************** Little Endian Handling ********************************/

/*
 * cpu_to_le16/32 are used when initializing structures, a context where a
 * function call is not allowed. To solve this, we code cpu_to_le16/32 in a way
 * that allows them to be used when initializing structures.
 */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x)  (x)
#define cpu_to_le32(x)  (x)
#else
#define cpu_to_le16(x)  ((((x) >> 8) & 0xffu) | (((x) & 0xffu) << 8))
#define cpu_to_le32(x)  \
  ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
  (((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))
#endif

#define le32_to_cpu(x)  le32toh(x)
#define le16_to_cpu(x)  le16toh(x)

/******************** Messages and Errors ***********************************/

static const char argv0[] = "canokey-ffs";

static unsigned verbosity = 6;

static void _msg(unsigned level, const char *fmt, ...)
{
  if (level < 2)
    level = 2;
  else if (level > 7)
    level = 7;

  if (level <= verbosity) {
    static const char levels[8][6] = {
      [2] = "crit:",
      [3] = "err: ",
      [4] = "warn:",
      [5] = "note:",
      [6] = "info:",
      [7] = "dbg: "
    };

    int _errno = errno;
    va_list ap;

    fprintf(stderr, "%s: %s ", argv0, levels[level]);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    if (fmt[strlen(fmt) - 1] != '\n') {
      char buffer[128];
      strerror_r(_errno, buffer, sizeof buffer);
      fprintf(stderr, ": (-%d) %s\n", _errno, buffer);
    }

    fflush(stderr);
  }
}

#define die(...)  (_msg(2, __VA_ARGS__), exit(1))
#define err(...)   _msg(3, __VA_ARGS__)
#define warn(...)  _msg(4, __VA_ARGS__)
#define note(...)  _msg(5, __VA_ARGS__)
#define info(...)  _msg(6, __VA_ARGS__)
#define debug(...) _msg(7, __VA_ARGS__)

#define die_on(cond, ...) do { \
  if (cond) \
    die(__VA_ARGS__); \
  } while (0)


/******************** Descriptors and Strings *******************************/

static const struct {
  struct usb_functionfs_descs_head_v2 header;
  __le32 hs_count;
  struct {
    //struct usb_interface_descriptor webusb; /* NOT AVAILABLE due to BSOD issue*/
    struct usb_interface_descriptor ccid;
    struct ccid_descriptor ccid_desc;
    struct usb_endpoint_descriptor_no_audio ccid_in;
    struct usb_endpoint_descriptor_no_audio ccid_out;
    struct usb_interface_descriptor fido;
    struct hid_descriptor fido_desc;
    struct usb_endpoint_descriptor_no_audio fido_in;
    struct usb_endpoint_descriptor_no_audio fido_out;
  } __attribute__((packed)) hs_descs;
} __attribute__((packed)) descriptors = {
  .header = {
    .magic = cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
    .flags = cpu_to_le32(FUNCTIONFS_HAS_HS_DESC),
    .length = cpu_to_le32(sizeof descriptors),
  },
  .hs_count = cpu_to_le32(8),
  .hs_descs = {
    //.webusb = {
    //  .bLength = sizeof descriptors.hs_descs.webusb,
    //  .bInterfaceNumber = 0,
    //  .bDescriptorType = USB_DT_INTERFACE,
    //  .bNumEndpoints = 0,
    //  .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
    //  .bInterfaceSubClass = USB_SUBCLASS_VENDOR_SPEC,
    //  .bInterfaceProtocol = 0xFF, /* TODO */
    //  .iInterface = 1, /* TODO */
    //},
    .ccid = {
      .bLength = sizeof descriptors.hs_descs.ccid,
      .bInterfaceNumber = 1,
      .bDescriptorType = USB_DT_INTERFACE,
      .bNumEndpoints = 2,
      .bInterfaceClass = USB_CLASS_CSCID,
      .iInterface = 4, /* STR_CCID */
    },
    .ccid_desc = {
      .bLength = sizeof descriptors.hs_descs.ccid_desc,
      .bDescriptorType = 0x21,
      .bcdCCID = cpu_to_le16(0x0110),
      .bMaxSlotIndex = 0,
      .bVoltageSupport = 7,
      .dwProtocols = cpu_to_le32(2),
      .dwDefaultClock = cpu_to_le32(0x0FA0),
      .dwMaximumClock = cpu_to_le32(0x0FA0),
      .bNumClockSupported = 0,
      .dwDataRate = cpu_to_le32(0x04B000),
      .dwMaxDataRate = cpu_to_le32(0x04B000),
      .bNumDataRatesSupported = 0,
      .dwMaxIFSD = cpu_to_le32(1342),
      .dwSynchProtocols = 0,
      .dwMechanical = 0,
      .dwFeatures = cpu_to_le32(0x0400FE),
      .dwMaxCCIDMessageLength = cpu_to_le32(1352),
      .bClassGetResponse = 0xFF,
      .bClassEnvelope = 0xFF,
      .wLcdLayout = 0,
      .bPINSupport = 0,
      .bMaxCCIDBusySlots = 1,
    },
    .ccid_in = {
      .bLength = sizeof descriptors.hs_descs.ccid_in,
      .bDescriptorType = USB_DT_ENDPOINT,
      .bEndpointAddress = 1 | USB_DIR_IN,
      .bmAttributes = USB_ENDPOINT_XFER_BULK,
      .wMaxPacketSize = cpu_to_le16(512),
      .bInterval = 1, /* NAK every 1 uframe */
    },
    .ccid_out = {
      .bLength = sizeof descriptors.hs_descs.ccid_out,
      .bDescriptorType = USB_DT_ENDPOINT,
      .bEndpointAddress = 2 | USB_DIR_OUT,
      .bmAttributes = USB_ENDPOINT_XFER_BULK,
      .wMaxPacketSize = cpu_to_le16(512),
      .bInterval = 1, /* NAK every 1 uframe */
    },
    .fido = {
      .bLength = sizeof descriptors.hs_descs.fido,
      .bInterfaceNumber = 2,
      .bDescriptorType = USB_DT_INTERFACE,
      .bNumEndpoints = 2,
      .bInterfaceClass = USB_CLASS_HID,
      .iInterface = 5,
    },
    .fido_desc = {
      .bLength = sizeof descriptors.hs_descs.fido_desc,
      .bDescriptorType = 0x21,
      .bcdHID = cpu_to_le16(0x0111),
      .bCountryCode = 0,
      .bNumDescriptors = 1,
      .class_bDescriptorType = 0x22,
      .class_wDescriptorLength = cpu_to_le16(34),
    },
    .fido_in = {
      .bLength = sizeof descriptors.hs_descs.fido_in,
      .bDescriptorType = USB_DT_ENDPOINT,
      .bEndpointAddress = 3 | USB_DIR_IN,
      .bmAttributes = USB_ENDPOINT_XFER_INT,
      .wMaxPacketSize = 64,
      .bInterval = 1,
    },
    .fido_out = {
      .bLength = sizeof descriptors.hs_descs.fido_out,
      .bDescriptorType = USB_DT_ENDPOINT,
      .bEndpointAddress = 4 | USB_DIR_OUT,
      .bmAttributes = USB_ENDPOINT_XFER_INT,
      .wMaxPacketSize = 64,
      .bInterval = 1,
    },
  },
};

#define STR_MANUFACTURER "canokeys.org"
#define STR_PRODUCT      "CanoKey FFS"
#define STR_SERIAL       "00114514"
#define STR_CCID         "OpenPGP PIV OATH"
#define STR_FIDO         "FIDO2/U2F"

static const struct {
  struct usb_functionfs_strings_head header;
  struct {
    __le16 code;
    const char str1[sizeof STR_MANUFACTURER];
    const char str2[sizeof STR_PRODUCT     ];
    const char str3[sizeof STR_SERIAL      ];
    const char str4[sizeof STR_CCID        ];
    const char str5[sizeof STR_FIDO        ];
  } __attribute__((packed)) lang0;
} __attribute__((packed)) strings = {
  .header = {
    .magic = cpu_to_le32(FUNCTIONFS_STRINGS_MAGIC),
    .length = cpu_to_le32(sizeof strings),
    .str_count = cpu_to_le32(5),
    .lang_count = cpu_to_le32(1),
  },
  .lang0 = {
    cpu_to_le16(0x0409), /* en-us */
    STR_MANUFACTURER,
    STR_PRODUCT,
    STR_SERIAL,
    STR_CCID,
    STR_FIDO,
  },
};

/* Implement USBD from canokey-core */

uint8_t setup_buffer[1500];
ssize_t setup_buffer_size;
bool setup_ready;
uint8_t ccid_buffer[1500];
ssize_t ccid_buffer_size;
bool ccid_ready;
uint8_t fido_buffer[1500];
ssize_t fido_buffer_size;
bool fido_ready;

USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t ep_type, uint16_t ep_mps) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return 0; }
USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep, uint8_t *pbuf, uint16_t size) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep, const uint8_t *pbuf, uint16_t size) {
  DBG_MSG("%d %d\n", ep, size);
  if ((ep & 0x7F) == EP_OUT(ccid)) {
    memcpy(ccid_buffer, pbuf, size);
    ccid_buffer_size = size;
    ccid_ready = true;
  } else if ((ep & 0x7F) == EP_OUT(ctap_hid)) {
    memcpy(fido_buffer, pbuf, size);
    fido_buffer_size = size;
    fido_ready = true;
  } else if (ep == 0) {
    memcpy(setup_buffer, pbuf, size);
    setup_buffer_size = size;
    setup_ready = true;
  } else {
    DBG_MSG("ep %d unknown!", ep);
  }
  return USBD_OK;
}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return 0; } // not used

/******************** Files and Threads Handling ****************************/

struct thread;

static ssize_t read_wrap(struct thread *t, void *buf, size_t nbytes);
static ssize_t write_wrap(struct thread *t, const void *buf, size_t nbytes);

static ssize_t ep0_consume(struct thread *t, const void *buf, size_t nbytes);

static ssize_t do_nothing(struct thread *t, const void *buf, size_t nbytes);
static ssize_t ccid_transmit(struct thread *t, const void *buf, size_t nbytes);
static ssize_t fido_transmit(struct thread *t, const void *buf, size_t nbytes);

static ssize_t handle_ccid_out(struct thread *t, void *buf, size_t nbytes);
static ssize_t handle_ccid_in(struct thread *t, void *buf, size_t nbytes);

static ssize_t handle_fido_out(struct thread *t, void *buf, size_t nbytes);
static ssize_t handle_fido_in(struct thread *t, void *buf, size_t nbytes);

static struct thread {
  const char *const filename;
  size_t buf_size;

  ssize_t (*in)(struct thread *, void *, size_t);

  ssize_t (*out)(struct thread *, const void *, size_t);

  int fd;
  pthread_t id;
  void *buf;
  ssize_t status;
} threads[] = {
  {
    "ep0", 8 * 1024,
    read_wrap,
    ep0_consume,
    0, 0, NULL, 0
  },
  {
    "ep1", 8 * 1024,
    handle_ccid_in,
    ccid_transmit,
    0, 0, NULL, 0
  },
  {
    "ep2", 8 * 1024,
    handle_ccid_out,
    do_nothing,
    0, 0, NULL, 0
  },
  {
    "ep3", 64,
    handle_fido_in,
    fido_transmit,
    0, 0, NULL, 0
  },
  {
    "ep4", 64,
    handle_fido_out,
    do_nothing,
    0, 0, NULL, 0
  },
};


static void init_thread(struct thread *t)
{
  t->buf = malloc(t->buf_size);
  die_on(!t->buf, "malloc");

  t->fd = open(t->filename, O_RDWR);
  die_on(t->fd < 0, "%s", t->filename);
}

static void cleanup_thread(void *arg)
{
  struct thread *t = arg;
  int ret, fd;

  fd = t->fd;
  if (t->fd < 0)
    return;
  t->fd = -1;

  /* test the FIFO ioctls (non-ep0 code paths) */
  if (t != threads) {
    ret = ioctl(fd, FUNCTIONFS_FIFO_STATUS);
    if (ret < 0) {
      /* ENODEV reported after disconnect */
      if (errno != ENODEV)
        err("%s: get fifo status", t->filename);
    } else if (ret) {
      warn("%s: unclaimed = %d\n", t->filename, ret);
      if (ioctl(fd, FUNCTIONFS_FIFO_FLUSH) < 0)
        err("%s: fifo flush", t->filename);
    }
  }

  if (close(fd) < 0)
    err("%s: close", t->filename);

  free(t->buf);
  t->buf = NULL;
}

static void *start_thread_helper(void *arg)
{
  struct thread *t = arg;
  ssize_t ret;

  info("%s: starts\n", t->filename);

  pthread_cleanup_push(cleanup_thread, arg);

  for (;;) {
    pthread_testcancel();

    ret = t->in(t, t->buf, t->buf_size);
    if (ret > 0) {
      ret = t->out(t, t->buf, ret);
    }

    if (ret > 0) {
      /* nop */
    } else if (!ret) {
      debug("EOF");
      break;
    } else if (errno == EINTR || errno == EAGAIN) {
      debug("EINTR|EAGAIN");
    } else {
      warn("WARN");
      break;
    }
  }

  pthread_cleanup_pop(1);

  t->status = ret;
  info("%s: ends\n", t->filename);
  return NULL;
}

static void start_thread(struct thread *t)
{
  debug("%s: starting\n", t->filename);

  die_on(pthread_create(&t->id, NULL, start_thread_helper, t) < 0,
         "pthread_create(%s)", t->filename);
}

static void join_thread(struct thread *t)
{
  int ret = pthread_join(t->id, NULL);

  if (ret < 0)
    err("%s: joining thread", t->filename);
  else
    debug("%s: joined\n", t->filename);
}


static ssize_t read_wrap(struct thread *t, void *buf, size_t nbytes)
{
  ssize_t ret = read(t->fd, buf, nbytes);
  debug("read_wrap: %X %d\n", t->id, ret);
  while (ret < 0) {
    debug("read error: %d\n", errno);
    t->fd = open(t->filename, O_RDWR);
    die_on(t->fd < 0, "%s", t->filename);
    ret = read(t->fd, buf, nbytes);
    debug("read_wrap: %X %d\n", t->id, ret);
  }
  //for (int i = 0; i != ret; ++i) {
  //  debug("%02X ", ((const uint8_t*)buf)[i]);
  //}
  //debug("\n");
  return ret;
}

static ssize_t write_wrap(struct thread *t, const void *buf, size_t nbytes)
{
  debug("write_wrap: %X %d\n", t->id, nbytes);
  //for (int i = 0; i != nbytes; ++i) {
  //  debug("%02X ", ((const uint8_t*)buf)[i]);
  //}
  //debug("\n");
  return write(t->fd, buf, nbytes);
}

static ssize_t handle_ccid_out(struct thread *t, void *buf, size_t nbytes) {
  ssize_t pos, len;
  ssize_t ret = read_wrap(t, buf, nbytes);
  debug("ccid_out: %d\n", ret);

  len = ret; pos = 0;
  while(len > EP_SIZE(ccid)) {
    CCID_OutEvent(buf + pos, EP_SIZE(ccid));
    len -= EP_SIZE(ccid);
    pos += EP_SIZE(ccid);
  }
  CCID_OutEvent(buf + pos, len);
  return ret;
}

static ssize_t handle_ccid_in(struct thread *t, void *buf, size_t nbytes) {
  while (!ccid_ready) { usleep(10); } // block here
  return ccid_buffer_size;
}

static ssize_t handle_fido_out(struct thread *t, void *buf, size_t nbytes) {
  ssize_t ret = read_wrap(t, buf, nbytes);
  debug("fido_out: %d\n", ret);
  CTAPHID_OutEvent(buf);
  return ret;
}

static ssize_t handle_fido_in(struct thread *t, void *buf, size_t nbytes) {
  while (!fido_ready) { usleep(10); } // block here
  return fido_buffer_size;
}

static ssize_t do_nothing(struct thread *t, const void *buf, size_t nbytes) {
  return 1;
}

static ssize_t ccid_transmit(struct thread *t, const void *buf, size_t nbytes) {
  debug("ccid_transmit: len %d\n", ccid_buffer_size);
  ssize_t in = write_wrap(t, ccid_buffer, ccid_buffer_size);
  ccid_ready = false;
  USBD_CCID_DataIn(&usb_device);
  return in;
}

static ssize_t fido_transmit(struct thread *t, const void *buf, size_t nbytes) {
  debug("fido_transmit: len %d\n", fido_buffer_size);
  ssize_t in = write_wrap(t, fido_buffer, fido_buffer_size);
  fido_ready = false;
  USBD_CTAPHID_DataIn();
  return in;
}

/******************** Endpoints routines ************************************/

// clang-format off
static const uint8_t report_desc[] = {
    0x06, 0xD0, 0xF1, // USAGE_PAGE (CTAP Usage Page)
    0x09, 0x01,       // USAGE (CTAP HID)
    0xA1, 0x01,       // COLLECTION (Application)
    0x09, 0x20,       //   USAGE (Usage Data In)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x81, 0x02,       //   INPUT (Data,Var,Abs)
    0x09, 0x21,       //   USAGE (Usage Data Out)
    0x15, 0x00,       //   LOGICAL_MINIMUM (0)
    0x26, 0xFF, 0x00, //   LOGICAL_MAXIMUM (255)
    0x75, 0x08,       //   REPORT_SIZE (8)
    0x95, 0x40,       //   REPORT_COUNT (64)
    0x91, 0x02,       //   OUTPUT (Data,Var,Abs)
    0xC0              // END_COLLECTION
};
// clang-format on

static void handle_setup(struct thread *t, const struct usb_ctrlrequest *setup)
{
  uint16_t value = le16_to_cpu(setup->wValue),
           index = le16_to_cpu(setup->wIndex),
           length = le16_to_cpu(setup->wLength);
  printf("bRequestType = %d\n", setup->bRequestType);
  printf("bRequest     = %d\n", setup->bRequest);
  printf("wValue       = %d\n", value);
  printf("wIndex       = %d\n", index);
  printf("wLength      = %d\n", length);

  // hack for CTAPHID only
  if (setup->bRequestType == 0x21) {
    read_wrap(t, t->buf, t->buf_size);
    write_wrap(t, setup_buffer, 0);
  }
  else if (setup->bRequestType & 0x80 && ((value >> 8) == 0x22)) {
    write_wrap(t, report_desc, sizeof(report_desc));
  }
}

static ssize_t
ep0_consume(struct thread *t, const void *buf, size_t nbytes)
{
  static const char *const names[] = {
    [FUNCTIONFS_BIND] = "BIND",
    [FUNCTIONFS_UNBIND] = "UNBIND",
    [FUNCTIONFS_ENABLE] = "ENABLE",
    [FUNCTIONFS_DISABLE] = "DISABLE",
    [FUNCTIONFS_SETUP] = "SETUP",
    [FUNCTIONFS_SUSPEND] = "SUSPEND",
    [FUNCTIONFS_RESUME] = "RESUME",
  };

  const struct usb_functionfs_event *event = buf;
  size_t n;

  for (n = nbytes / sizeof *event; n; --n, ++event)
    switch (event->type) {
    case FUNCTIONFS_BIND:
    case FUNCTIONFS_UNBIND:
    case FUNCTIONFS_ENABLE:
    case FUNCTIONFS_DISABLE:
    case FUNCTIONFS_SETUP:
    case FUNCTIONFS_SUSPEND:
    case FUNCTIONFS_RESUME:
      printf("Event %s\n", names[event->type]);
      if (event->type == FUNCTIONFS_SETUP)
        handle_setup(t, &event->u.setup);
      break;

    default:
      printf("Event %03u (unknown)\n", event->type);
    }

  return nbytes;
}

static void ep0_init(struct thread *t)
{
  ssize_t ret;

  info("%s: writing descriptors (in v2 format)\n", t->filename);
  ret = write(t->fd, &descriptors, sizeof descriptors);
  die_on(ret < 0, "%s: write: descriptors", t->filename);

  info("%s: writing strings\n", t->filename);
  ret = write(t->fd, &strings, sizeof strings);
  die_on(ret < 0, "%s: write: strings", t->filename);
}

/******************** Main **************************************************/

/* Override the function defined in usb_device.c */
void usb_resources_alloc(void) {
  uint8_t iface = 0;
  uint8_t ep = 1;

  // 0xFF for disable
  // doc: interfaces/USB/device/usb_device.h
  memset(&IFACE_TABLE, 0xFF, sizeof(IFACE_TABLE));
  memset(&EP_TABLE, 0xFF, sizeof(EP_TABLE));

  EP_TABLE.ccid = ep++;
  IFACE_TABLE.ccid = iface++;
  EP_SIZE_TABLE.ccid = 64; // note: must less than 255 as it is uint8_t


  EP_TABLE.ctap_hid = ep++;
  IFACE_TABLE.ctap_hid = iface++;
  EP_SIZE_TABLE.ctap_hid = 64;
}

void* device_thread(void *vargp) {
  while(1) {
    device_loop(0);
    usleep(10);
  }
  return NULL;
}

void device_init() {
  char *canokey_file = "/tmp/canokey-file";
  usb_device_init();
  if (access(canokey_file, F_OK) == 0) {
    card_read(canokey_file);
  } else {
    card_fabrication_procedure(canokey_file);
  }
  set_nfc_state(1);

  usb_device.dev_state = USBD_STATE_CONFIGURED; // ignore canokey udc

  CCID_Init();
  USBD_CTAPHID_Init(&usb_device);

  // start device loop in another thread
  pthread_t device_thread_id;
  pthread_create(&device_thread_id, NULL, device_thread, NULL);
}

int main(int argc, char **argv)
{
  unsigned i;

  device_init();

  init_thread(threads);
  ep0_init(threads);

  for (i = 1; i < sizeof threads / sizeof *threads; ++i)
    init_thread(threads + i);

  for (i = 1; i < sizeof threads / sizeof *threads; ++i)
    start_thread(threads + i);

  start_thread_helper(threads);

  for (i = 1; i < sizeof threads / sizeof *threads; ++i)
    join_thread(threads + i);

  return 0;
}
