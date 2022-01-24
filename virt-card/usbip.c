// SPDX-License-Identifier: Apache-2.0
#include "apdu.h"
#include "ccid.h"
#include "device.h"
#include "fabrication.h"
#include "oath.h"
#include "usb_device.h"
#include "usbd_conf.h"
#include "usbd_core.h"
#include "usbd_desc.h"
#include "webusb.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * canonical protocol for interrupt in/out
 * captured in wire
 *
SubIntrIN:  00000001 00000d05 0001000f 00000001 00000001 00000200 00000040 ffffffff 00000000 00000004 00000000 00000000 
SubIntrOUT: 00000001 00000d06 0001000f 00000000 00000001 00000000 00000040 ffffffff 00000000 00000004 00000000 00000000 ffffffff860008a784ce5ae212376300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
RetIntrOut: 00000003 00000d06 00000000 00000000 00000000 00000000 00000040 ffffffff 00000000 00000000 00000000 00000000 
RetIntrIn:  00000003 00000d05 00000000 00000000 00000000 00000000 00000040 ffffffff 00000000 00000000 00000000 00000000 ffffffff860011a784ce5ae2123763612891b1020100000400000000000000000000000000000000000000000000000000000000000000000000000000000000
 */

struct CmdSubmitBody {
  uint32_t seq_num;
  uint32_t dev_id;
  uint32_t direction;
  uint32_t ep;
  uint32_t transfer_flags;
  uint32_t transfer_buffer_length;
  uint32_t start_frame;
  uint32_t number_of_packets;
  uint32_t interval;
  uint8_t setup[8];
};

struct RetSubmitBody {
  uint32_t seq_num;
  uint32_t dev_id;
  uint32_t direction;
  uint32_t ep;
  uint32_t status;
  uint32_t actual_length;
  uint32_t start_frame;
  uint32_t number_of_packets;
  uint32_t error_count;
  uint8_t setup[8];
};

struct CmdUnlinkBody {
  uint32_t seq_num;
  uint32_t dev_id;
  uint32_t direction;
  uint32_t ep;
  uint32_t seq_num_submit;
  uint8_t padding[24];
};

struct RetUnlinkBody {
  uint32_t seq_num;
  uint32_t dev_id;
  uint32_t direction;
  uint32_t ep;
  uint32_t status;
  uint8_t padding[24];
};

#define EP_RX_BUFFER_MAXSIZE 1024
#define EP_TX_BUFFER_MAXSIZE 4096
struct Endpoint {
  uint8_t *rx_buffer;
  uint16_t rx_size;

  uint8_t tx_buffer[EP_TX_BUFFER_MAXSIZE];
  uint16_t tx_size;
  uint16_t tx_pos;

  uint8_t type;
  uint8_t mps;

  struct CmdSubmitBody submit;

  /* For INTR IN only */
  struct CmdSubmitBody intr_in;
  uint8_t host_ready;
};

// global state
// CTRL INTR BULK
#define EP_NUM 3
struct Endpoint endpoints[EP_NUM];
int initialized = 0;

// utilities
int write_exact(int fd, const uint8_t *buffer, size_t write_len) {
  size_t offset = 0;
  while (offset < write_len) {
    int res = write(fd, &buffer[offset], write_len - offset);
    if (res <= 0) {
      perror("write");
      return -1;
    }
    offset += res;
  }
  return 0;
}

int read_exact(int fd, uint8_t *buffer, size_t read_len) {
  size_t offset = 0;
  while (offset < read_len) {
    int res = read(fd, &buffer[offset], read_len - offset);
    if (res <= 0) {
      perror("read");
      return -1;
    }
    offset += res;
  }
  return 0;
}

uint8_t endpoint_ready(uint8_t ep) {
  return endpoints[ep].host_ready && endpoints[ep].tx_size != 0;
}

void endpoint_mark_ready(uint8_t ep, uint8_t ready) {
  endpoints[ep].host_ready = ready;
}

void endpoint_clear(int ep) {
  endpoints[ep].tx_size = 0;
  endpoints[ep].tx_pos = 0;
  endpoint_mark_ready(ep, 0);
}

void endpoints_init() {
  for(int ep = 0; ep != EP_NUM; ++ep) {
    bzero(&endpoints[ep].submit, sizeof(endpoints[ep].submit));
    endpoint_clear(ep);
  }
}

// mock device functions

USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep, uint8_t type, uint16_t mps) {
  DBG_MSG("ep %d type %d mps %d\n", ep, type, mps);
  // type/mps are the same for OUT/IN
  ep = ep & 0x7F;
  endpoints[ep].type = type;
  endpoints[ep].mps = mps;
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep) { return USBD_OK; }
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep) { return 0; }
USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep, uint8_t *pbuf, uint16_t size) {
  DBG_MSG("ep %d size %d\n", ep, size);
  ep = ep & 0x7F;
  endpoints[ep].rx_buffer = pbuf;
  endpoints[ep].rx_size = size;
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep, const uint8_t *pbuf, uint16_t size) {
  // handle set-address LL_Transmit
  // no traffic during initialization should go to TCP
  if (!initialized) return USBD_OK;
  DBG_MSG("ep %d size %d\n", ep, size);
  ep = ep & 0x7F;
  memcpy(endpoints[ep].tx_buffer + endpoints[ep].tx_size,
          pbuf, size);
  endpoints[ep].tx_size += size;
  if (ep != 0) USBD_LL_DataInStage(&usb_device, ep, NULL);
  return USBD_OK;
}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep) { return endpoints[ep].rx_size; }

/* Override the function defined in usb_device.c */
void usb_resources_alloc(void) {
  uint8_t iface = 0;
  uint8_t ep = 1;

  // 0xFF for disable
  // doc: interfaces/USB/device/usb_device.h
  memset(&IFACE_TABLE, 0xFF, sizeof(IFACE_TABLE));
  memset(&EP_TABLE, 0xFF, sizeof(EP_TABLE));

  EP_TABLE.ctap_hid = ep++;
  IFACE_TABLE.ctap_hid = iface++;
  EP_SIZE_TABLE.ctap_hid = 64;

  IFACE_TABLE.webusb = iface++;

  EP_TABLE.ccid = ep++;
  IFACE_TABLE.ccid = iface++;
  EP_SIZE_TABLE.ccid = 64;

  /*
   * remember to modify EP_NUM and descriptor in usbip_devlist
   * if you want to enable KBDHID
   */
  //EP_TABLE.kbd_hid = ep;
  //IFACE_TABLE.kbd_hid = iface;
  //EP_SIZE_TABLE.kbd_hid = 8;
}

void sigint_handler() {
  static time_t last_time = 0;
  time_t cur_time = time(NULL);
  if (cur_time - last_time < 2) {
    fprintf(stderr, "Received Ctrl-C, quitting\n");
    exit(0);
  } else {
    last_time = cur_time;
    set_touch_result(!get_touch_result());
    fprintf(stderr, "Toggling touch status to %hhu, re-type Ctrl-C again quickly to quit\n", get_touch_result());
  }
}

void usbip_payload_rx(int client_fd, uint32_t ep) {
  uint32_t transfer_buffer_length = ntohl(endpoints[ep].submit.transfer_buffer_length);
  printf("[DBG] usbip_payload_rx:\tTransfer buffer: %u bytes\n", transfer_buffer_length);
  while (transfer_buffer_length > 0) {
    uint8_t *transfer_buffer = endpoints[ep].rx_buffer;
    uint32_t transfer_size = endpoints[ep].rx_size;
    if (transfer_buffer_length < transfer_size) transfer_size = transfer_buffer_length;
    if (read_exact(client_fd, transfer_buffer, transfer_size) < 0) return;
    transfer_buffer_length -= transfer_size;

    for (int i = 0; i < transfer_size; i++) {
      printf(" %02X", transfer_buffer[i]);
    }
    printf("\n");

    endpoints[ep].rx_size = transfer_size;
    USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);
  }
}

void usbip_tx_submit_zero(int client_fd, uint8_t ep) {
  // mainly used for BULK OUT, and INTR OUT
  printf("<- RET_SUBMIT_ZERO: seq %d\n", ntohl(endpoints[ep].submit.seq_num));

  struct RetSubmitBody body;
  body.seq_num = endpoints[ep].submit.seq_num;
  body.dev_id = 0;
  body.direction = 0;
  body.ep = 0; // see wire format above
  body.status = 0;
  // for interrupt, special value for actual length
  if(endpoints[ep].type == USBD_EP_TYPE_INTR) { // interrupt ep
    body.actual_length = endpoints[ep].submit.transfer_buffer_length;
  } else {
    body.actual_length = 0;
  }
  body.start_frame = 0xffffffff; // see wire data above
  body.number_of_packets = 0;
  body.error_count = 0;
  bzero(body.setup, 8);

  uint8_t command[4] = {0, 0, 0, 3};
  write_exact(client_fd, command, sizeof(command));
  write_exact(client_fd, (uint8_t *)&body, sizeof(body));
}

void usbip_tx_submit(int client_fd, uint8_t ep) {
  struct CmdSubmitBody *submit;
  if(endpoints[ep].type == USBD_EP_TYPE_INTR) {
    submit = &endpoints[ep].intr_in;
  } else {
    submit = &endpoints[ep].submit;
  }
  struct RetSubmitBody body;
  body.seq_num = submit->seq_num;
  body.dev_id = 0;
  body.direction = 0;
  body.ep = 0; // see wire format above
  body.status = 0;
  // for interrupt, special value for actual length
  uint32_t actual_length;
  if(endpoints[ep].type == USBD_EP_TYPE_INTR) { // interrupt ep
    actual_length = ntohl(submit->transfer_buffer_length);
  } else {
    actual_length = endpoints[ep].tx_size;
  }
  body.actual_length = htonl(actual_length);
  body.start_frame = 0xffffffff; // see wire data above
  body.number_of_packets = 0;
  body.error_count = 0;
  bzero(body.setup, 8);
  printf("<- RET_SUBMIT: seq %d size %d\n",
      ntohl(submit->seq_num), actual_length);

  uint8_t command[4] = {0, 0, 0, 3};
  write_exact(client_fd, command, sizeof(command));
  write_exact(client_fd, (uint8_t *)&body, sizeof(body));
  // data
  if(endpoints[ep].type == USBD_EP_TYPE_INTR) {
    write_exact(client_fd, endpoints[ep].tx_buffer + endpoints[ep].tx_pos,
        actual_length);
    endpoints[ep].tx_pos += actual_length;
  } else {
    write_exact(client_fd, endpoints[ep].tx_buffer, endpoints[ep].tx_size);
    endpoints[ep].tx_pos = endpoints[ep].tx_size;
  }

  // clear out processed request
  if (endpoints[ep].tx_pos == endpoints[ep].tx_size) {
    printf("-- RET_SUBMIT: clear ep %d\n", ep);
    endpoint_clear(ep);
    // for INTR IN only
    endpoint_mark_ready(ep, 0);
  }
}

void usbip_tx_unlink(int client_fd, struct RetUnlinkBody *ret) {
  printf("<- RET_UNLINK\n");
  uint8_t command[4] = {0, 0, 0, 4};
  write_exact(client_fd, command, sizeof(command));
  write_exact(client_fd, (uint8_t *)ret, sizeof(struct RetUnlinkBody));
}

int usbip_devlist(int client_fd) {
  // REQ_DEVLIST
  printf("-> OP_REQ_DEVLIST\n");

  // status
  uint8_t status[4];
  if (read_exact(client_fd, status, sizeof(status)) < 0) return -1;

  printf("<- OP_RET_DEVLIST\n");
  // NOTE: devlist and import must before submit/unlink
  //       hence calling write_exact is acceptable
  // resp
  uint8_t resp_header[] = {
      // version 273
      0x01,
      0x11,
      // reply code
      0x00,
      0x05,
      // status
      0x00,
      0x00,
      0x00,
      0x00,
      // number of exported devices=1
      0x00,
      0x00,
      0x00,
      0x01,
  };
  if (write_exact(client_fd, resp_header, sizeof(resp_header)) < 0) return -1;

  uint8_t path[256];
  strcpy((char *)path, "/sys/device/pci0000:00/0000:00:01.2/usb1/1-1");
  if (write_exact(client_fd, path, sizeof(path)) < 0) return -1;

  uint8_t bus_id[32];
  strcpy((char *)bus_id, "1-1");
  if (write_exact(client_fd, bus_id, sizeof(bus_id)) < 0) return -1;

  uint8_t resp_body[] = {
      // bus num
      0x00,
      0x00,
      0x00,
      0x01,
      // dev num
      0x00,
      0x00,
      0x00,
      0x02,
      // speed = high
      0x00,
      0x00,
      0x00,
      0x03,
      // idVendor
      LO(USBD_VID),
      HI(USBD_VID),
      // idProduct
      LO(USBD_PID),
      HI(USBD_PID),
      // bcdDevice
      0x00,
      0x01,
      // bDeviceClass
      0x00,
      // bDeviceSubClass
      0x00,
      // bDeviceProtocol
      0x00,
      // bConfigurationValue
      0x01,
      // bNumConfigurations
      USBD_MAX_NUM_CONFIGURATION,
      // bNumInterfaces
      // disable keyboard interface
      0x03,//USBD_MAX_NUM_INTERFACES,
      // interface 1
      // bInterfaceClass
      0x03,
      // bInterfaceSubClass
      0x00,
      // bInterfaceProtocol
      0x00,
      // bPadding
      0x00,
      // disable keyboard interface
      //// interface 2
      //// bInterfaceClass
      //0x03,
      //// bInterfaceSubClass
      //0x00,
      //// bInterfaceProtocol
      //0x00,
      //// bPadding
      //0x00,
      // interface 3
      // bInterfaceClass
      0xFF,
      // bInterfaceSubClass
      0xFF,
      // bInterfaceProtocol
      0xFF,
      // bPadding
      0x00,
      // interface 4
      // bInterfaceClass
      0x0B,
      // bInterfaceSubClass
      0x00,
      // bInterfaceProtocol
      0x00,
      // bPadding
      0x00,
  };
  if (write_exact(client_fd, resp_body, sizeof(resp_body)) < 0) return -1;
  return 0;
}

int usbip_import(int client_fd) {
  // REQ_IMPORT
  printf("-> OP_REQ_IMPORT\n");

  uint8_t status[4];
  if (read_exact(client_fd, status, sizeof(status)) < 0) return -1;

  uint8_t bus_id[32];
  if (read_exact(client_fd, bus_id, sizeof(bus_id)) < 0) return -1;

  printf("->\tBus Id: %s\n", bus_id);

  printf("<- OP_RET_IMPORT\n");
  // NOTE: devlist and import must before submit/unlink
  //       hence calling write_exact is acceptable
  uint8_t resp_header[] = {
      // version 273
      0x01,
      0x11,
      // reply code
      0x00,
      0x03,
      // status
      0x00,
      0x00,
      0x00,
      0x00,
  };
  if (write_exact(client_fd, resp_header, sizeof(resp_header)) < 0) return -1;

  uint8_t path[256];
  strcpy((char *)path, "/sys/device/pci0000:00/0000:00:01.2/usb1/1-1");
  if (write_exact(client_fd, path, sizeof(path)) < 0) return -1;

  if (write_exact(client_fd, bus_id, sizeof(bus_id)) < 0) return -1;

  uint8_t resp_body[] = {
      // bus num
      0x00,
      0x00,
      0x00,
      0x01,
      // dev num
      0x00,
      0x00,
      0x00,
      0x02,
      // speed = high
      0x00,
      0x00,
      0x00,
      0x03,
      // idVendor
      LO(USBD_VID),
      HI(USBD_VID),
      // idProduct
      LO(USBD_PID),
      HI(USBD_PID),
      // bcdDevice
      0x00,
      0x01,
      // bDeviceClass
      0x00,
      // bDeviceSubClass
      0x00,
      // bDeviceProtocol
      0x00,
      // bConfigurationValue
      0x01,
      // bNumConfigurations
      USBD_MAX_NUM_CONFIGURATION,
      // bNumInterfaces
      // disable keyboard interface
      0x03,//USBD_MAX_NUM_INTERFACES,
  };
  if (write_exact(client_fd, resp_body, sizeof(resp_body)) < 0) return -1;
  return 0;
}

int usbip_submit(int client_fd) {
  // body
  struct CmdSubmitBody body;
  if (read_exact(client_fd, (uint8_t *)&body, sizeof(body)) < 0) return -1;

  uint32_t ep = ntohl(body.ep) & 0x7F;
  int direction_out = ntohl(body.direction) == 0;
  uint32_t seq_num = ntohl(body.seq_num);

  if (!direction_out && endpoints[ep].type == USBD_EP_TYPE_INTR) {
    // special submit for INTR IN
    memcpy(&endpoints[ep].intr_in, &body, sizeof(body));
  } else {
    memcpy(&endpoints[ep].submit, &body, sizeof(body));
  }

  // control
  if (endpoints[ep].type == USBD_EP_TYPE_CTRL) {
    // control transfer
    if (direction_out) {
      // control out:
      printf("->CONTROL OUT seq %d\n", seq_num);
      // setup, out, in
      printf("--CTL\tSETUP\n");
      USBD_LL_SetupStage(&usb_device, body.setup);
      printf("->CTL\tOUT\n");
      usbip_payload_rx(client_fd, ep);
      device_loop(0);
      printf("<-CTL\tIN\n");
      usbip_tx_submit(client_fd, ep);
    } else {
      // control in:
      printf("->CONTROL IN seq %d\n", seq_num);
      // setup, in, out
      printf("--CTL\tSETUP\n");
      USBD_LL_SetupStage(&usb_device, body.setup);
      printf("<-CTL\tIN\n");
      device_loop(0);
      usbip_tx_submit(client_fd, ep);
      // FIXME: should be here according to usb protocol?
      //        not clear for usbip protocol
      //printf("->CTL\tOUT\n");
      //usbip_payload_rx(client_fd, ep);
    }
  } else if (endpoints[ep].type == USBD_EP_TYPE_BULK) {
    // bulk transfer
    if (direction_out) {
      // bulk out
      printf("->BULK OUT ep %d seq %d\n", ep, seq_num);
      usbip_payload_rx(client_fd, ep);
      usbip_tx_submit_zero(client_fd, ep);
      printf("<-BULK OUT\n");
    } else {
      // bulk in
      printf("->BULK IN ep %d seq %d\n", ep, seq_num);
      device_loop(0);
      usbip_tx_submit(client_fd, ep);
      printf("<-BULK IN\n");
    }
  } else if (endpoints[ep].type == USBD_EP_TYPE_INTR) {
    // interrupt transfer
    if (direction_out) {
      // intr out
      printf("->INTR OUT ep %d seq %d\n", ep, seq_num);
      usbip_payload_rx(client_fd, ep);
      device_loop(0);
      usbip_tx_submit_zero(client_fd, ep); // OUT ZERO-LENGTH ACK
      if (endpoint_ready(ep)) // async IN reply
        usbip_tx_submit(client_fd, ep);
      printf("<-INTR OUT\n");
    } else {
      // intr in
      printf("->INTR IN ep %d seq %d\n", ep, seq_num);
      if (!endpoint_ready(ep)) {
        printf("-- DataIn\n");
        USBD_LL_DataInStage(&usb_device, ep, NULL);
        endpoint_mark_ready(ep, 1);
      } else {
        usbip_tx_submit(client_fd, ep);
      }
      printf("<-INTR IN\n");
    }
  } else {
      printf("SUBMIT unhandled: %d\n", endpoints[ep].type);
      assert(false);
  }
  return 0;
}

int usbip_unlink(int client_fd) {
  // CMD_UNLINK
  printf("-> OP_CMD_UNLINK\n");
  struct CmdUnlinkBody body;
  if (read_exact(client_fd, (uint8_t *)&body, sizeof(body)) < 0) return -1;

  // full policy doc: linux/latest/source/drivers/usb/usbip/stub_rx.c#L251
  uint32_t status = 0;
  for (int ep = 0; ep != EP_NUM; ++ep) {
    // single threaded, hence only handle INTR IN
    if (endpoints[ep].intr_in.seq_num == body.seq_num_submit) {
      printf("-- OP_CMD_UNLINK: ep %u seq %u to %u\n",
          ep, htonl(body.seq_num), htonl(endpoints[ep].intr_in.seq_num));
      status = htonl(-ECONNRESET);
      // note that in original policy, this RetUnlink is done by callback func `stub_complete`,
      // for ease of handling(we do not have callback), we implement callback here
      endpoint_mark_ready(ep, 0);
    }
  }

  struct RetUnlinkBody ret;
  ret.seq_num = body.seq_num;
  ret.dev_id = 0;
  ret.direction = 0;
  ret.ep = 0;
  ret.status = status;
  bzero(ret.padding, sizeof(ret.padding));

  usbip_tx_unlink(client_fd, &ret);
  return 0;
}

void usbip_loop(int client_fd) {
  while (1) {
    uint8_t command[4];
    if (read_exact(client_fd, command, sizeof(command)) < 0) return;

    if (command[2] == 0x80 && command[3] == 0x05) {
      if(usbip_devlist(client_fd) < 0) return;
    } else if (command[2] == 0x80 && command[3] == 0x03) {
      if(usbip_import(client_fd) < 0) return;
    } else if (command[0] == 0x00 && command[1] == 0x00 && command[2] == 0x00 && command[3] == 0x01) {
      if(usbip_submit(client_fd) < 0) return;
    } else if (command[0] == 0x00 && command[1] == 0x00 && command[2] == 0x00 && command[3] == 0x02) {
      if(usbip_unlink(client_fd) < 0) return;
    } else {
      printf("-> OP_UNKNOWN\n");
      assert(false);
    }
    printf("\n");
  }
}

int main(int argc, char **argv) {
  // parse args
  char *canokey_file = "/tmp/canokey-file";
  int port = 3240;
  int touch = 0;
  if (argc > 1)
    canokey_file = argv[1];
  printf("Using file: %s\n", canokey_file);
  if (argc > 2)
    port = atoi(argv[2]);
  if (argc > 3)
    touch = 1;

  // emulate touch by SIGINT
  signal(SIGINT, sigint_handler);

  // setup usbip server
  char *listen_addr = "127.0.0.1";
  int fd;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(listen_addr);
  addr.sin_port = htons(port);
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("setsockopt");
    return 1;
  }
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }
  if (listen(fd, SOMAXCONN) < 0) {
    perror("listen");
    return 1;
  }
  printf("listening on %s:%d\n", listen_addr, port);

  // init usb stack
  usb_device_init();
  endpoints_init();
  // set address to 1
  uint8_t set_address[] = {0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  USBD_LL_SetupStage(&usb_device, set_address);
  // unlimited max packet for ep0
  usb_device.ep_in[0].maxpacket = -1;
  usb_device.ep_out[0].maxpacket = -1;

  // access canokey_file
  if (access(canokey_file, F_OK) == 0) {
    card_read(canokey_file);
  } else {
    card_fabrication_procedure(canokey_file);
  }

  // if touch is not on,
  // emulate the NFC mode, where user-presence tests are skipped
  set_nfc_state(!touch);

  // disable stdout buffer
  setvbuf(stdout, NULL, _IONBF, 0);

  initialized = 1;

  while (1) {
    struct sockaddr_storage client_addr;
    socklen_t sock_len = sizeof(client_addr);
    int client_fd = accept(fd, (struct sockaddr *)&client_addr, &sock_len);
    if (client_fd < 0) {
      perror("accept");
      return 1;
    }
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0) {
      perror("setsockopt");
      return 1;
    }
    printf("got connection\n");

    usbip_loop(client_fd);

    printf("closing connection\n");
    close(client_fd);
  }
  return 0;
}
// vim: sts=2 ts=2 sw=2
