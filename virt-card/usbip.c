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
#include <pthread.h>
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

#define EP_TX_BUFFER_MAXSIZE 65535
struct Endpoint {
  uint8_t *rx_buffer;
  uint16_t rx_size;
  uint8_t tx_buffer[EP_TX_BUFFER_MAXSIZE];
  uint16_t tx_size;
  uint8_t tx_ready; // is device ready
  uint8_t type;
  uint8_t mps;
  struct CmdSubmitBody submit;
  uint8_t data_in; // is host ready
};

// global state
struct CmdSubmitBody current_cmd_submit_body;
int client_fd = -1;
#define EP_NUM 256
struct Endpoint endpoints[EP_NUM];
int flag = 0;
char *canokey_file = "/tmp/canokey-file";
int port = 3240;
int touch = 0;

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

// mock device functions

USBD_StatusTypeDef USBD_LL_Init(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_DeInit(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Start(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_Stop(USBD_HandleTypeDef *pdev) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_OpenEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t ep_type, uint16_t ep_mps) {
  DBG_MSG("%d %d\n", ep_type, ep_mps);
  endpoints[ep_addr].type = ep_type;
  endpoints[ep_addr].mps = ep_mps;
  return USBD_OK;
}

USBD_StatusTypeDef USBD_LL_CloseEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_FlushEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return USBD_OK; }
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return 0; }
USBD_StatusTypeDef USBD_LL_SetUSBAddress(USBD_HandleTypeDef *pdev, uint8_t dev_addr) { return USBD_OK; }
USBD_StatusTypeDef USBD_LL_PrepareReceive(USBD_HandleTypeDef *pdev, uint8_t ep_addr, uint8_t *pbuf, uint16_t size) {
  DBG_MSG("%d\n", size);
  endpoints[ep_addr].rx_buffer = pbuf;
  endpoints[ep_addr].rx_size = size;
  return USBD_OK;
}
void SendRetSubmit(const uint8_t *pbuf, uint16_t size, uint8_t ep) {
  printf("<- RET_SUBMIT: %d\n", size);
  for (size_t i = 0; i < size; i++) {
    printf("%02X ", pbuf[i]);
  }
  printf("\n");

  // command
  uint8_t command[4] = {0, 0, 0, 3};
  write_exact(client_fd, command, sizeof(command));

  struct RetSubmitBody body;
  body.seq_num = endpoints[ep].submit.seq_num;
  body.dev_id = endpoints[ep].submit.dev_id;
  body.direction = endpoints[ep].submit.direction;
  body.ep = ep;
  body.status = 0;
  body.actual_length = htonl(size);
  body.start_frame = 0;
  body.number_of_packets = 0;
  body.error_count = 0;
  memcpy(body.setup, endpoints[ep].submit.setup, 8);
  write_exact(client_fd, (uint8_t *)&body, sizeof(body));

  // data
  write_exact(client_fd, pbuf, size);
  printf("<- RET_SUBMIT: FINISH\n");

  // clear out processed request
  bzero(&endpoints[ep].submit, sizeof(endpoints[ep].submit));
}
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep_num, const uint8_t *pbuf, uint16_t size) {
  uint8_t ep = ep_num;
  DBG_MSG("%d %d %d %d\n", ep, size, endpoints[ep].data_in, endpoints[ep].tx_ready);
  if (client_fd == -1) {
    // ignore
  } else {
    flag = 1;
    if (endpoints[ep].data_in) { // if host ready, send to host
      SendRetSubmit(pbuf, size, ep_num);
      endpoints[ep].tx_size = 0;
      endpoints[ep].tx_ready = 0;
      endpoints[ep].data_in = 0;
    } else { // buffer it until host ready
      memcpy(endpoints[ep].tx_buffer, pbuf, size);
      endpoints[ep].tx_size = size;
      endpoints[ep].tx_ready = 1;
      DBG_MSG("buffer\n");
    }
  }
  return USBD_OK;
}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return endpoints[ep_addr].rx_size; }

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

void endpoint_rx(uint32_t ep) {
  uint32_t transfer_buffer_length = ntohl(current_cmd_submit_body.transfer_buffer_length);
  uint8_t *transfer_buffer = endpoints[ep].rx_buffer;
  printf("[DBG] endpoint_rx:\tTransfer buffer: %u bytes\n\t", transfer_buffer_length);
  if (read_exact(client_fd, transfer_buffer, transfer_buffer_length) < 0) {
    return;
  }
  
  for (int i = 0; i < transfer_buffer_length; i++) {
    printf(" %02X", transfer_buffer[i]);
  }
  printf("\n");
  endpoints[ep].rx_size = transfer_buffer_length;
}

void endpoint_tx(uint32_t ep) {
  endpoints[ep].data_in = 1;
  if (endpoints[ep].tx_ready) {
    // ready for data transfer 
    USBD_LL_Transmit(&usb_device, ep, endpoints[ep].tx_buffer, endpoints[ep].tx_size);
  }
  else {
    // wait for another thread
    USBD_LL_DataInStage(&usb_device, ep & 0x7F, NULL); // for all interfaces, no difference on IN and OUT
  }
}

void device_delay(int ms) {
  struct timespec spec = {.tv_sec = ms / 1000, .tv_nsec = ms % 1000 * 1000000ll};
  nanosleep(&spec, NULL);
}
uint32_t device_get_tick(void) {
  uint64_t ms, s;
  struct timespec spec;

  clock_gettime(CLOCK_MONOTONIC, &spec);

  s = spec.tv_sec;
  ms = spec.tv_nsec / 1000000;
  return (uint32_t)(s * 1000 + ms);
}
void device_set_timeout(void (*callback)(void), uint16_t timeout) {}
int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking) {
  // since device loop is single threaded, naive impl is ok
  DBG_MSG("%d\n", *lock);
  if (*lock != 0 && !blocking) {
      return -1;
  } else {
      *lock = 1;
      return 0;
  }
}
void device_spinlock_unlock(volatile uint32_t *lock) {
  // since device loop is single threaded, naive impl is ok
  DBG_MSG("%d\n", *lock);
  *lock = 0;
}
int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update) {
  // since device loop is single threaded, naive impl is ok
  DBG_MSG("\n");
  if (*var != expect)
      return -1;
  *var = update;
  return 0;
}
void led_on(void) {}
void led_off(void) {}

void* device_thread(void *vargp) {
  while(1) {
    device_loop(0);
    usleep(1);
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc > 1)
    canokey_file = argv[1];
  printf("Using file: %s\n", canokey_file);

  if (argc > 2)
    port = atoi(argv[2]);

  if (argc > 3)
    touch = 1;


  int fd;
  uint8_t bus_id[32];
  strcpy((char *)bus_id, "1-1");
  uint8_t path[256];
  strcpy((char *)path, "/sys/device/pci0000:00/0000:00:01.2/usb1/1-1");

  signal(SIGINT, sigint_handler);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
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

  printf("listening on 127.0.0.1:%d\n", port);

  // init usb stack
  usb_device_init();
  if (access(canokey_file, F_OK) == 0) {
    card_read(canokey_file);
  } else {
    card_fabrication_procedure(canokey_file);
  }
  // if touch is not on,
  // emulate the NFC mode, where user-presence tests are skipped
  set_nfc_state(!touch);
  // set address to 1
  uint8_t set_address[] = {0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  USBD_LL_SetupStage(&usb_device, set_address);
  // disable stdout buffer
  setvbuf(stdout, NULL, _IONBF, 0);

  // unlimited max packet for ep0
  usb_device.ep_in[0].maxpacket = -1;
  usb_device.ep_out[0].maxpacket = -1;

  // start device loop in another thread
  pthread_t device_thread_id;
  pthread_create(&device_thread_id, NULL, device_thread, NULL);

  while (1) {
    struct sockaddr_storage client_addr;
    socklen_t sock_len = sizeof(client_addr);
    client_fd = accept(fd, (struct sockaddr *)&client_addr, &sock_len);
    if (client_fd < 0) {
      perror("accept");
      return 1;
    }
    if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0) {
      perror("setsockopt");
      return 1;
    }
    printf("got connection\n");

    while (1) {
      uint8_t command[4];
      if (read_exact(client_fd, command, sizeof(command)) < 0) {
        break;
      }

      if (command[2] == 0x80 && command[3] == 0x05) {
        // REQ_DEVLIST
        printf("-> OP_REQ_DEVLIST\n");

        // status
        uint8_t status[4];
        if (read_exact(client_fd, status, sizeof(status)) < 0) {
          break;
        }

        printf("<- OP_RET_DEVLIST\n");
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
        if (write_exact(client_fd, resp_header, sizeof(resp_header)) < 0) {
          break;
        }

        if (write_exact(client_fd, path, sizeof(path)) < 0) {
          break;
        }

        if (write_exact(client_fd, bus_id, sizeof(bus_id)) < 0) {
          break;
        }

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
        if (write_exact(client_fd, resp_body, sizeof(resp_body)) < 0) {
          break;
        }
      } else if (command[2] == 0x80 && command[3] == 0x03) {
        // REQ_IMPORT
        printf("-> OP_REQ_IMPORT\n");

        // status
        uint8_t status[4];
        if (read_exact(client_fd, status, sizeof(status)) < 0) {
          break;
        }

        // status
        uint8_t bus_id[32];
        if (read_exact(client_fd, bus_id, sizeof(bus_id)) < 0) {
          break;
        }

        printf("->\tBus Id: %s\n", bus_id);

        printf("<- OP_RET_IMPORT\n");
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
        if (write_exact(client_fd, resp_header, sizeof(resp_header)) < 0) {
          break;
        }

        if (write_exact(client_fd, path, sizeof(path)) < 0) {
          break;
        }

        if (write_exact(client_fd, bus_id, sizeof(bus_id)) < 0) {
          break;
        }

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
        if (write_exact(client_fd, resp_body, sizeof(resp_body)) < 0) {
          break;
        }
      } else if (command[0] == 0x00 && command[1] == 0x00 && command[2] == 0x00 && command[3] == 0x01) {
        // CMD_SUBMIT
        //printf("-> OP_CMD_SUBMIT %d\n", command[3]);

        // body
        if (read_exact(client_fd, (uint8_t *)&current_cmd_submit_body, sizeof(current_cmd_submit_body)) < 0) {
          break;
        }

        uint32_t ep = ntohl(current_cmd_submit_body.ep);
        int direction_out = ntohl(current_cmd_submit_body.direction) == 0;
        if (ep != 0 && !direction_out && endpoints[ep].type == USBD_EP_TYPE_INTR) {
          // special endpoint for INTR IN
          memcpy(&endpoints[ep | 0x80].submit, &current_cmd_submit_body, sizeof(current_cmd_submit_body));
        } else {
          memcpy(&endpoints[ep].submit, &current_cmd_submit_body, sizeof(current_cmd_submit_body));
        }

        // control
        if (endpoints[ep].type == USBD_EP_TYPE_CTRL) {
          // control transfer
          if (direction_out) {
            // control out:
            printf("->CONTROL OUT\n");

            // setup, out, in
            printf("->CTL\tSETUP\n");
            USBD_LL_SetupStage(&usb_device, current_cmd_submit_body.setup);

            printf("<-CTL\tOUT\n");
            endpoint_rx(ep);
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);

            printf("->CTL\tIN\n");
            endpoint_tx(ep);
          } else {
            // control in:
            printf("->CONTROL IN\n");

            // setup, in, out
            printf("->CTL\tSETUP\n");
            USBD_LL_SetupStage(&usb_device, current_cmd_submit_body.setup);

            printf("->CTL\tIN\n");
            endpoint_tx(ep);
            
            printf("<-CTL\tOUT\n");
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);
          }
        } else if (endpoints[ep].type == USBD_EP_TYPE_BULK) {
          // bulk transfer
          if (direction_out) {
            // bulk out
            printf("->BULK OUT\n");

            endpoint_rx(ep);
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);

            // zero length packet
            SendRetSubmit(NULL, 0, ep);
            printf("<-BULK OUT\n");
          } else {
            // bulk in
            printf("->BULK IN\n");
            endpoint_tx(ep);
            printf("<-BULK IN\n");
          }
        } else if (endpoints[ep].type == USBD_EP_TYPE_INTR) {
          // interrupt transfer
          if (direction_out) {
            // intr out
            printf("->INTR OUT %d\n", ep);
            endpoint_rx(ep);
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);

            // zero length packet
            SendRetSubmit(NULL, 0, ep);
            printf("<-\tOUT\n");
          } else {
            // intr in
            printf("->INTR IN\n");

            endpoint_tx(ep | 0x80); // special ep for INTR IN
            printf("<-\tIN\n");
          }
        } else {
            printf("SUBMIT unhandled: %d\n", endpoints[ep].type);
            assert(false);
        }

      } else if (command[0] == 0x00 && command[1] == 0x00 && command[2] == 0x00 && command[3] == 0x02) {
        // CMD_UNLINK
        printf("-> OP_CMD_UNLINK\n");
        // body
        struct CmdUnlinkBody body;
        if (read_exact(client_fd, (uint8_t *)&body, sizeof(body)) < 0) {
          break;
        }
        // ret
        struct RetUnlinkBody ret;
        ret.seq_num = body.seq_num;
        ret.dev_id = body.dev_id;
        ret.direction = body.direction;
        ret.ep = body.ep;
        ret.status = 0;

        uint8_t command[4] = {0, 0, 0, 4};
        write_exact(client_fd, command, sizeof(command));
      
        if (write_exact(client_fd, (uint8_t *)&ret, sizeof(ret)) < 0) {
          break;
        }
        flag = 1;
        printf("<- OP_CMD_UNLINK\n");
      } else {
        printf("-> OP_UNKNOWN\n");
        assert(false);
      }
      if (flag) printf("\n\n");
      flag = 0;
    }
    printf("closing connection\n");

    close(client_fd);
  }
  return 0;
}
// vim: sts=2 ts=2 sw=2
