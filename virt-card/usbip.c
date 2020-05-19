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

#define MAX_TX_BUFFERS 16
struct Endpoint {
  uint8_t *rx_buffer;
  uint16_t rx_size;
  // ring buffer as a queue
  uint8_t *tx_buffer[MAX_TX_BUFFERS];
  uint16_t tx_size[MAX_TX_BUFFERS];
  uint32_t tx_from;
  uint32_t tx_to;
  uint8_t type;
  uint8_t mps;
};

// global state
struct CmdSubmitBody current_cmd_submit_body;
int client_fd = -1;
struct Endpoint endpoints[256];

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
  endpoints[ep_addr].rx_buffer = pbuf;
  endpoints[ep_addr].rx_size = size;
  return USBD_OK;
}
void SendRetSubmit(const uint8_t *pbuf, uint16_t size) {
  if (size == 0 || pbuf != NULL) {
    printf("error size=%hu pbuf=%p\n", size, pbuf);
    return;
  }
  printf("<- RET_SUBMIT:\n\t");
  for (size_t i = 0; i < size; i++) {
    printf("%02X ", pbuf[i]);
  }
  printf("\n");

  // command
  uint8_t command[4] = {0, 0, 0, 3};
  write_exact(client_fd, command, sizeof(command));

  struct RetSubmitBody body;
  body.seq_num = current_cmd_submit_body.seq_num;
  body.dev_id = current_cmd_submit_body.dev_id;
  body.direction = current_cmd_submit_body.direction;
  body.ep = current_cmd_submit_body.ep;
  body.status = 0;
  body.actual_length = htonl(size);
  body.start_frame = 0;
  body.number_of_packets = 0;
  body.error_count = 0;
  memcpy(body.setup, current_cmd_submit_body.setup, 8);
  write_exact(client_fd, (uint8_t *)&body, sizeof(body));

  // data
  write_exact(client_fd, pbuf, size);
}
USBD_StatusTypeDef USBD_LL_Transmit(USBD_HandleTypeDef *pdev, uint8_t ep_num, const uint8_t *pbuf, uint16_t size) {
  if (client_fd == -1) {
    // ignore
  } else {
    // save to buffer
    uint32_t ep = ep_num & 0x7F;
    if (size > 0) {
      uint8_t *buffer = malloc(size);
      memcpy(buffer, pbuf, size);
      endpoints[ep].tx_buffer[endpoints[ep].tx_to] = buffer;
      endpoints[ep].tx_size[endpoints[ep].tx_to] = size;
      endpoints[ep].tx_to = (endpoints[ep].tx_to + 1) % MAX_TX_BUFFERS;
    }
  }
  return USBD_OK;
}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *pdev, uint8_t ep_addr) { return endpoints[ep_addr].rx_size; }
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
void device_disable_irq(void) {}
void device_enable_irq(void) {}
void device_set_timeout(void (*callback)(void), uint16_t timeout) {}
void fm_write_eeprom(uint16_t addr, uint8_t *buf, uint8_t len) { return; }

/* Override the function defined in usb_device.c */
void usb_resources_alloc(void) {
  uint8_t iface = 0;
  uint8_t ep = 1;

  memset(&IFACE_TABLE, 0xFF, sizeof(IFACE_TABLE));
  memset(&EP_TABLE, 0xFF, sizeof(EP_TABLE));

  EP_TABLE.ctap_hid = ep++;
  IFACE_TABLE.ctap_hid = iface++;
  EP_SIZE_TABLE.ctap_hid = 64;

  IFACE_TABLE.webusb = iface++;

  EP_TABLE.ccid = ep++;
  IFACE_TABLE.ccid = iface++;
  EP_SIZE_TABLE.ccid = 64;

  EP_TABLE.kbd_hid = ep;
  IFACE_TABLE.kbd_hid = iface;
  EP_SIZE_TABLE.kbd_hid = 8;
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
  printf("\tTransfer buffer: %u bytes\n\t", transfer_buffer_length);
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
  if (endpoints[ep].tx_from != endpoints[ep].tx_to) {
    uint32_t tx_from = endpoints[ep].tx_from;
    SendRetSubmit(endpoints[ep].tx_buffer[tx_from], endpoints[ep].tx_size[tx_from]);
    free(endpoints[ep].tx_buffer[tx_from]);
    endpoints[ep].tx_size[tx_from] = 0;
    endpoints[ep].tx_from = (endpoints[ep].tx_from + 1) % MAX_TX_BUFFERS;
  } else {
    SendRetSubmit(NULL, 0);
  }
}

int main() {
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
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(3240);

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

  printf("listening on 0.0.0.0:3240\n");

  // init usb stack
  usb_device_init();
  card_fabrication_procedure("/tmp/lfs-root");
  // set address to 1
  uint8_t set_address[] = {0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  USBD_LL_SetupStage(&usb_device, set_address);
  // disable stdout buffer
  setvbuf(stdout, NULL, _IONBF, 0);
  // unlimited max packet for ep0
  usb_device.ep_in[0].maxpacket = -1;
  usb_device.ep_out[0].maxpacket = -1;

  // oath init
  uint8_t r_buf[1024] = {0};
  // name: abc, algo: HOTP+SHA1, digit: 6, key: 0x00 0x01 0x02
  uint8_t data[] = {0x71, 0x03, 'a', 'b', 'c', 0x73, 0x05, 0x11, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = data, .ins = OATH_INS_PUT, .lc = sizeof(data)};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  oath_process_apdu(capdu, rapdu);
  // set default
  uint8_t data2[] = {0x71, 0x03, 'a', 'b', 'c'};
  capdu->data = data2;
  capdu->ins = OATH_INS_SET_DEFAULT;
  capdu->lc = sizeof(data2);
  oath_process_apdu(capdu, rapdu);

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
      printf("reading command\n");
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
            // bInterfaces
            USBD_MAX_NUM_INTERFACES,
            // interface 1
            // bInterfaceClass
            0x03,
            // bInterfaceSubClass
            0x00,
            // bInterfaceProtocol
            0x00,
            // bPadding
            0x00,
            // interface 2
            // bInterfaceClass
            0x03,
            // bInterfaceSubClass
            0x00,
            // bInterfaceProtocol
            0x00,
            // bPadding
            0x00,
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
            // bInterfaces
            USBD_MAX_NUM_INTERFACES,
        };
        if (write_exact(client_fd, resp_body, sizeof(resp_body)) < 0) {
          break;
        }
      } else if (command[0] == 0x00 && command[1] == 0x00 && command[2] == 0x00 && command[3] == 0x01) {
        // CMD_SUBMIT
        printf("-> OP_CMD_SUBMIT\n");

        // body
        if (read_exact(client_fd, (uint8_t *)&current_cmd_submit_body, sizeof(current_cmd_submit_body)) < 0) {
          break;
        }

        uint32_t ep = ntohl(current_cmd_submit_body.ep);
        printf("\tEndpoint: %u with type %hhu\n", ep, endpoints[ep].type);
        // print setup bytes
        printf("\tSetup:");
        for (int i = 0; i < 8; i++) {
          printf(" %02X", current_cmd_submit_body.setup[i]);
        }
        printf("\n");

        device_loop();

        int direction_out = ntohl(current_cmd_submit_body.direction) == 0;

        // control
        if (endpoints[ep].type == USBD_EP_TYPE_CTRL) {
          // control transfer
          if (direction_out) {
            // control out:
            printf("->CONTROL OUT\n");

            // setup, out, in
            printf("->\tSETUP\n");
            USBD_LL_SetupStage(&usb_device, current_cmd_submit_body.setup);

            printf("<-\tOUT\n");
            uint32_t transfer_buffer_length = ntohl(current_cmd_submit_body.transfer_buffer_length);
            uint8_t *transfer_buffer = endpoints[ep].rx_buffer;
            printf("\tTransfer buffer: %u bytes\n\t", transfer_buffer_length);
            if (read_exact(client_fd, transfer_buffer, transfer_buffer_length) < 0) {
              break;
            }
            for (int i = 0; i < transfer_buffer_length; i++) {
              printf(" %02X", transfer_buffer[i]);
            }
            printf("\n");
            endpoints[ep].rx_size = transfer_buffer_length;
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);

            printf("->\tIN\n");
            USBD_LL_DataInStage(&usb_device, ep, NULL);
            endpoint_tx(ep);

          } else {
            // control in:
            printf("->CONTROL IN\n");

            // setup, in, out
            printf("->\tSETUP\n");
            USBD_LL_SetupStage(&usb_device, current_cmd_submit_body.setup);

            printf("->\tIN\n");
            USBD_LL_DataInStage(&usb_device, ep, NULL);
            endpoint_tx(ep);

            printf("<-\tOUT\n");
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);
          }
        } else if (endpoints[ep].type == USBD_EP_TYPE_BULK) {
          // bulk transfer
          if (direction_out) {
            // bulk out
            printf("->BULK OUT\n");

            printf("<-\tOUT\n");
            endpoint_rx(ep);
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);

            // zero length packet
            SendRetSubmit(NULL, 0);
          } else {
            // bulk in
            printf("->BULK IN\n");

            printf("<-\tIN\n");
            endpoint_tx(ep);
          }
        } else if (endpoints[ep].type == USBD_EP_TYPE_INTR) {
          // interrupt transfer
          if (direction_out) {
            // intr out
            printf("->INTR OUT\n");

            printf("->\tOUT\n");
            endpoint_rx(ep);
            USBD_LL_DataOutStage(&usb_device, ep, endpoints[ep].rx_buffer);

            // zero length packet
            SendRetSubmit(NULL, 0);
          } else {
            // intr in
            printf("->INTR IN\n");

            printf("<-\tIN\n");
            USBD_LL_DataInStage(&usb_device, ep, NULL);
            endpoint_tx(ep);
          }
        }

      } else if (command[0] == 0x00 && command[1] == 0x00 && command[2] == 0x00 && command[3] == 0x02) {
        // CMD_UNLINK
        printf("-> OP_CMD_UNLINK\n");
      } else {
        printf("unknown command\n");
      }
    }
    printf("closing connection\n");

    close(client_fd);
  }
  return 0;
}