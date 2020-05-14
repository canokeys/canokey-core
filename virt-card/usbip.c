#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <usbd_conf.h>

int write_exact(int fd, uint8_t *buffer, size_t write_len) {
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

int main() {
  int fd;

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

  while (1) {
    struct sockaddr_storage client_addr;
    socklen_t sock_len = sizeof(client_addr);
    int client_fd = accept(fd, (struct sockaddr *)&client_addr, &sock_len);
    if (client_fd < 0) {
      perror("accept");
      return 1;
    }
    printf("got connection\n");

    while (1) {
      // version
      uint8_t version[2];
      if (read_exact(client_fd, version, sizeof(version)) < 0) {
        break;
      }

      // command code
      uint8_t command[2];
      if (read_exact(client_fd, command, sizeof(command)) < 0) {
        break;
      }

      if (command[0] == 0x80 && command[1] == 0x05) {
        // REQ_DEVLIST
        printf("-> OP_REQ_DEVLIST\n");

        // status
        uint8_t status[4];
        if (read_exact(client_fd, status, sizeof(status)) < 0) {
          break;
        }

        printf("<- OP_REP_DEVLIST\n");
        // resp
        uint8_t resp_header[] = {
            // version
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

        uint8_t path[256];
        strcpy((char *)path, "/sys/device/dummy/usb");
        if (write_exact(client_fd, path, sizeof(path)) < 0) {
          break;
        }

        uint8_t bus_id[32];
        strcpy((char *)bus_id, "1234");
        if (write_exact(client_fd, bus_id, sizeof(bus_id)) < 0) {
          break;
        }

        uint8_t resp_body[] = {
            // bus num
            0x00,
            0x00,
            0x00,
            0x00,
            // dev num
            0x00,
            0x00,
            0x00,
            0x00,
            // speed
            0x00,
            0x00,
            0x00,
            0x00,
            // idVendor
            0x00,
            0x07,
            // idProduct
            0x04,
            0x83,
            // bcdDevice
            0xaa,
            0xbb,
            // bDeviceClass
            0x00,
            // bDeviceSubClass
            0x00,
            // bDeviceProtocol
            0x00,
            // bConfigurationValue
            0x00,
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
      }
    }
    printf("closing connection\n");

    close(client_fd);
  }
  return 0;
}