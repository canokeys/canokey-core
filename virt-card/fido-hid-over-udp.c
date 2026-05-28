// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "device.h"
#include "ctap.h"
#include "ctaphid.h"
#include "fabrication.h"
#include "applets.h"

static int udp_server() {
  static bool run_already = false;
  static int fd = -1;
  if (run_already && fd >= 0) return fd;
  run_already = true;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket failed");
    return 1;
  }

  int flags = fcntl(fd, F_GETFD);
  flags |= FD_CLOEXEC;
  fcntl(fd, F_SETFD, flags);

  struct timeval read_timeout;
  read_timeout.tv_sec = 0;
  read_timeout.tv_usec = 10;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(struct timeval)) != 0) {
    perror("setsockopt");
    exit(1);
  }

  int reuseaddr = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) != 0) {
    perror("setsockopt");
    exit(1);
  }

  struct sockaddr_in serveraddr;
  memset(&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(8111);
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
    perror("bind failed");
    exit(1);
  }
  return fd;
}

static int udp_recv(int fd, uint8_t *buf, int size) {

  fd_set input;
  FD_ZERO(&input);
  FD_SET(fd, &input);
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 100;
  int n = select(fd + 1, &input, NULL, NULL, &timeout);
  if (n == -1) {
    perror("select\n");
    exit(1);
  } else if (n == 0)
    return 0;
  if (!FD_ISSET(fd, &input)) {
  }
  int length = recvfrom(fd, buf, size, 0, NULL, 0);
  if (length < 0) {
    perror("recvfrom failed");
    exit(1);
  }
  return length;
}

static void udp_send(int fd, uint8_t *buf, int size) {
  struct sockaddr_in serveraddr;
  memset(&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(7112);
  serveraddr.sin_addr.s_addr = htonl(0x7f000001); // (127.0.0.1)

  if (sendto(fd, buf, size, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
    perror("sendto failed");
    exit(1);
  }
}

static int current_fd;
static void emulate_reboot(void);

static uint8_t udp_send_current_fd(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len) {
  UNUSED(pdev);
  // printf("udp_send_current_fd %hu\n", len);
  udp_send(current_fd, report, len);
  CTAPHID_TxContinue();
  return 0;
}

static int get_env_flag(const char *name, int default_value) {
  const char *value = getenv(name);
  if (value == NULL || *value == '\0') return default_value;
  return atoi(value) != 0;
}

static const char *get_lfs_root_path(void) {
  const char *value = getenv("CANOKEY_VIRT_LFS_ROOT");
  if (value == NULL || *value == '\0') return "/tmp/canokey-fido-hid-over-udp-lfs-root";
  return value;
}

static void write_testmode_file(const char *path, int value) {
  FILE *fp = fopen(path, "w");
  if (fp == NULL) {
    perror(path);
    exit(1);
  }
  fprintf(fp, "%d", value);
  fclose(fp);
}

static void configure_testmode_files(void) { write_testmode_file("/tmp/canokey-test-up", 0); }

static void reset_storage_if_requested(const char *lfs_root) {
  if (!get_env_flag("CANOKEY_VIRT_RESET_STORAGE", 1)) return;
  if (unlink(lfs_root) != 0 && errno != ENOENT) {
    perror(lfs_root);
    exit(1);
  }
}

static void emulate_reboot(void) {
  testmode_set_initial_ticks(0);
  testmode_set_initial_ticks(device_get_tick());
  ctap_schedule_runtime_reset();
  if (applets_install() < 0) exit(1);
}

static int handle_udp_control_packet(const uint8_t *buf, int length) {
  static const uint8_t magic_cmd[HID_RPT_SIZE] = {
      0xac, 0x10, 0x52, 0xca, 0x95, 0xe5, 0x69, 0xde, 0x69, 0xe0, 0x2e, 0xbf, 0xf3, 0x33, 0x48, 0x5f,
      0x13, 0xf9, 0xb2, 0xda, 0x34, 0xc5, 0xa8, 0xa3, 0x40, 0x52, 0x66, 0x97, 0xa9, 0xab, 0x2e, 0x0b,
      0x39, 0x4d, 0x8d, 0x04, 0x97, 0x3c, 0x13, 0x40, 0x05, 0xbe, 0x1a, 0x01, 0x40, 0xbf, 0xf6, 0x04,
      0x5b, 0xb2, 0x6e, 0xb7, 0x7a, 0x73, 0xea, 0xa4, 0x78, 0x13, 0xf6, 0xb4, 0x9a, 0x72, 0x50, 0xdc,
  };
  static const uint8_t inject_error_prefix[] = {
      0x99, 0x10, 0x52, 0xca, 0x95, 0xe5, 0x69, 0xde, 0x69, 0xe0, 0x2e, 0xbf,
  };

  if (length == HID_RPT_SIZE && memcmp(magic_cmd, buf, sizeof(magic_cmd)) == 0) {
    printf("MAGIC REBOOT command received!\r\n");
    emulate_reboot();
    return 1;
  }

  if (length > (int)sizeof(inject_error_prefix) + 2 &&
      memcmp(buf, inject_error_prefix, sizeof(inject_error_prefix)) == 0) {
    const uint8_t *data = buf + sizeof(inject_error_prefix);
    testmode_inject_error(data[0], data[1], (uint16_t)(length - (int)sizeof(inject_error_prefix) - 2), data + 2);
    return 1;
  }

  return 0;
}

static void handle_udp_packet(uint8_t *buf, int length) {
  if (length <= 0) return;
  if (handle_udp_control_packet(buf, length)) return;
  if (length == HID_RPT_SIZE) CTAPHID_OutEvent(buf);
}

void USBD_CTAPHID_ServiceReceive(void) {
  uint8_t buf[HID_RPT_SIZE];
  int length = udp_recv(current_fd, buf, sizeof(buf));
  handle_udp_packet(buf, length);
}

// Run on SIGTERM/SIGINT. SIGTERM's default action is "terminate" — atexit
// handlers do NOT run, so the gcov runtime never flushes the in-memory
// .gcda counters and the coverage report misses everything this process
// did. Calling exit() from the handler hands control to the C runtime,
// which runs atexit hooks (including __gcov_dump) before tearing down.
// Use the conventional 128+signo exit code so callers can still see the
// process was signal-terminated.
static void on_term(int sig) { exit(128 + sig); }

int main() {
  signal(SIGTERM, on_term);
  signal(SIGINT, on_term);

  const int nfc_mode = get_env_flag("CANOKEY_VIRT_NFC", 0);
  const char *lfs_root = get_lfs_root_path();
  const char *test_nfc_mode = nfc_mode ? "1" : "0";

  current_fd = udp_server();
  if (setenv("CANOKEY_TEST_NFC", "0", 1) != 0) {
    perror("setenv");
    exit(1);
  }
  configure_testmode_files();
  reset_storage_if_requested(lfs_root);
  card_fabrication_procedure(lfs_root);
  if (setenv("CANOKEY_TEST_NFC", test_nfc_mode, 1) != 0) {
    perror("setenv");
    exit(1);
  }
  set_nfc_state((uint8_t)nfc_mode);
  CTAPHID_Init(udp_send_current_fd);
  emulate_reboot();
  for (;;) {
    CTAPHID_Loop(0);
  }
  return 0;
}
