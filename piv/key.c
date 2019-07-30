#include "key.h"
#include <common.h>

#define TAG_KEY 0x00
#define MAX_CERT_LEN 1996

int key_create(const char *path) {
  if (write_file(path, NULL, 0) < 0)
    return -1;
  if (write_attr(path, TAG_KEY, NULL, 0) < 0)
    return -1;
  return 0;
}

int key_read_cert(const char *path, void *buf) {
  int len = read_file(path, buf, MAX_CERT_LEN);
  if (len < 0)
    return -1;
  return len;
}

int key_write_cert(const char *path, void *buf, uint16_t len) {
  return write_file(path, buf, len);
}
