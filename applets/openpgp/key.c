// SPDX-License-Identifier: Apache-2.0
#include "key.h"
#include <fs.h>

#define ATTR_FINGERPRINT 0x00
#define ATTR_DATETIME 0x01

int openpgp_key_get_fingerprint(const char *path, void *buf) {
  return read_attr(path, ATTR_FINGERPRINT, buf, KEY_FINGERPRINT_LENGTH);
}

int openpgp_key_set_fingerprint(const char *path, const void *buf) {
  return write_attr(path, ATTR_FINGERPRINT, buf, KEY_FINGERPRINT_LENGTH);
}

int openpgp_key_get_datetime(const char *path, void *buf) {
  return read_attr(path, ATTR_DATETIME, buf, KEY_DATETIME_LENGTH);
}

int openpgp_key_set_datetime(const char *path, const void *buf) {
  return write_attr(path, ATTR_DATETIME, buf, KEY_DATETIME_LENGTH);
}
