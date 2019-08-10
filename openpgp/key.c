#include "key.h"
#include <fs.h>
#include <rsa.h>

#define ATTR_FINGERPRINT 0x00
#define ATTR_DATETIME 0x01
#define ATTR_ATTR 0x02
#define ATTR_STATUS 0x03

int openpgp_key_get_attributes(const char *path, void *buf) {
  return read_attr(path, ATTR_ATTR, buf, MAX_ATTR_LENGTH);
}

int openpgp_key_set_attributes(const char *path, const void *buf, uint8_t len) {
  return write_attr(path, ATTR_ATTR, buf, len);
}

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

int openpgp_key_get_status(const char *path) {
  uint8_t status;
  int err = read_attr(path, ATTR_STATUS, &status, sizeof(status));
  if (err < 0)
    return err;
  return status;
}

int openpgp_key_set_status(const char *path, uint8_t status) {
  return write_attr(path, ATTR_STATUS, &status, sizeof(status));
}

int openpgp_key_get_key(const char *path, void *buf, uint16_t len) {
  int err = read_file(path, buf, len);
  if (err < 0)
    return err;
  return 0;
}

int openpgp_key_set_key(const char *path, const void *buf, uint16_t len) {
  int err = write_file(path, buf, len);
  if (err < 0)
    return err;
  return 0;
}
