#include "key.h"
#include <memory.h>
#include <fs.h>
#include <rsa.h>

static const uint8_t attributes[] = {0x01, 0x08, 0x00, 0x00, 0x17, 0x00};

#define ATTR_FINGERPRINT 0x00
#define ATTR_DATETIME 0x01

void openpgp_key_get_attributes(void *buf) {
  memcpy(buf, attributes, sizeof(attributes));
}

int openpgp_key_get_fingerprint(const char *path, void *buf) {
  int err = read_attr(path, ATTR_FINGERPRINT, buf, KEY_FINGERPRINT_LENGTH) < 0;
  if (err < 0)
    return err;
  return KEY_FINGERPRINT_LENGTH;
}

int openpgp_key_set_fingerprint(const char *path, const void *buf) {
  return write_attr(path, ATTR_FINGERPRINT, buf, KEY_FINGERPRINT_LENGTH) < 0;
}

int openpgp_key_get_datetime(const char *path, void *buf) {
  int err = read_attr(path, ATTR_DATETIME, buf, KEY_DATETIME_LENGTH) < 0;
  if (err < 0)
    return err;
  return KEY_DATETIME_LENGTH;
}

int openpgp_key_set_datetime(const char *path, const void *buf) {
  return write_attr(path, ATTR_DATETIME, buf, KEY_DATETIME_LENGTH) < 0;
}

int openpgp_key_get_rsa_key(const char *path, void *buf) {
  int err = read_file(path, buf, sizeof(rsa_key_t));
  if (err < 0)
    return err;
  return 0;
}

int openpgp_key_set_rsa_key(const char *path, const void *buf) {
  int err = write_file(path, buf, sizeof(rsa_key_t));
  if (err < 0)
    return err;
  return 0;
}
