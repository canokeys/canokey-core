#include "key.h"
#include <memory.h>
#include <fs.h>

static const uint8_t attributes[] = {0x01, 0x08, 0x00, 0x00, 0x17, 0x00};

#define ATTR_FINGERPRINT 0x00
#define ATTR_DATETIME 0x01

void openpgp_key_get_attributes(uint8_t *buf) {
  memcpy(buf, attributes, sizeof(attributes));
}

int openpgp_key_get_fingerprint(const char *path, uint8_t *buf) {
  int err = read_attr(path, ATTR_FINGERPRINT, buf, FINGERPRINT_LENGTH) < 0;
  if (err < 0)
    return err;
  return FINGERPRINT_LENGTH;
}

int openpgp_key_set_fingerprint(const char *path, uint8_t *buf) {
  return write_attr(path, ATTR_FINGERPRINT, buf, FINGERPRINT_LENGTH) < 0;
}

int openpgp_key_get_datetime(const char *path, uint8_t *buf) {
  int err = read_attr(path, ATTR_DATETIME, buf, DATETIME_LENGTH) < 0;
  if (err < 0)
    return err;
  return DATETIME_LENGTH;
}

int openpgp_key_set_datetime(const char *path, uint8_t *buf) {
  return write_attr(path, ATTR_DATETIME, buf, DATETIME_LENGTH) < 0;
}
