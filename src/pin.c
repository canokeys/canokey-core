#include <fs.h>
#include <memory.h>
#include <pin.h>

#define RETRY_ATTR 0
#define DEFAULT_RETRY_ATTR 1
#define MAX_LENGTH 64

int pin_create(const pin_t *pin, const void *buf, uint8_t len,
               uint8_t max_retries) {
  int err = write_file(pin->path, buf, len);
  if (err < 0)
    return PIN_IO_FAIL;
  err = write_attr(pin->path, RETRY_ATTR, &max_retries, sizeof(max_retries));
  if (err < 0)
    return PIN_IO_FAIL;
  err = write_attr(pin->path, DEFAULT_RETRY_ATTR, &max_retries,
                   sizeof(max_retries));
  if (err < 0)
    return PIN_IO_FAIL;
  return 0;
}

int pin_verify(pin_t *pin, const void *buf, uint8_t len) {
  pin->is_validated = 0;
  if (len < pin->min_length || len > pin->max_length)
    return PIN_LENGTH_INVALID;
  uint8_t ctr;
  int err = read_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0)
    return PIN_IO_FAIL;
  if (ctr == 0)
    return 0;
  uint8_t pin_buf[MAX_LENGTH];
  int real_len = read_file(pin->path, pin_buf, MAX_LENGTH);
  if (real_len < 0)
    return PIN_IO_FAIL;
  if (real_len != len || memcmp(buf, pin_buf, len) != 0) {
    --ctr;
    err = write_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
    if (err < 0)
      return PIN_IO_FAIL;
    return PIN_AUTH_FAIL;
  }
  pin->is_validated = 1;
  err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0)
    return PIN_IO_FAIL;
  err = write_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0)
    return PIN_IO_FAIL;
  return ctr;
}

int pin_update(pin_t *pin, const void *buf, uint8_t len) {
  pin->is_validated = 0;
  if (len < pin->min_length || len > pin->max_length)
    return PIN_LENGTH_INVALID;
  int err = write_file(pin->path, buf, len);
  if (err < 0)
    return PIN_IO_FAIL;
  uint8_t ctr;
  err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0)
    return PIN_IO_FAIL;
  err = write_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0)
    return PIN_IO_FAIL;
  return 0;
}

int pin_get_size(const pin_t *pin) {
  return get_file_size(pin->path);
}

int pin_get_retries(const pin_t *pin) {
  uint8_t ctr;
  int err = read_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0)
    return PIN_IO_FAIL;
  return ctr;
}
