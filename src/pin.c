// SPDX-License-Identifier: Apache-2.0
#include <crypto-util.h>
#include <fs.h>
#include <memzero.h>
#include <pin.h>
#include <string.h>

#define RETRY_ATTR 0
#define DEFAULT_RETRY_ATTR 1

int pin_create(const pin_t *pin, const void *buf, uint8_t len, uint8_t max_retries) {
  int err = write_file(pin->path, buf, 0, len, 1);
  if (err < 0) return PIN_IO_FAIL;
  err = write_attr(pin->path, RETRY_ATTR, &max_retries, sizeof(max_retries));
  if (err < 0) return PIN_IO_FAIL;
  err = write_attr(pin->path, DEFAULT_RETRY_ATTR, &max_retries, sizeof(max_retries));
  if (err < 0) return PIN_IO_FAIL;
  return 0;
}

int pin_verify(pin_t *pin, const void *buf, uint8_t len, uint8_t *retries) {
  pin->is_validated = 0;
  if (len < pin->min_length || len > pin->max_length) return PIN_LENGTH_INVALID;
  uint8_t ctr;
  int err = read_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  if (retries) *retries = ctr;
  if (ctr == 0) return PIN_AUTH_FAIL;
  uint8_t pin_buf[PIN_MAX_LENGTH];
  int real_len = read_file(pin->path, pin_buf, 0, PIN_MAX_LENGTH);
  if (real_len < 0) return PIN_IO_FAIL;
  if (((real_len != (int)len) - memcmp_s(buf, pin_buf, len)) != 0) { // the two conditions should be both evaluated
    --ctr;
    if (retries) *retries = ctr;
    err = write_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
    if (err < 0) {
      memzero(pin_buf, sizeof(pin_buf));
      return PIN_IO_FAIL;
    }
    memzero(pin_buf, sizeof(pin_buf));
#ifndef FUZZ // skip verification while fuzzing
    return PIN_AUTH_FAIL;
#endif
  }
  pin->is_validated = 1;
  err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) {
    memzero(pin_buf, sizeof(pin_buf));
    return PIN_IO_FAIL;
  }
  err = write_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) {
    memzero(pin_buf, sizeof(pin_buf));
    return PIN_IO_FAIL;
  }
  memzero(pin_buf, sizeof(pin_buf));
  return 0;
}

int pin_update(pin_t *pin, const void *buf, uint8_t len) {
  if (len < pin->min_length || len > pin->max_length) return PIN_LENGTH_INVALID;
  pin->is_validated = 0;
  int err = write_file(pin->path, buf, 0, len, 1);
  if (err < 0) return PIN_IO_FAIL;
  uint8_t ctr;
  err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  err = write_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  return 0;
}

int pin_get_size(const pin_t *pin) { return get_file_size(pin->path); }

int pin_get_retries(const pin_t *pin) {
  if (pin_get_size(pin) == 0) return 0;
  uint8_t ctr;
  int err = read_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  return ctr;
}

int pin_get_default_retries(const pin_t *pin) {
  if (pin_get_size(pin) == 0) return 0;
  uint8_t ctr;
  int err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  return ctr;
}

int pin_clear(const pin_t *pin) {
  int err = write_file(pin->path, NULL, 0, 0, 1);
  if (err < 0) return PIN_IO_FAIL;
  uint8_t ctr;
  err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  err = write_attr(pin->path, RETRY_ATTR, &ctr, sizeof(ctr));
  if (err < 0) return PIN_IO_FAIL;
  return 0;
}
