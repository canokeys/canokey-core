// SPDX-License-Identifier: Apache-2.0
#include <crypto-util.h>
#include <fs.h>
#include <memzero.h>
#include <pin.h>
#include <string.h>

#define RETRY_ATTR 0
#define DEFAULT_RETRY_ATTR 1

int pin_create(const pin_t *pin, const void *buf, uint8_t len, uint8_t max_retries) {
  if (max_retries == 0 || max_retries > PIN_MAX_RETRIES) return PIN_LENGTH_INVALID;
  const struct lfs_attr attrs[] = {
      {.type = RETRY_ATTR, .buffer = (void *)&max_retries, .size = sizeof(max_retries)},
      {.type = DEFAULT_RETRY_ATTR, .buffer = (void *)&max_retries, .size = sizeof(max_retries)},
  };
  return write_file_attrs(pin->path, attrs, 2, buf, len, 1) < 0 ? PIN_IO_FAIL : 0;
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
  uint8_t default_ctr;
  err = read_attr(pin->path, DEFAULT_RETRY_ATTR, &default_ctr, sizeof(default_ctr));
  if (err < 0) {
    memzero(pin_buf, sizeof(pin_buf));
    return PIN_IO_FAIL;
  }
  if (ctr != default_ctr) {
    err = write_attr(pin->path, RETRY_ATTR, &default_ctr, sizeof(default_ctr));
    if (err < 0) {
      memzero(pin_buf, sizeof(pin_buf));
      return PIN_IO_FAIL;
    }
  }
  memzero(pin_buf, sizeof(pin_buf));
  pin->is_validated = 1;
  return 0;
}

// Commit the PIN data together with a retry counter reset to the persisted
// default. A read failure leaves the file untouched and returns PIN_IO_FAIL.
static int pin_write_data_reset_retry(const pin_t *pin, const void *buf, uint8_t len) {
  uint8_t ctr;
  if (read_attr(pin->path, DEFAULT_RETRY_ATTR, &ctr, sizeof(ctr)) < 0) return PIN_IO_FAIL;
  const struct lfs_attr retry = {.type = RETRY_ATTR, .buffer = &ctr, .size = sizeof(ctr)};
  return write_file_attrs(pin->path, &retry, 1, buf, len, 1) < 0 ? PIN_IO_FAIL : 0;
}

int pin_update(pin_t *pin, const void *buf, uint8_t len) {
  if (len < pin->min_length || len > pin->max_length) return PIN_LENGTH_INVALID;
  pin->is_validated = 0;
  return pin_write_data_reset_retry(pin, buf, len);
}

int pin_get_size(const pin_t *pin) { return get_file_size(pin->path); }

static int pin_get_counter(const pin_t *pin, uint8_t attr) {
  if (pin_get_size(pin) == 0) return 0;
  uint8_t ctr;
  if (read_attr(pin->path, attr, &ctr, sizeof(ctr)) < 0) return PIN_IO_FAIL;
  return ctr;
}

int pin_get_retries(const pin_t *pin) { return pin_get_counter(pin, RETRY_ATTR); }

int pin_get_default_retries(const pin_t *pin) { return pin_get_counter(pin, DEFAULT_RETRY_ATTR); }

int pin_set_retries(const pin_t *pin, uint8_t max_retries) {
  if (max_retries == 0 || max_retries > PIN_MAX_RETRIES) return PIN_LENGTH_INVALID;
  const struct lfs_attr attrs[] = {
      {.type = RETRY_ATTR, .buffer = (void *)&max_retries, .size = sizeof(max_retries)},
      {.type = DEFAULT_RETRY_ATTR, .buffer = (void *)&max_retries, .size = sizeof(max_retries)},
  };
  // A missing file fails here; set_attrs_commit never creates one.
  return set_attrs_commit(pin->path, attrs, 2) < 0 ? PIN_IO_FAIL : 0;
}

uint16_t pin_get_retry_sw(uint8_t retries) {
  if (retries > PIN_MAX_RETRIES) retries = PIN_MAX_RETRIES;
  return (uint16_t)(0x63C0 + retries);
}

int pin_clear(const pin_t *pin) { return pin_write_data_reset_retry(pin, NULL, 0); }
