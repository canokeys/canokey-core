/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_SRC_PIN_H
#define CANOKEY_CORE_SRC_PIN_H

#include <stdint.h>

typedef struct {
  uint8_t min_length;
  uint8_t max_length;
  uint8_t is_validated;
  char path[];
} pin_t;

#define PIN_IO_FAIL -1
#define PIN_AUTH_FAIL -2
#define PIN_LENGTH_INVALID -3
#define PIN_MAX_LENGTH 64

int pin_create(const pin_t *pin, const void *buf, uint8_t len,
               uint8_t max_retries);
int pin_verify(pin_t *pin, const void *buf, uint8_t len, uint8_t *retries);
int pin_update(pin_t *pin, const void *buf, uint8_t len);
int pin_get_size(const pin_t *pin);
int pin_get_retries(const pin_t *pin);
int pin_get_default_retries(const pin_t *pin);
int pin_clear(const pin_t *pin);

#endif // CANOKEY_CORE_SRC_PIN_H
