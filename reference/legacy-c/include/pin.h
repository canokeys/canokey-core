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

// PIN retry warnings are encoded as ISO 7816 status word 63Cx, so retry
// counts must fit in the low status-word nibble.
#define PIN_MAX_RETRIES 15

int pin_create(const pin_t *pin, const void *buf, uint8_t len, uint8_t max_retries);
int pin_verify(pin_t *pin, const void *buf, uint8_t len, uint8_t *retries);
int pin_update(pin_t *pin, const void *buf, uint8_t len);
int pin_get_size(const pin_t *pin);
int pin_get_retries(const pin_t *pin);
int pin_get_default_retries(const pin_t *pin);

// Set both current and default retry counters. Existing PIN secret bytes are
// left unchanged; applets that need default PIN reset must call pin_create().
int pin_set_retries(const pin_t *pin, uint8_t max_retries);

// Return SW 63Cx for authentication failures, clamping x to PIN_MAX_RETRIES.
uint16_t pin_get_retry_sw(uint8_t retries);
int pin_clear(const pin_t *pin);

#endif // CANOKEY_CORE_SRC_PIN_H
