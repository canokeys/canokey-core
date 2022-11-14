// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <stdint.h>

uint16_t tlv_get_length_safe(const uint8_t *data, const size_t len, int *fail, size_t *length_size) {
  uint16_t ret = 0;
  if (len < 1) {
    *fail = 1;
  } else if (data[0] < 0x80) {
    ret = data[0];
    *length_size = 1;
    *fail = 0;
  } else if (data[0] == 0x81) {
    if (len < 2) {
      *fail = 1;
    } else {
      ret = data[1];
      *length_size = 2;
      *fail = 0;
    }
  } else if (data[0] == 0x82) {
    if (len < 3) {
      *fail = 1;
    } else {
      ret = (uint16_t)(data[1] << 8u) | data[2];
      *length_size = 3;
      *fail = 0;
    }
  } else {
    *fail = 1;
  }

  if (*fail == 0 && ret + *length_size > len) {
    // length does not overflow,
    // but data does
    *fail = 1;
  }

  return ret;
}
