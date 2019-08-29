#include <common.h>

uint16_t tlv_get_length(const uint8_t *data) {
  if (data[0] < 0x80)
    return data[0];
  if (data[0] == 0x81)
    return data[1];
  if (data[0] == 0x82)
    return (uint16_t)(data[1] << 8u) | data[2];
  return 0;
}

uint8_t tlv_length_size(uint16_t length) {
  if (length < 128)
    return 1;
  if (length < 256)
    return 2;
  return 3;
}
