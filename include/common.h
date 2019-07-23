#ifndef CANOKEY_CORE_INCLUDE_COMMON_H
#define CANOKEY_CORE_INCLUDE_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <memory.h>
#include <string.h>
#include <fs.h>

#define LO(x) ((uint8_t)((x)&0xFFu))
#define HI(x) ((uint8_t)(((x) >> 8u) & 0xFFu))

uint16_t tlv_get_length(const uint8_t *data);
uint8_t tlv_length_size(uint16_t length);

#endif // CANOKEY_CORE_INCLUDE_COMMON_H
