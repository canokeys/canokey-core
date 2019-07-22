#ifndef CANOKEY_CORE_INCLUDE_COMMON_H
#define CANOKEY_CORE_INCLUDE_COMMON_H

#include <stdint.h>
#include <memory.h>
#include <string.h>
#include <fs.h>

#define LO(x) ((uint8_t)((x)&0xFFu))
#define HI(x) ((uint8_t)(((x) >> 8u) & 0xFFu))

#endif // CANOKEY_CORE_INCLUDE_COMMON_H
