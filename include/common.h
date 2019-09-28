#ifndef CANOKEY_CORE_INCLUDE_COMMON_H
#define CANOKEY_CORE_INCLUDE_COMMON_H

#include <fs.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define APDU_BUFFER_SIZE 1280

#define DEBUG

#ifdef DEBUG
#include <crypto-util.h>
#include <stdio.h>
#define DBG_MSG(format, ...)                                                   \
  printf("[DBG] %s(%d): " format, __func__, __LINE__, ##__VA_ARGS__)
#define ERR_MSG(format, ...)                                                   \
  printf("[ERR] %s(%d): " format, __func__, __LINE__, ##__VA_ARGS__)
#define PRINT_HEX(...) print_hex(__VA_ARGS__)
#else
#define DBG_MSG(...)
#define ERR_MSG(...)
#define PRINT_HEX(...)
#endif

#ifndef htobe32
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe32(x) (x)
#else
#define htobe32(x) __builtin_bswap32(x)
#endif
#endif

#ifndef htobe16
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe16(x) (x)
#else
#define htobe16(x) __builtin_bswap16(x)
#endif
#endif

#define LO(x) ((uint8_t)(((uint16_t)x) & 0xFFu))
#define HI(x) ((uint8_t)(((uint16_t)x) >> 8u))

uint16_t tlv_get_length(const uint8_t *data);
uint8_t tlv_length_size(uint16_t length);

/**
 * Fill a 4-byte serial number
 * @param buf buffer to be filled
 */
void fill_sn(uint8_t *buf);

#endif // CANOKEY_CORE_INCLUDE_COMMON_H
