#ifndef CANOKEY_CORE_INCLUDE_COMMON_H
#define CANOKEY_CORE_INCLUDE_COMMON_H

#include <fs.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define APDU_BUFFER_SIZE 1280

#ifdef DEBUG_OUTPUT
#include <crypto-util.h>
#include <stdio.h>
#define DBG_MSG(format, ...) printf("[DBG] %s(%d): " format, __func__, __LINE__, ##__VA_ARGS__)
#define ERR_MSG(format, ...) printf("[ERR] %s(%d): " format, __func__, __LINE__, ##__VA_ARGS__)
#define PRINT_HEX(...) print_hex(__VA_ARGS__)
#else
#define DBG_MSG(...)
#define ERR_MSG(...)
#define PRINT_HEX(...)
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe32(x) (x)
#define htobe16(x) (x)
#define letoh32(x) __builtin_bswap32(x)
#define htole32(x) __builtin_bswap32(x)
#else
#define htobe32(x) __builtin_bswap32(x)
#define htobe16(x) __builtin_bswap16(x)
#define letoh32(x) (x)
#define htole32(x) (x)
#endif

#define LO(x) ((uint8_t)((x)&0x00FF))
#define HI(x) ((uint8_t)(((x)&0xFF00) >> 8))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define UNUSED(x) ((void)(x))
#define __weak __attribute__((weak))
#define __packed __attribute__((packed))

// get length of tlv with bounds checking
uint16_t tlv_get_length_safe(const uint8_t *data, const size_t len, int *fail, size_t *length_size);

/**
 * Fill a 4-byte serial number
 * @param buf buffer to be filled
 */
void fill_sn(uint8_t *buf);

#endif // CANOKEY_CORE_INCLUDE_COMMON_H
