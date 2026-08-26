/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_COMMON_H
#define CANOKEY_CORE_INCLUDE_COMMON_H

#include <fs.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef APDU_BUFFER_SIZE
#define APDU_BUFFER_SIZE 256
#endif
// Raw transport storage also has to hold APDU headers/trailers and the final SW bytes.
#define APDU_COMMAND_OVERHEAD 32
#define APDU_COMMAND_BUFFER_SIZE (APDU_BUFFER_SIZE + APDU_COMMAND_OVERHEAD)
// Parsed incoming APDU data can reuse the whole command buffer after the
// transport header is stripped, so the input limit may exceed APDU_BUFFER_SIZE.
#define APDU_INCOMING_DATA_SIZE APDU_COMMAND_BUFFER_SIZE
// FIDO CBOR requests over NFC/PCSC can legitimately exceed the generic APDU
// payload limit, so chained FIDO commands use a dedicated larger reassembly
// buffer (pke_buffer).  The effective limit is pke_buffer_size().
#define CTAP_MAX_REQUEST_SIZE pke_buffer_size()
#define TOUCH_EXPIRE_TIME 1000
#define TOUCH_AFTER_PWRON 1500

#ifdef DEBUG_OUTPUT
#include <crypto-util.h>
#include <stdio.h>
#define DBG_MSG(format, ...) printf("[DBG] %s(%d): " format, __func__, __LINE__, ##__VA_ARGS__)
#define ERR_MSG(format, ...) printf("[ERR] %s(%d): " format, __func__, __LINE__, ##__VA_ARGS__)
#define DBG_KEY_META(meta)                                                                                             \
  printf("[DBG] %s(%d): type: %d, origin: %d, usage: %d, pin: %d, touch: %d\n", __func__, __LINE__, (meta)->type,      \
         (meta)->origin, (meta)->usage, (meta)->pin_policy, (meta)->touch_policy);
#define PRINT_HEX(...) print_hex(__VA_ARGS__)
#else
#define DBG_MSG(...)                                                                                                   \
  do {                                                                                                                 \
  } while (0)
#define ERR_MSG(...)                                                                                                   \
  do {                                                                                                                 \
  } while (0)
#define DBG_KEY_META(...)                                                                                              \
  do {                                                                                                                 \
  } while (0)
#define PRINT_HEX(...)                                                                                                 \
  do {                                                                                                                 \
  } while (0)
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe32(x) (x)
#define htobe16(x) (x)
#define letoh32(x) __builtin_bswap32(x)
#define htole32(x) __builtin_bswap32(x)
#define be32toh(x) (x)
#else
#define htobe32(x) __builtin_bswap32(x)
#define htobe16(x) __builtin_bswap16(x)
#define letoh32(x) (x)
#define htole32(x) (x)
#define be32toh(x) __builtin_bswap32(x)
#endif

#define LO(x) ((uint8_t)((x) & 0x00FF))
#define HI(x) ((uint8_t)(((x) & 0xFF00) >> 8))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define SWAP(x, y, T)                                                                                                  \
  do {                                                                                                                 \
    T SWAP = x;                                                                                                        \
    x = y;                                                                                                             \
    y = SWAP;                                                                                                          \
  } while (0)

// C23/C2x [[fallthrough]] is not supported by all compilers (e.g. armclang).
#if defined(__has_c_attribute)
#if __has_c_attribute(fallthrough)
#define CNK_FALLTHROUGH [[fallthrough]]
#endif
#endif
#ifndef CNK_FALLTHROUGH
#define CNK_FALLTHROUGH                                                                                                \
  do {                                                                                                                 \
  } while (0)
#endif

#define UNUSED(x) ((void)(x))
#define __weak __attribute__((weak))
#define __packed __attribute__((packed))

typedef struct {
  uint16_t value;
  uint8_t count;
  uint8_t seen;
} tlv_len_stream_t;

// Feed one BER-TLV length byte. Returns 1 when complete, 0 when more bytes are
// required, and -1 for unsupported or indefinite length encodings.
int tlv_len_stream_feed(tlv_len_stream_t *state, uint8_t byte, uint16_t *length);

// get length of tlv with bounds checking
uint16_t tlv_get_length_safe(const uint8_t *data, const size_t len, int *fail, size_t *length_size);

#endif // CANOKEY_CORE_INCLUDE_COMMON_H
