/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE__PKE_H
#define CANOKEY_CORE__PKE_H

#include <key.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PLATFORM_HAS_PKE_BUFFER
#define PLATFORM_HAS_PKE_BUFFER 0
#endif

#define PKE_BUFFER_SIZE (sizeof(ck_key_t))

enum {
  PKE_BUFFER_OWNER_NONE,
  PKE_BUFFER_OWNER_OPENPGP,
  PKE_BUFFER_OWNER_PIV,
  PKE_BUFFER_OWNER_CTAP,
};

size_t pke_buffer_size(void);
int pke_buffer_read(size_t offset, void *buf, size_t len);
int pke_buffer_write(size_t offset, const void *buf, size_t len);
int pke_buffer_clear(void);
int pke_buffer_acquire(uint8_t owner);
int pke_buffer_release(uint8_t owner);

#endif // CANOKEY_CORE__PKE_H
