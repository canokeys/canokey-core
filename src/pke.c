// SPDX-License-Identifier: Apache-2.0
#include <device.h>
#include <pke.h>
#include <string.h>

#if !PLATFORM_HAS_PKE_BUFFER

static volatile uint32_t pke_buffer_owner;
static uint8_t pke_buffer_storage[PKE_BUFFER_SIZE];

size_t pke_buffer_size(void) { return sizeof(pke_buffer_storage); }

int pke_buffer_read(size_t offset, void *buf, size_t len) {
  if (offset > sizeof(pke_buffer_storage) || len > sizeof(pke_buffer_storage) - offset) return -1;
  memcpy(buf, pke_buffer_storage + offset, len);
  return 0;
}

int pke_buffer_write(size_t offset, const void *buf, size_t len) {
  if (offset > sizeof(pke_buffer_storage) || len > sizeof(pke_buffer_storage) - offset) return -1;
  memcpy(pke_buffer_storage + offset, buf, len);
  return 0;
}

int pke_buffer_clear(void) {
  memset(pke_buffer_storage, 0, sizeof(pke_buffer_storage));
  return 0;
}

int pke_buffer_acquire(uint8_t owner) {
  device_atomic_compare_and_swap(&pke_buffer_owner, PKE_BUFFER_OWNER_NONE, owner);
  return pke_buffer_owner == owner ? 0 : -1;
}

int pke_buffer_release(uint8_t owner) {
  device_atomic_compare_and_swap(&pke_buffer_owner, owner, PKE_BUFFER_OWNER_NONE);
  return pke_buffer_owner == PKE_BUFFER_OWNER_NONE ? 0 : -1;
}

#endif
