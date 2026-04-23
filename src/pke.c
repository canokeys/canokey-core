// SPDX-License-Identifier: Apache-2.0
#include <device.h>
#include <pke.h>

static volatile uint32_t pke_buffer_owner;
typedef union {
  ck_key_t key;
  uint8_t buffer[PKE_BUFFER_SIZE];
} pke_buffer_storage_t;

static pke_buffer_storage_t pke_buffer_storage;

__weak uint8_t *pke_buffer_data(void) { return pke_buffer_storage.buffer; }

__weak ck_key_t *pke_buffer_key(void) { return &pke_buffer_storage.key; }

__weak size_t pke_buffer_size(void) { return sizeof(pke_buffer_storage.buffer); }

__weak int pke_buffer_acquire(uint8_t owner) {
  device_atomic_compare_and_swap(&pke_buffer_owner, PKE_BUFFER_OWNER_NONE, owner);
  return pke_buffer_owner == owner ? 0 : -1;
}

__weak int pke_buffer_release(uint8_t owner) {
  device_atomic_compare_and_swap(&pke_buffer_owner, owner, PKE_BUFFER_OWNER_NONE);
  return pke_buffer_owner == PKE_BUFFER_OWNER_NONE ? 0 : -1;
}
