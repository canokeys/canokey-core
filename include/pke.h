/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE__PKE_H
#define CANOKEY_CORE__PKE_H

#include <key.h>
#include <stddef.h>
#include <stdint.h>

#define PKE_BUFFER_SIZE (sizeof(ck_key_t))

enum {
  PKE_BUFFER_OWNER_NONE,
  PKE_BUFFER_OWNER_OPENPGP,
  PKE_BUFFER_OWNER_PIV,
  PKE_BUFFER_OWNER_CTAP,
};

uint8_t *pke_buffer_data(void);
ck_key_t *pke_buffer_key(void);
size_t pke_buffer_size(void);
int pke_buffer_acquire(uint8_t owner);
int pke_buffer_release(uint8_t owner);

#endif // CANOKEY_CORE__PKE_H
