// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_MLDSA_STREAM_CACHE_H
#define CANOKEY_MLDSA_STREAM_CACHE_H
#include <stdbool.h>
#include <ml-dsa-44.h>

/* One operation owns this fixed-capacity stage from seed expansion through
 * the final output chunk. Each provider owns its internal cache layout. */
enum { CK_MLDSA_STAGE_BYTES = 1888 };
int ck_mldsa_prepare(bool small, uint8_t *stage, uint8_t *tr, const uint8_t *seed);
int ck_mldsa_sign_chunk(bool small, uint8_t *stage, mldsa44_sign_state_t *state, const uint8_t *mu);
#endif
