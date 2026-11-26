// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_MLDSA_STREAM_CACHE_H
#define CANOKEY_MLDSA_STREAM_CACHE_H
#include <stdbool.h>
#include <ml-dsa-44.h>

/* One operation owns this fixed-capacity stage from seed expansion through
 * the final output chunk. Each provider owns its internal cache layout. */
enum { CK_MLDSA_STAGE_BYTES = 1888, CK_MLDSA65_PREP_TAIL = 5 * MLDSA_POLYT0_PACKEDBYTES - CK_MLDSA_STAGE_BYTES };
/* The caller supplies the complete public-key buffer for the selected parameter set. */
int ck_mldsa_public(bool small, uint8_t *out, const uint8_t *seed);
int ck_mldsa_prepare(bool small, uint8_t *stage, uint8_t *tr, const uint8_t *seed);
int ck_mldsa_sign_chunk(bool small, uint8_t *stage, mldsa44_sign_state_t *state, const uint8_t *mu);
/* The caller owns tail through message absorption. The first signing call
 * consumes and wipes it before using the overlapping signing state. */
int ck_mldsa_prepare65_tail(uint8_t *stage, uint8_t *tr, const uint8_t *seed, uint8_t *tail);
int ck_mldsa_sign_first65(uint8_t *stage, mldsa44_sign_state_t *state, const uint8_t *mu, uint8_t *tail);
#endif
