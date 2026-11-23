// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_MLDSA_STREAM_CACHE_H
#define CANOKEY_MLDSA_STREAM_CACHE_H
#include <stdbool.h>
#include <ml-dsa-44.h>

/* One operation owns this stage from seed expansion to the final output.
 * 44 can retain all four packed t0 rows. 65 retains packed s1 followed
 * by the last three t0 rows. On acceptance it becomes the output chunk. */
enum {
  CK_MLDSA_TAIL_ROWS = 3,
  CK_MLDSA_STAGE_BYTES = MLDSA_L * MLDSA_POLYETA_PACKEDBYTES + CK_MLDSA_TAIL_ROWS * MLDSA_POLYT0_PACKEDBYTES,
};
int ck_mldsa_prepare(bool small, uint8_t *stage, uint8_t *tr, const uint8_t *seed);
int ck_mldsa_sign_chunk(bool small, uint8_t *stage, mldsa44_sign_state_t *state, const uint8_t *mu);
#endif
