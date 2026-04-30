/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H
#define CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H

#include "../applets/ctap/ctap-internal.h"
#include <ml-dsa-65.h>
#include <pke.h>
#include <rsa.h>

#define OPENPGP_SESSION_CRYPTO_BASE_LENGTH 513
#define OPENPGP_SESSION_CRYPTO_BUFFER_LENGTH                                                                     \
  ((OPENPGP_SESSION_CRYPTO_BASE_LENGTH > PKE_BUFFER_SIZE) ? OPENPGP_SESSION_CRYPTO_BASE_LENGTH : PKE_BUFFER_SIZE)
#define PIV_SESSION_CRYPTO_BUFFER_LENGTH (RSA_N_BIT_MAX / 8)
#define PIV_SESSION_RESPONSE_BUFFER_LENGTH (PIV_SESSION_CRYPTO_BUFFER_LENGTH + 8)

typedef enum {
  CTAP_MLDSA_STREAM_NONE,
  CTAP_MLDSA_STREAM_PK,
  CTAP_MLDSA_STREAM_SIG,
} CTAP_mldsa_stream_kind;

typedef struct {
  CTAP_mldsa_stream_kind kind;
  uint8_t prefix[384];
  size_t prefix_len;
  size_t prefix_off;
  uint8_t suffix[512];
  size_t suffix_len;
  size_t suffix_off;
  uint8_t stage_buf[MLDSA_SEEDBYTES + 4 * MLDSA_POLYT1_PACKEDBYTES];
  uint8_t *stage;
  size_t stage_len;
  size_t stage_off;
  uint8_t seed[PRI_KEY_SIZE];
  uint8_t tr[MLDSA_TRBYTES];
  uint8_t msg[sizeof(CTAP_auth_data) + CLIENT_DATA_HASH_SIZE];
  size_t msg_len;
  mldsa_keygen_state_t keygen;
  mldsa_sign_state_t sign;
  size_t total_len;
  bool pending;
} CTAP_mldsa_stream_state;

typedef struct {
  uint8_t crypto[PIV_SESSION_CRYPTO_BUFFER_LENGTH];
  uint8_t response[PIV_SESSION_RESPONSE_BUFFER_LENGTH];
} applet_piv_session_scratch_t;

typedef union {
  CTAP_mldsa_stream_state ctap_mldsa;
  uint8_t openpgp_crypto[OPENPGP_SESSION_CRYPTO_BUFFER_LENGTH];
  applet_piv_session_scratch_t piv;
} applet_session_scratch_t;

extern applet_session_scratch_t applet_session_scratch;

#endif // CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H
