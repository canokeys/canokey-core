/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H
#define CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H

#include "../applets/ctap/ctap-internal.h"
#include <ml-dsa-65.h>
#include <pke.h>
#include <rsa.h>

// Single global scratch buffer shared by CTAP/OpenPGP/PIV session work.
// Keep this sized for the largest non-streamable artifact: an RSA-4096 result
// plus small ASN.1/TLV wrapper overhead. Large transport payloads must be
// streamed from their transport staging area or persistent temporary files.
#define APPLET_SHARED_BUFFER_LENGTH ((RSA_N_BIT_MAX / 8) + 32)

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

typedef union {
  CTAP_mldsa_stream_state ctap_mldsa;
  CTAP_get_assertion ctap_ga;
  uint8_t buffer[APPLET_SHARED_BUFFER_LENGTH];
} applet_session_scratch_t;

extern applet_session_scratch_t applet_session_scratch;

#endif // CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H
