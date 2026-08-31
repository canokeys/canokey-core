/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H
#define CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H

#include "../applets/ctap/ctap-internal.h"
#include <ecc.h>
#include <key.h>
#include <ml-dsa-65.h>
#include <ml-kem-768.h>
#include <pke.h>
#include <rsa.h>
#include <sha.h>
#include <sha3.h>
#include <stddef.h>

// Single global scratch buffer shared by CTAP/OpenPGP/PIV session work.
// Keep this sized for the largest non-streamable artifact: an RSA-4096 result
// plus small ASN.1/TLV wrapper overhead. Large transport payloads must be
// streamed from their transport staging area or persistent temporary files.
//
// Lifetime contract: this is a union, so `ctap_ga`, `ctap_mldsa`, and `buffer`
// alias the same storage. ctap_process_cbor uses `buffer` as the CBOR encoder
// output area while still reading parsed fields back from `ga` later in the
// flow (e.g. ext_hmac_secret_*, pin_uv_auth_*). For that to be safe, every
// CTAP_get_assertion field that needs to survive an encoder write must live
// past byte APPLET_SHARED_BUFFER_LENGTH, which is the upper bound the encoder
// can reach. The static_asserts below pin those offsets so a future field
// reorder breaks the build instead of silently corrupting parser state.
#define APPLET_SHARED_BUFFER_LENGTH ((RSA_N_BIT_MAX / 8) + 32)
#define PIV_ATTESTATION_PLAN_SIZE 384
#define MLDSA_STREAM_STAGE_BYTES (MLDSA_K * MLDSA_POLYT0_PACKEDBYTES)
#define CTAP_MLDSA_PREFIX_BYTES 384
#define CTAP_MLDSA_PK_STAGE_BYTES (MLDSA_SEEDBYTES + 4 * MLDSA_POLYT1_PACKEDBYTES)
#define CTAP_MLDSA_PK_SUFFIX_BYTES 512
#define CTAP_MLDSA_SIG_SUFFIX_BYTES 260

typedef enum {
  CTAP_MLDSA_STREAM_NONE,
  CTAP_MLDSA_STREAM_PK,
  CTAP_MLDSA_STREAM_SIG,
} CTAP_mldsa_stream_kind;

typedef struct {
  union {
    struct {
      uint8_t prefix[CTAP_MLDSA_PREFIX_BYTES];
      uint8_t stage[CTAP_MLDSA_PK_STAGE_BYTES];
      uint8_t suffix[CTAP_MLDSA_PK_SUFFIX_BYTES];
      uint8_t seed[PRI_KEY_SIZE];
      mldsa_keygen_state_t keygen;
    } pk;
    struct {
      union {
        _Alignas(uint32_t) uint8_t stage[MLDSA_STREAM_STAGE_BYTES];
        struct {
          uint8_t prefix[CTAP_MLDSA_PREFIX_BYTES];
          uint8_t seed[PRI_KEY_SIZE];
          uint8_t tr[MLDSA_TRBYTES];
          uint8_t msg[sizeof(CTAP_auth_data) + CLIENT_DATA_HASH_SIZE];
          uint16_t msg_len;
        } input;
      } workspace;
      uint8_t suffix[CTAP_MLDSA_SIG_SUFFIX_BYTES];
      mldsa_sign_state_t sign;
    } sig;
  } storage;
  // A normal CBOR response is encoded into the first
  // APPLET_SHARED_BUFFER_LENGTH bytes of this union. Keep stream metadata
  // after that window so non-ML-DSA responses leave the cleared state intact.
  CTAP_mldsa_stream_kind kind;
  CTAP_mldsa_stream_kind storage_kind;
  bool pending;
  uint16_t prefix_len;
  uint16_t prefix_off;
  uint16_t suffix_len;
  uint16_t suffix_off;
  uint16_t stage_len;
  uint16_t stage_off;
  uint32_t total_len;
  uint32_t emitted;
} CTAP_mldsa_stream_state;

typedef enum {
  PIV_MLDSA_STREAM_NONE,
  PIV_MLDSA_STREAM_PK,
  PIV_MLDSA_STREAM_SIG,
} piv_mldsa_stream_kind_t;

typedef struct {
  piv_mldsa_stream_kind_t kind;
  uint8_t prefix[32];
  size_t prefix_len;
  size_t prefix_off;
  _Alignas(uint64_t) uint8_t stage[MLDSA_STREAM_STAGE_BYTES];
  size_t stage_len;
  size_t stage_off;
  uint8_t seed[MLDSA_SEEDBYTES];
  uint8_t tr[MLDSA_TRBYTES];
  uint8_t mu[MLDSA_CRHBYTES];
  key_meta_t pending_meta;
  uint8_t pending_key_id;
  bool install_pending;
  union {
    mldsa_keygen_state_t keygen;
    mldsa_sign_state_t sign;
  } crypto;
  size_t total_len;
  size_t emitted;
} piv_mldsa_stream_state_t;

typedef struct {
  uint16_t outer_remaining;
  uint16_t message_len;
  uint16_t message_received;
  tlv_len_stream_t tlv_len;
  uint8_t phase;
  union {
    SHA3_CTX_T mldsa;
    ed25519_randomized_sign_state_t ed25519;
  } crypto;
} piv_ga_stream_state_t;

typedef union {
  struct {
    uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
    uint8_t public_key[MLKEM768_PUBLIC_KEY_BYTES];
    uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES];
  } decaps;
  struct {
    uint8_t prefix[24];
    uint8_t public_key[MLKEM768_PUBLIC_KEY_BYTES];
    size_t prefix_len;
    size_t total_len;
  } public_key;
} piv_mlkem_scratch_t;

typedef union {
  rsa_key_t rsa;
  ecc_key_t ecc;
  uint8_t attestation_plan[PIV_ATTESTATION_PLAN_SIZE];
} piv_attestation_plan_work_t;

typedef struct {
  uint8_t stage[MLDSA_SEEDBYTES + 4 * MLDSA_POLYT1_PACKEDBYTES];
  mldsa_keygen_state_t keygen;
  size_t stage_len;
  size_t stage_off;
  size_t emitted;
} piv_attestation_mldsa_scratch_t;

typedef struct {
  uint8_t digest[32];
  piv_attestation_plan_work_t plan_work;
  union {
    piv_attestation_mldsa_scratch_t mldsa;
    uint8_t public_material[APPLET_SHARED_BUFFER_LENGTH];
  } source;
} piv_attestation_scratch_t;

typedef union {
  CTAP_mldsa_stream_state ctap_mldsa;
  CTAP_make_credential ctap_mc;
  CTAP_get_assertion ctap_ga;
  piv_mldsa_stream_state_t piv_mldsa;
  piv_ga_stream_state_t piv_ga_stream;
  piv_mlkem_scratch_t piv_mlkem;
  piv_attestation_scratch_t piv_attestation;
  uint8_t buffer[APPLET_SHARED_BUFFER_LENGTH];
} applet_session_scratch_t;

_Static_assert(sizeof(CTAP_make_credential) <= sizeof(CTAP_mldsa_stream_state),
               "MakeCredential parsing should not enlarge the shared scratch union");
_Static_assert(sizeof(piv_attestation_scratch_t) <= sizeof(CTAP_mldsa_stream_state),
               "PIV attestation should not enlarge the shared scratch union");
_Static_assert(sizeof(piv_mldsa_stream_state_t) <= sizeof(CTAP_mldsa_stream_state),
               "PIV ML-DSA streaming should not enlarge the shared scratch union");
_Static_assert(sizeof(CTAP_mldsa_stream_state) <= 3160, "CTAP ML-DSA stream state exceeds shared scratch budget");
_Static_assert(offsetof(CTAP_mldsa_stream_state, kind) >= APPLET_SHARED_BUFFER_LENGTH,
               "CTAP ML-DSA stream metadata overlaps the CBOR encoder window");
_Static_assert(sizeof(piv_mlkem_scratch_t) <= sizeof(CTAP_mldsa_stream_state),
               "PIV ML-KEM scratch should not enlarge the shared scratch union");
_Static_assert(sizeof(piv_ga_stream_state_t) <= sizeof(CTAP_mldsa_stream_state),
               "PIV GENERAL AUTHENTICATE input should not enlarge the shared scratch union");

extern applet_session_scratch_t applet_session_scratch;

// Fields below are read from `ga` after the CBOR encoder (which writes into
// `buffer`) has begun emitting bytes. They MUST live past the encoder window
// or the response generation will silently clobber the parsed input.
_Static_assert(offsetof(CTAP_get_assertion, pin_uv_auth_param) >= APPLET_SHARED_BUFFER_LENGTH,
               "ga.pin_uv_auth_param overlaps the CBOR encoder window");
_Static_assert(offsetof(CTAP_get_assertion, pin_uv_auth_protocol) >= APPLET_SHARED_BUFFER_LENGTH,
               "ga.pin_uv_auth_protocol overlaps the CBOR encoder window");
_Static_assert(offsetof(CTAP_get_assertion, ext_hmac_secret_data.salt_auth) >= APPLET_SHARED_BUFFER_LENGTH,
               "ga.ext_hmac_secret_data.salt_auth overlaps the CBOR encoder window");

#endif // CANOKEY_CORE_INCLUDE_APPLET_SCRATCH_H
