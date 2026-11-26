// SPDX-License-Identifier: Apache-2.0
// Exercise the production adapter's profile boundary with native host crypto.
#include "crypto_fixture.h"
#include <assert.h>
#include <stdalign.h>
#include <string.h>

int32_t ck_test_key(uint8_t op, uint8_t alg, rsa_key_t *key, const uint8_t *input, size_t n, uint8_t *out,
                    size_t capacity);

static void rejected_key(uint8_t alg) {
  rsa_key_t key, before;
  uint8_t output[CK_RSA_OUTPUT_BYTES], expected[sizeof(output)];
  memset(&key, 0xa5, sizeof(key));
  memcpy(&before, &key, sizeof(key));
  memset(output, 0x5a, sizeof(output));
  memcpy(expected, output, sizeof(output));
  for (uint8_t op = CK_KEY_GENERATE; op <= CK_KEY_SM2_MESSAGE_DIGEST; ++op) {
    assert(ck_test_key(op, alg, &key, NULL, 0, output, sizeof(output)) == -1);
    assert(memcmp(&key, &before, sizeof(key)) == 0);
    assert(memcmp(output, expected, sizeof(output)) == 0);
  }
}

static void public_key(uint8_t alg) {
  rsa_key_t material = {0};
  ecc_key_t reference = {0};
  uint8_t output[CK_RSA_OUTPUT_BYTES];
  // Scalar 1 for Weierstrass; a fixed nonzero seed for Ed/X25519.
  reference.pri[PRIVATE_KEY_LENGTH[alg] - 1] = 1;
  memcpy((uint8_t *)&material + CK_KEY_METADATA_BYTES, &reference, sizeof(reference));
  assert(ecc_complete_key(alg, &reference) == 0);
  if (alg == X25519) swap_big_number_endian(reference.pub);
  assert(ck_test_key(CK_KEY_PUBLIC, alg, &material, NULL, 0, output, sizeof(output)) ==
         (int32_t)PUBLIC_KEY_LENGTH[alg]);
  assert(memcmp(output, reference.pub, PUBLIC_KEY_LENGTH[alg]) == 0);
}

static void signature_capacity(void) {
  rsa_key_t key, before;
  uint8_t digest[32] = {0}, output[64];
  memset(&key, 0xa5, sizeof(key));
  memcpy(&before, &key, sizeof(key));
  memset(output, 0x5a, sizeof(output));
  // Reject before touching key material or output, including a NULL output.
  for (size_t capacity = 0; capacity < sizeof(output); ++capacity) {
    assert(ck_test_key(CK_KEY_EC_SIGN, SECP256R1, &key, digest, sizeof(digest), capacity ? output : NULL, capacity) ==
           -1);
    assert(memcmp(&key, &before, sizeof(key)) == 0);
    for (size_t i = 0; i < sizeof(output); ++i)
      assert(output[i] == 0x5a);
  }
  // Other operations still require their generic output/scratch reservation.
  assert(ck_test_key(CK_KEY_PUBLIC, SECP256R1, &key, NULL, 0, output, sizeof(output)) == -1);
  assert(memcmp(&key, &before, sizeof(key)) == 0);
}

static void digest_contract(void) {
  static const uint8_t abc_sha256[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                         0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                         0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  alignas(8) uint8_t state[CK_HASH_STATE_BYTES + 8];
  uint8_t before[sizeof(state)], output[40];
  memset(state, 0xa5, sizeof(state));
  memset(output, 0x5a, sizeof(output));
  assert(ck_digest_init(state) == 0);
  const uint8_t *message = (const uint8_t *)"abc";
  size_t offset = 0;
  for (size_t n = 0; n < 3; ++n) {
    assert(ck_digest_update(state, message + offset, n) == 0);
    offset += n;
  }
  memcpy(before, state, sizeof(state));
  for (size_t capacity = 0; capacity < 32; ++capacity) {
    uint8_t *out = capacity ? output : NULL;
    assert(ck_digest_final(state, out, capacity) == -1);
    assert(memcmp(state, before, sizeof(state)) == 0);
    for (size_t i = 0; i < sizeof(output); ++i)
      assert(output[i] == 0x5a);
  }
  assert(ck_digest_final(state, output, sizeof(output)) == 0);
  assert(memcmp(output, abc_sha256, sizeof(abc_sha256)) == 0);
  for (size_t i = 32; i < sizeof(output); ++i)
    assert(output[i] == 0x5a);
  for (size_t i = 0; i < CK_HASH_STATE_BYTES; ++i)
    assert(state[i] == 0);
  for (size_t i = CK_HASH_STATE_BYTES; i < sizeof(state); ++i)
    assert(state[i] == 0xa5);
  // Abort a live operation, then repeat cleanup after ownership is released.
  assert(ck_digest_init(state) == 0);
  assert(ck_digest_update(state, message, 3) == 0);
  for (unsigned repeat = 0; repeat < 2; ++repeat) {
    assert(ck_digest_abort(state) == 0);
    for (size_t i = 0; i < CK_HASH_STATE_BYTES; ++i)
      assert(state[i] == 0);
    for (size_t i = CK_HASH_STATE_BYTES; i < sizeof(state); ++i)
      assert(state[i] == 0xa5);
  }
}

int main(void) {
  digest_contract();
  rejected_key(255);
  signature_capacity();
  public_key(SECP256R1);
  public_key(SECP256K1);
  public_key(SECP384R1);
  public_key(SECP521R1);
  public_key(ED25519);
#if defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
  public_key(X25519);
#else
  rejected_key(X25519);
  rejected_key(RSA2048);
  rejected_key(RSA3072);
  rejected_key(RSA4096);
#endif
#if defined(RUST_CORE_CTAP) || defined(RUST_CORE_PIV)
  public_key(SM2);
#else
  rejected_key(SM2);
#endif
#if defined(RUST_CORE_CTAP) && !defined(RUST_CORE_PIV)
  alignas(8) uint8_t scratch[CK_CRYPTO_SCRATCH_BYTES] = {0};
  uint8_t seed[64] = {0}, output[32];
  memset(output, 0x5a, sizeof(output));
  const uint8_t algorithms[] = {MLKEM768, MLKEM512};
  for (size_t i = 0; i < sizeof(algorithms); ++i) {
    assert(fixture_stream_public_init(algorithms[i], scratch, seed, sizeof(seed)) == -1);
    assert(fixture_stream_decapsulate_init(algorithms[i], scratch, seed, sizeof(seed)) == -1);
    assert(fixture_stream_decapsulate_update(scratch, seed, sizeof(seed)) == -1);
    assert(fixture_stream_decapsulate_final(scratch, output, sizeof(output)) == -1);
    for (size_t j = 0; j < sizeof(output); ++j)
      assert(output[j] == 0x5a);
    fixture_stream_abort(scratch);
    for (size_t j = 0; j < sizeof(scratch); ++j)
      assert(scratch[j] == 0);
  }
#endif
  return 0;
}
