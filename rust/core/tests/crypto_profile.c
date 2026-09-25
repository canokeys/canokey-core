// SPDX-License-Identifier: Apache-2.0
// Exercise the production adapter's profile boundary with native host crypto.
#include "crypto_ops.h"
#include <assert.h>
#include <stdalign.h>
#include <string.h>

static void rejected_key(uint8_t alg) {
  rsa_key_t key, before;
  uint8_t output[CK_RSA_OUTPUT_BYTES], expected[sizeof(output)];
  memset(&key, 0xa5, sizeof(key));
  memcpy(&before, &key, sizeof(key));
  memset(output, 0x5a, sizeof(output));
  memcpy(expected, output, sizeof(output));
  for (uint8_t op = CK_KEY_GENERATE; op <= CK_KEY_SM2_MESSAGE_DIGEST; ++op) {
    assert(ck_platform_key(op, alg, &key, NULL, 0, output, sizeof(output)) == -1);
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
  assert(ck_platform_key(CK_KEY_PUBLIC, alg, &material, NULL, 0, output, sizeof(output)) ==
         (int32_t)PUBLIC_KEY_LENGTH[alg]);
  assert(memcmp(output, reference.pub, PUBLIC_KEY_LENGTH[alg]) == 0);
}

int main(void) {
  rejected_key(255);
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
  const uint8_t ops[] = {CK_STREAM_PUBLIC_INIT, CK_STREAM_DECAPSULATE_INIT,
                        CK_STREAM_DECAPSULATE_UPDATE, CK_STREAM_DECAPSULATE_FINAL};
  for (size_t i = 0; i < sizeof(ops); ++i) {
    assert(ck_platform_stream(ops[i], MLKEM768, scratch, seed, sizeof(seed), output, sizeof(output)) == -1);
    for (size_t j = 0; j < sizeof(output); ++j) assert(output[j] == 0x5a);
    assert(ck_platform_stream(CK_STREAM_ABORT, 0, scratch, NULL, 0, NULL, 0) == 0);
    for (size_t j = 0; j < sizeof(scratch); ++j) assert(scratch[j] == 0);
  }
#endif
  return 0;
}
