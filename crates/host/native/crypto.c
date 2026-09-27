/* SPDX-License-Identifier: Apache-2.0 */
/* Host native crypto only; virtual hardware and persistence live in Rust. */
#include "core.h"
#include <assert.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
void ck_platform_hmac_sha1(const uint8_t key[20], const uint8_t *input, size_t n, uint8_t out[20]) {
  unsigned len = 20;
  assert(HMAC(EVP_sha1(), key, 20, input, n, out, &len));
}
int32_t ck_platform_mac(uint8_t alg, const uint8_t *key, size_t k, const uint8_t *input, size_t n, uint8_t out[64]) {
  const EVP_MD *md = alg == 1 ? EVP_sha1() : alg == 2 ? EVP_sha256() : EVP_sha512();
  unsigned len = 64;
  memset(out, 0, 64);
  assert(HMAC(md, key, (int)k, input, n, out, &len));
  return 0;
}
int32_t ck_platform_random(uint8_t *out, size_t n) { return RAND_bytes(out, (int)n) == 1 ? 0 : -1; }
void ck_platform_serial(uint8_t out[4]) { memset(out, 0, 4); }
void ck_platform_sha256(const uint8_t *input, size_t n, uint8_t out[32]) {
  unsigned length;
  assert(EVP_Digest(input, n, out, &length, EVP_sha256(), NULL) && length == 32);
}
int32_t ck_platform_aes256(uint8_t encrypt, const uint8_t key[32], const uint8_t iv[16], uint8_t *data, size_t n) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return -1;
  int length = 0, final = 0;
  int ok = EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt) &&
           EVP_CIPHER_CTX_set_padding(ctx, 0) && EVP_CipherUpdate(ctx, data, &length, data, (int)n) &&
           EVP_CipherFinal_ex(ctx, data + length, &final) && (size_t)(length + final) == n;
  EVP_CIPHER_CTX_free(ctx);
  return ok ? 0 : -1;
}
