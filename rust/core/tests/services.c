/* SPDX-License-Identifier: Apache-2.0 */
#include "core.h"
#include <assert.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
static uint8_t files[14][32768];
static int32_t sizes[14] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
int32_t ck_platform_size(uint8_t id) {
  assert(id < 14);
  return sizes[id];
}
int32_t ck_platform_read(uint8_t id, uint8_t *out, size_t n) {
  assert(id < 14);
  if (sizes[id] < 0) return -1;
  if ((size_t)sizes[id] > n) return -2;
  memcpy(out, files[id], sizes[id]);
  return sizes[id];
}
int32_t ck_platform_write(uint8_t id, const uint8_t *input, size_t n) {
  assert(id < 14 && n <= sizeof(files[id]));
  memcpy(files[id], input, n);
  sizes[id] = (int32_t)n;
  return (int32_t)n;
}
void ck_platform_hmac_sha1(const uint8_t key[20], const uint8_t *input, size_t n, uint8_t out[20]) {
  unsigned len = 20;
  assert(HMAC(EVP_sha1(), key, 20, input, n, out, &len));
}
#if defined(WITH_OATH) || defined(WITH_OPENPGP)
int32_t ck_platform_read_at(uint8_t id, uint32_t offset, uint8_t *out, size_t n) {
  assert(id < 14);
  if (sizes[id] < 0 || offset > (uint32_t)sizes[id] || n > (uint32_t)sizes[id] - offset) return -2;
  memcpy(out, files[id] + offset, n);
  return (int32_t)n;
}
int32_t ck_platform_write_at(uint8_t id, uint32_t offset, const uint8_t *input, size_t n) {
  assert(id < 14 && offset + n <= sizeof(files[id]));
  if (sizes[id] < 0 || offset > (uint32_t)sizes[id]) return -2;
  memcpy(files[id] + offset, input, n);
  if (offset + n > (uint32_t)sizes[id]) sizes[id] = (int32_t)(offset + n);
  return (int32_t)n;
}
int32_t ck_platform_has_space(uint32_t bytes, uint32_t reserve) {
  (void)reserve;
  return bytes + (uint32_t)sizes[3] <= sizeof(files[3]);
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
#endif

static uint32_t ticks;
uint32_t ck_platform_now(void) { return ticks; }
uint8_t ck_platform_touched(void) { return (ticks % 100) >= 20 && (ticks % 100) < 60; }
uint8_t ck_platform_progress(void) {
  ticks++;
  return 1;
}
void ck_platform_led(uint8_t on) { (void)on; }

#ifdef WITH_OPENPGP
static uint8_t stage[2048];
static size_t stage_size;
int32_t ck_platform_stage(uint8_t operation, uint8_t id, const uint8_t *b, size_t n) {
  if (operation == 0 || operation == 3) { memset(stage,0,sizeof(stage)); stage_size=0; return 0; }
  if (operation == 1) { assert(stage_size+n<=sizeof(stage));memcpy(stage+stage_size,b,n);stage_size+=n;return 0; }
  assert(operation==2);ck_platform_write(id,stage,stage_size);memset(stage,0,sizeof(stage));stage_size=0;return 0;
}
#endif
