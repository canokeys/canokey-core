/* SPDX-License-Identifier: Apache-2.0 */
#include "core.h"
#include <assert.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
static uint8_t files[186][32768];
static int32_t sizes[186];
static int initialized;
static int failed_write_record = -1;
void ck_test_fail_write(uint8_t id) { failed_write_record = id; }
static void storage_init(void) {
  if (!initialized) { for (size_t i = 0; i < 186; i++) sizes[i] = -1; initialized = 1; }
}
int32_t ck_platform_usage(uint32_t *used, uint32_t *total) {
  storage_init();*used=4096;*total=128*1024;
  for(size_t i=0;i<186;i++) if(sizes[i]>0) *used+=(uint32_t)sizes[i];
  return *used<=*total ? 0 : -2;
}
int32_t ck_platform_size(uint8_t id) {
  storage_init();
  assert(id < 186);
  return sizes[id];
}
int32_t ck_platform_read(uint8_t id, uint8_t *out, size_t n) {
  storage_init();
  assert(id < 186);
  if (sizes[id] < 0) return -1;
  if ((size_t)sizes[id] > n) return -2;
  memcpy(out, files[id], sizes[id]);
  return sizes[id];
}
int32_t ck_platform_write(uint8_t id, const uint8_t *input, size_t n) {
  if (failed_write_record == id) { failed_write_record = -1; return -2; }
  storage_init();
  assert(id < 186 && n <= sizeof(files[id]));
  memcpy(files[id], input, n);
  sizes[id] = (int32_t)n;
  return (int32_t)n;
}
void ck_platform_hmac_sha1(const uint8_t key[20], const uint8_t *input, size_t n, uint8_t out[20]) {
  unsigned len = 20;
  assert(HMAC(EVP_sha1(), key, 20, input, n, out, &len));
}
#if defined(WITH_OATH) || defined(WITH_OPENPGP) || defined(WITH_PIV) || defined(WITH_CTAP) || defined(WITH_NDEF)
int32_t ck_platform_read_at(uint8_t id, uint32_t offset, uint8_t *out, size_t n) {
  storage_init();
  assert(id < 186);
  if (sizes[id] < 0 || offset > (uint32_t)sizes[id] || n > (uint32_t)sizes[id] - offset) return -2;
  memcpy(out, files[id] + offset, n);
  return (int32_t)n;
}
int32_t ck_platform_write_at(uint8_t id, uint32_t offset, const uint8_t *input, size_t n) {
  storage_init();
  assert(id < 186 && offset + n <= sizeof(files[id]));
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

#ifndef WITH_HID
static uint32_t ticks;
uint32_t ck_platform_now(void) { return ticks; }
uint8_t ck_platform_touched(void) { return (ticks % 100) >= 20 && (ticks % 100) < 60; }
uint8_t ck_platform_progress(void) {
  ticks++;
  return 1;
}
void ck_platform_led(uint8_t on) { (void)on; }
#endif

#if defined(WITH_OATH) || defined(WITH_OPENPGP) || defined(WITH_PIV) || defined(WITH_CTAP) || defined(WITH_NDEF)
static uint8_t stage[8192];
static size_t stage_size;
int32_t ck_platform_stage(uint8_t operation, uint8_t id, const uint8_t *b, size_t n) {
  storage_init();
  if (operation == 4) { assert(id < 186); memset(files[id],0,sizeof(files[id]));sizes[id]=-1;return 0; }
  if (operation == 5) { assert(id < 186 && n == 1 && b[0] < 186);uint8_t to=b[0];if(sizes[id]<0)return -2;memcpy(files[to],files[id],sizes[id]);sizes[to]=sizes[id];memset(files[id],0,sizeof(files[id]));sizes[id]=-1;return 0; }
  if (operation == 0 || operation == 3) { memset(stage,0,sizeof(stage)); stage_size=0; return 0; }
  if (operation == 1) { assert(stage_size+n<=sizeof(stage));memcpy(stage+stage_size,b,n);stage_size+=n;return 0; }
  assert(operation == 2);
  int32_t result = ck_platform_write(id, stage, stage_size);
  memset(stage, 0, sizeof(stage));
  stage_size = 0;
  // Staged callers must observe the same one-shot failure as direct writes.
  return result < 0 ? result : 0;
}
#endif

#ifdef WITH_CTAP
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
#endif

#if defined(WITH_CTAP) && !defined(WITH_HID)
/* The host card uses APDUs; native USB/PKE entrypoints must stay unused. */
uint8_t ck_ccid_idle(void) { return 1; }
void ck_hid_keepalive(uint8_t waiting) { (void)waiting; }
void ck_hid_execution_begin(uint32_t cid) { (void)cid; assert(0); }
void ck_hid_execution_end(void) { assert(0); }
size_t pke_buffer_size(void) { return 0; }
int pke_buffer_acquire(uint8_t owner) { (void)owner; assert(0); return -1; }
int pke_buffer_release(uint8_t owner) { (void)owner; assert(0); return -1; }
int pke_buffer_clear(void) { assert(0); return -1; }
int pke_buffer_read(size_t offset, uint8_t *out, size_t n) {
  (void)offset; (void)out; (void)n; assert(0); return -1;
}
int pke_buffer_write(size_t offset, const uint8_t *in, size_t n) {
  (void)offset; (void)in; (void)n; assert(0); return -1;
}
#endif

int32_t ck_platform_resize(uint8_t id, uint32_t length) {
  storage_init();
  assert(id < 186 && length <= sizeof(files[id]));
  if(sizes[id] < 0)return -1;
  if(length > (uint32_t)sizes[id])memset(files[id]+sizes[id],0,length-(uint32_t)sizes[id]);
  sizes[id]=(int32_t)length;return 0;
}

/* Raw configuration-page backend; Rust owns metadata, flags and CRC policy. */
static uint8_t config_page[512];
static int config_page_ready;
int platform_config_page_read(size_t offset, void *out, size_t length) {
  if (!config_page_ready) { memset(config_page, 0xff, sizeof(config_page)); config_page_ready=1; }
  assert(offset <= sizeof(config_page) && length <= sizeof(config_page) - offset);
  memcpy(out, config_page + offset, length);return 0;
}
int platform_config_page_write(const void *page, size_t length) {
  assert(length == sizeof(config_page) && ((uintptr_t)page & 3) == 0);
  config_page_ready=1;memcpy(config_page, page, length);return 0;
}
