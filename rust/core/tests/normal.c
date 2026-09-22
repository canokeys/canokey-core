/* SPDX-License-Identifier: Apache-2.0 */
#include "core.h"
#include <assert.h>
#include <string.h>
#ifdef WITH_PASS
#include <openssl/sha.h>
#include <openssl/hmac.h>
static uint8_t files[2][142];
static int sizes[2] = {-1, -1};
int32_t ck_platform_size(uint8_t f) { return sizes[f]; }
int32_t ck_platform_read(uint8_t f, uint8_t *out, size_t n) {
  memcpy(out, files[f], n);
  return (int32_t)n;
}
int32_t ck_platform_write(uint8_t f, const uint8_t *in, size_t n) {
  memcpy(files[f], in, n);
  sizes[f] = (int)n;
  return (int32_t)n;
}
void ck_platform_sha256(const uint8_t *in, size_t n, uint8_t out[32]) { assert(SHA256(in, n, out)); }
void ck_platform_hmac_sha1(const uint8_t key[20], const uint8_t *in, size_t n, uint8_t out[20]) {
  unsigned len = 20;
  assert(HMAC(EVP_sha1(), key, 20, in, n, out, &len));
}
#endif
static uint8_t buffer[258];
static int exchange(const uint8_t *in, size_t n, uint16_t sw) {
  memcpy(buffer, in, n);
  int result = ck_core_exchange(1, buffer, n, buffer, sizeof(buffer));
  assert(result >= 2);
  assert(buffer[result - 2] == (sw >> 8));
  assert(buffer[result - 1] == (sw & 255));
  return result - 2;
}
#define SEND(sw, ...)                                                                                                  \
  do {                                                                                                                 \
    const uint8_t request[] = {__VA_ARGS__};                                                                           \
    exchange(request, sizeof(request), sw);                                                                            \
  } while (0)
int main(void) {
#ifdef WITH_PASS
  SHA256((const uint8_t *)"123456", 6, files[1]);
  files[1][32] = files[1][33] = 3;
  sizes[1] = 34;
#endif
  assert(ck_core_install() == 0);
#ifdef WITH_PASS
  assert(ck_core_applet_count() == 1);
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0, 6, '1', '2', '3', '4', '5', '6');
  /* Configure one static password using an ordinary two-frame command chain. */
  SEND(0x9000, 0x10, 0x44, 1, 0, 3, 2, 3, 'a');
  SEND(0x9000, 0, 0x44, 1, 0, 3, 'b', 'c', 1);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 4);
  assert(memcmp(buffer, "abc\r", 4) == 0);
  SEND(0x6102, 0, 0x43, 0, 0, 1);
  assert(buffer[0] == 2);
  SEND(0x9000, 0, 0xc0, 0, 0, 2);
  assert(buffer[0] == 1 && buffer[1] == 0);
  /* RFC 2202 HMAC-SHA1 vector. */
  uint8_t config[27] = {0, 0x44, 2, 0, 22, 3, 20};
  memset(config + 7, 0x0b, 20);
  exchange(config, sizeof(config), 0x9000);
  static const uint8_t expected[20] = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
                                       0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00};
  assert(ck_core_challenge(1, (const uint8_t *)"Hi There", 8, buffer) == 0);
  assert(memcmp(buffer, expected, 20) == 0);
  ck_core_reset();
  assert(ck_core_install() == 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 4);
  assert(memcmp(buffer, "abc\r", 4) == 0);
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x6982, 0, 0x43, 0, 0); /* Reset revokes authentication. */
#else
  assert(ck_core_applet_count() == 0);
  SEND(0x6a82, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
#endif
  return 0;
}
