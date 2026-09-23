/* SPDX-License-Identifier: Apache-2.0 */
#include "core.h"
#include <assert.h>
#include <string.h>
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
  assert(ck_core_install() == 0);
#ifdef WITH_PASS
#ifdef WITH_OATH
  assert(ck_core_applet_count() ==
#ifdef WITH_OPENPGP
  3
#else
  2
#endif
);
#else
  assert(ck_core_applet_count() == 1);
#endif
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0, 6, '1', '2', '3', '4', '5', '6');
  SEND(0x9000, 0, 0x20, 0, 0); /* Query retains the current grant. */
  /* ADMIN allows command chaining only for the (not yet enabled) FIDO certificate. */
  SEND(0x9000, 0, 0x44, 1, 0, 6, 2, 3, 'a', 'b', 'c', 1);
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0);
  SEND(0x9000, 0, 0x43, 0, 0); /* Documented read needs no explicit Le. */
  assert(buffer[0] == 2 && buffer[1] == 1 && buffer[2] == 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 4);
  assert(memcmp(buffer, "abc\r", 4) == 0);
  assert(ck_core_output_sample(0, 1501, 1) == -1);
  assert(ck_core_output_sample(1, 2100, 1) == -1);
  assert(ck_core_output_sample(0, 2200, 1) == 'a');
  assert(ck_core_output_sample(0, 2201, 0) == -1);
  assert(ck_core_output_sample(0, 2202, 1) == 'b');
  assert(ck_core_output_sample(0, 2203, 1) == 'c');
  assert(ck_core_output_sample(0, 2204, 1) == '\r');
  assert(ck_core_output_sample(0, 2205, 1) == -1);
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
  SEND(0x9000, 0, 0x21, 0, 0, 6, '6', '5', '4', '3', '2', '1');
  SEND(0x63c3, 0, 0x20, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0, 6, '6', '5', '4', '3', '2', '1');
  ck_core_reset();
  assert(ck_core_install() == 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 4);
  assert(memcmp(buffer, "abc\r", 4) == 0);
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x6982, 0, 0x43, 0, 0); /* Reset revokes authentication. */
  SEND(0x9000, 0, 0x20, 0, 0, 6, '6', '5', '4', '3', '2', '1');
  SEND(0x9000, 0, 0x13, 0, 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 0);
  /* Complete ordinary lock -> strong presence -> factory recovery workflow. */
  SEND(0x9000, 0, 0x44, 1, 0, 6, 2, 3, 'x', 'y', 'z', 0);
  SEND(0x63c2, 0, 0x20, 0, 0, 6, '0', '0', '0', '0', '0', '0');
  SEND(0x63c1, 0, 0x20, 0, 0, 6, '0', '0', '0', '0', '0', '0');
  SEND(0x6983, 0, 0x20, 0, 0, 6, '0', '0', '0', '0', '0', '0');
  SEND(0x9000, 0, 0x50, 0, 0, 5, 'R', 'E', 'S', 'E', 'T');
  SEND(0x9000, 0, 0x20, 0, 0, 6, '1', '2', '3', '4', '5', '6');
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 0);
#else
  assert(ck_core_applet_count() == 0);
  SEND(0x6a82, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
#endif
  return 0;
}
