/* SPDX-License-Identifier: Apache-2.0 */
#include "core.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

enum { OWNER_CCID = 1, STATUS_BYTES = 2, RESPONSE_BYTES = 258 };

static void pointer_guards(void) {
  /* Short SELECT with an unknown AID is valid input for every profile. */
  const uint8_t request[] = {0, 0xa4, 4, 0, 1, 0xff};
  uint8_t output[RESPONSE_BYTES];
  memset(output, 0xa5, sizeof(output));
  assert(ck_core_exchange(OWNER_CCID, NULL, sizeof(request), output, sizeof(output)) == -1);
  assert(ck_core_exchange(OWNER_CCID, request, sizeof(request), NULL, sizeof(output)) == -1);
  assert(ck_core_exchange(OWNER_CCID, request, SIZE_MAX, output, sizeof(output)) == -1);
  assert(ck_core_exchange(OWNER_CCID, request, sizeof(request), output, SIZE_MAX) == -1);
  for (size_t capacity = 0; capacity < STATUS_BYTES; ++capacity)
    assert(ck_core_exchange(OWNER_CCID, request, sizeof(request), output, capacity) == -1);
  for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
}

#ifdef WITH_OPENPGP
enum { CERTIFICATE_BYTES = 600, ARENA_BYTES = 272, PGP_CERT_SIG_RECORD = 11 };
static void aliased_response_regressions(void) {
  extern int32_t ck_platform_write(uint8_t, const uint8_t *, size_t);
  uint8_t payload[CERTIFICATE_BYTES];
  for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 7 + 1);
  assert(ck_platform_write(PGP_CERT_SIG_RECORD, payload, sizeof(payload)) == CERTIFICATE_BYTES);
  const size_t first_capacity[] = {250, 249, 3, 2};
  /* OpenPGP SELECT, GET DATA certificate, and short GET RESPONSE (Le=256). */
  const uint8_t select[] = {0, 0xa4, 4, 0, 6, 0xd2, 0x76, 0, 1, 0x24, 1};
  const uint8_t read[] = {0, 0xca, 0x7f, 0x21, 0};
  const uint8_t next[] = {0, 0xc0, 0, 0, 0};
  for (size_t variant = 0; variant < sizeof(first_capacity) / sizeof(first_capacity[0]); ++variant) {
    uint8_t output[RESPONSE_BYTES];
    ck_core_reset();
    int selected = ck_core_exchange(OWNER_CCID, select, sizeof(select), output, sizeof(output));
    assert(selected >= STATUS_BYTES);
    assert(output[selected - 2] == 0x90 && output[selected - 1] == 0);
    size_t offset = 0;
    for (unsigned round = 0; offset < sizeof(payload); ++round) {
      assert(round < 10);
      uint8_t arena[ARENA_BYTES], before[ARENA_BYTES];
      memset(arena, 0xa5, sizeof(arena));
      memcpy(arena + 1, round ? next : read, sizeof(read));
      memcpy(before, arena, sizeof(arena));
      size_t capacity = round ? (variant == 2 ? 202 : RESPONSE_BYTES) : first_capacity[variant];
      int n = ck_core_exchange(OWNER_CCID, arena + 1, sizeof(read), arena + 1, capacity);
      size_t count = sizeof(payload) - offset;
      if (count > capacity - STATUS_BYTES) count = capacity - STATUS_BYTES;
      assert(n == (int)(count + STATUS_BYTES));
      assert(!memcmp(arena + 1, payload + offset, count));
      offset += count;
      size_t remaining = sizeof(payload) - offset;
      uint16_t expected = remaining ? (uint16_t)(0x6100 | (remaining > 255 ? 255 : remaining)) : 0x9000;
      assert(arena[1 + count] == (expected >> 8) && arena[2 + count] == (expected & 0xff));
      assert(arena[0] == 0xa5);
      assert(!memcmp(arena + 1 + capacity, before + 1 + capacity, sizeof(arena) - 1 - capacity));
    }
    assert(ck_core_exchange(OWNER_CCID, next, sizeof(next), output, sizeof(output)) == STATUS_BYTES);
    assert(output[0] == 0x69 && output[1] == 0x86);
  }
}
#endif

int main(void) {
  assert(ck_core_install() == 0);
  pointer_guards();
#ifdef WITH_OPENPGP
  aliased_response_regressions();
#endif
  return 0;
}
