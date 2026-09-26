/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only in-process host card; not a firmware APDU extension. */
#include "core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int32_t ck_platform_size(uint8_t id);
int main(void) {
  assert(ck_core_install() == 0);
  char line[1100];
  uint8_t buffer[512];
  while (fgets(line, sizeof(line), stdin)) {
    int32_t n;
#ifdef WITH_CTAP
    if (strncmp(line, "POLL ", 5) == 0) {
      extern uint8_t ck_platform_progress(void);
      for (int i = 0; i < atoi(line + 5); i++) {
        ck_platform_progress();
        ck_core_presence_sample();
      }
      puts("9000");
      fflush(stdout);
      continue;
    }
#endif
    if (strncmp(line, "FAIL_WRITE ", 11) == 0) {
      extern void ck_test_fail_write(uint8_t id);
      unsigned id;
      assert(sscanf(line + 11, "%u", &id) == 1 && id < 186);
      ck_test_fail_write((uint8_t)id);
      puts("9000");
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "CORRUPT ", 8) == 0) {
      extern void ck_test_corrupt_record(uint8_t id, size_t offset, uint8_t mask);
      unsigned id, mask;
      size_t offset;
      assert(sscanf(line + 8, "%u %zu %u", &id, &offset, &mask) == 3 && id < 186 && mask < 256);
      ck_test_corrupt_record((uint8_t)id, offset, (uint8_t)mask);
      puts("9000");
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "REMOVE ", 7) == 0) {
      extern void ck_test_remove_record(uint8_t id);
      unsigned id;
      assert(sscanf(line + 7, "%u", &id) == 1 && id < 186);
      ck_test_remove_record((uint8_t)id);
      puts("9000");
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "SIZE ", 5) == 0) {
      printf("%08x\n", (unsigned)ck_platform_size((uint8_t)atoi(line + 5)));
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "RESET", 5) == 0) {
      ck_core_reset();
      assert(ck_core_install() == 0);
      puts("9000");
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "TOUCH ", 6) == 0) {
#if (defined(WITH_PIV) || defined(WITH_CTAP)) && !defined(WITH_OATH)
      n = 0;
#else
      n = ck_core_touch((uint8_t)atoi(line + 6), buffer, sizeof(buffer));
#endif
    } else {
      size_t len = strcspn(line, "\r\n");
      assert(len % 2 == 0 && len / 2 <= sizeof(buffer));
      for (size_t i = 0; i < len / 2; i++) {
        unsigned value;
        assert(sscanf(line + i * 2, "%2x", &value) == 1);
        buffer[i] = (uint8_t)value;
      }
      n = ck_core_exchange(1, buffer, len / 2, buffer, sizeof(buffer));
    }
    assert(n >= 0);
    for (int32_t i = 0; i < n; i++)
      printf("%02x", buffer[i]);
    puts("");
    fflush(stdout);
  }
  return 0;
}
