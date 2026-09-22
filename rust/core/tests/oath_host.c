/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only in-process host card; not a firmware APDU extension. */
#include "core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
  assert(ck_core_install() == 0);
  char line[1100];
  uint8_t buffer[512];
  while (fgets(line, sizeof(line), stdin)) {
    int32_t n;
    if (strncmp(line, "RESET", 5) == 0) {
      ck_core_reset();
      assert(ck_core_install() == 0);
      puts("9000");
      fflush(stdout);
      continue;
    }
    if (strncmp(line, "TOUCH ", 6) == 0) {
      n = ck_core_touch((uint8_t)atoi(line + 6), buffer, sizeof(buffer));
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
