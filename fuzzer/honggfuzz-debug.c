// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libhfuzz/libhfuzz.h>

#include "admin.h"
#include "ccid.h"
#include "ctap.h"
#include "device.h"
#include "fabrication.h"
#include "ndef.h"
#include "oath.h"
#include "openpgp.h"
#include "piv.h"

// ./honggfuzz-debug 4 --keep '../fuzzing/applet4/working/SIGABRT...fuzz'
int main(int argc, char **argv) {
  LLVMFuzzerInitialize(&argc, &argv);
  if (argc > 3) { // run commands
    FILE *fin = fopen(argv[3], "r");
    if (!fin) return 0;
    fseek(fin, 0, SEEK_END);
    long sz = ftell(fin);
    printf("Input file size: %ld\n", sz);
    fseek(fin, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, fin);
    fclose(fin);

    LLVMFuzzerTestOneInput(buf, sz);
    free(buf);
    printf("End\n");
  }
  return 0;
}
