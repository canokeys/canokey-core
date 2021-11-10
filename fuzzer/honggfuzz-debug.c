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

// ./build/honggfuzz-debug 4 --keep 'fuzzing/applet4/working/SIGABRT.xxx.fuzz'
// export ASAN_OPTIONS=detect_leaks=0
// gdb -tui ./build/honggfuzz-debug
//  r 4 --keep 'fuzzing/applet4/working/SIGABRT.xxx.fuzz'
int main(int argc, char **argv) {
  LLVMFuzzerInitialize(&argc, &argv);
  if (argc > 3) { // run commands
    printf("Opening: %s\n", argv[3]);
    FILE *fin = fopen(argv[3], "r");
    assert(fin != NULL);
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
