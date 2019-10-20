
#include <fcntl.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libhfuzz/libhfuzz.h>

#include "ccid.h"
#include "fabrication.h"

extern ccid_bulkin_data_t bulkin_data[2];
extern ccid_bulkout_data_t bulkout_data[2];
int Lun;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  CCID_Init();
  card_fabrication_procedure();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if (len < 1 || buf[0] > 1) return 0;
  Lun = buf[0];
  len--;
  buf++;

  if (len > APDU_BUFFER_SIZE) len = APDU_BUFFER_SIZE;
  memcpy(bulkout_data[Lun].abData, buf, len);
  bulkout_data[Lun].dwLength = len;
  PC_to_RDR_XfrBlock(Lun);
  return 0;
}
