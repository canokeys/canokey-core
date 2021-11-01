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
#include "fabrication.h"
#include "ndef.h"
#include "oath.h"
#include "openpgp.h"
#include "piv.h"
#include "device.h"

typedef int applet_process_t(const CAPDU *capdu, RAPDU *rapdu);

applet_process_t *applets[] = {piv_process_apdu,   ctap_process_apdu,    oath_process_apdu,
                               admin_process_apdu, openpgp_process_apdu, ndef_process_apdu};

extern ccid_bulkin_data_t bulkin_data;
extern ccid_bulkout_data_t bulkout_data;
static applet_process_t *process_func;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  static char lfs_root[64];
  process_func = NULL;
  if (*argc > 1) {
    int idx = atoi((*argv)[1]);
    if (idx >= 0 && idx < sizeof(applets) / sizeof(applets[0])) {
      process_func = applets[idx];
      printf("Applet %d Fuzzing Test\n", idx);
      sprintf(lfs_root, "/tmp/fuzz_applet%d", idx);
    }
  }
  if (!process_func) {
    printf("CCID Fuzzing Test\n");
    sprintf(lfs_root, "/tmp/fuzz_ccid");
  }
  unlink(lfs_root);
  CCID_Init();
  set_nfc_state(1);
  card_fabrication_procedure(lfs_root);
  printf("Finished initialization\n");
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  if (!process_func) { // CCID Fuzzing Test
    if (len > APDU_BUFFER_SIZE) len = APDU_BUFFER_SIZE;
    memcpy(bulkout_data.abData, buf, len);
    bulkout_data.dwLength = len;
    PC_to_RDR_XfrBlock();

  } else { // Applet Fuzzing Test
    // allow more than one apdu in a file
    while (len > 2) {
      // two bytes length
      uint16_t apdu_len = buf[1];
      apdu_len = (apdu_len << 8) | buf[0];
      buf += sizeof(uint16_t);
      len -= 2;

      // after length: data
      if (apdu_len > APDU_BUFFER_SIZE) apdu_len = APDU_BUFFER_SIZE;
      if (apdu_len > len) apdu_len = len;
      memcpy(bulkout_data.abData, buf, apdu_len);
      len -= apdu_len;

      CAPDU capdu;
      RAPDU rapdu;
      capdu.data = bulkout_data.abData;
      rapdu.data = bulkout_data.abData;
      rapdu.len = APDU_BUFFER_SIZE;
      if (build_capdu(&capdu, bulkout_data.abData, apdu_len) < 0) {
        return 0;
      }
      // realloc data to let asan find out buffer overflow
      if (capdu.lc > 0) {
        uint8_t *new_data = malloc(capdu.lc);
        memcpy(new_data, capdu.data, capdu.lc);
        capdu.data = new_data;
      } else {
        // should never read data when lc=0
        capdu.data = NULL;
      }
      // PRINT_HEX(buf, apdu_len);
      buf += apdu_len;
      capdu.le = MIN(capdu.le, APDU_BUFFER_SIZE);
      process_func(&capdu, &rapdu);

      if (capdu.lc > 0) {
        free(capdu.data);
      }
    }
  }
  return 0;
}
