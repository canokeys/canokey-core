// SPDX-License-Identifier: Apache-2.0
//
// Coverage-guided fuzz harness for the Rust core, driven through the same
// backend as apdu-replay (tests/support/services.c volatile records).
//
// Each input is a sequence of framed records, little-endian lengths:
//
//   [tag:u8][len:u16][payload]
//
//   tag 0x00  APDU     payload is one raw APDU, executed via ck_core_exchange
//                      with automatic GET RESPONSE chaining, mirroring the
//                      apdu-replay semantics (and therefore the device).
//   tag 0x01  POWEROFF len = 0; ck_core_reset(), same session reset as the
//                      product CCID slot power-off path.
//   tag 0x02  STORAGE FAULT  payload = [record_id, op]; op 0 fails the next
//                      write, op 1 fails the next read of that record.
//
// Truncated frames and unknown tags end the input. Card state persists
// across inputs inside the fuzzer process, like a real card across a
// session; POWEROFF frames let the fuzzer discover reset scheduling.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core.h"

#define FUZZ_MAX_APDU_LEN 4096                 // bytes, same cap as apdu-replay
#define FUZZ_MAX_RESPONSE_DATA (64 * 1024)     // well beyond any real card response
#define FUZZ_MAX_GET_RESPONSE 1024             // guards against a stuck 61xx loop

enum {
  FUZZ_TAG_APDU = 0x00,
  FUZZ_TAG_POWEROFF = 0x01,
  FUZZ_TAG_STORAGE_FAULT = 0x02,
};

enum {
  FUZZ_FAULT_FAIL_WRITE = 0,
  FUZZ_FAULT_FAIL_READ = 1,
};

// One-shot failure hooks provided by tests/support/services.c.
void ck_test_fail_write(uint8_t id);
void ck_test_fail_read(uint8_t id);

static uint8_t r_buf[288]; // Same short response capacity as the product transport.
static uint8_t resp_buf[FUZZ_MAX_RESPONSE_DATA];

static void fuzz_init(void) {
  static int initialized;
  if (initialized) return;
  initialized = 1;
  // Keep library DBG_MSG/ERR_MSG printf output out of the fuzzer's stdout stats.
  if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) abort();
  if (ck_core_install() != 0) abort(); // fabrication failure is a harness bug
}

static void run_apdu(const uint8_t *apdu, size_t len) {
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  size_t total = 0;
  unsigned sw;
  for (unsigned chain = 0;;) {
    int32_t received = ck_core_exchange(1, apdu, len, r_buf, sizeof(r_buf));
    if (received < 2) return; // engine rejected the exchange; nothing to chain
    size_t data_len = (size_t)received - 2;
    sw = ((unsigned)r_buf[data_len] << 8) | r_buf[data_len + 1];
    // Truncation here only loses coverage of the chained tail; never overrun.
    size_t room = sizeof(resp_buf) - total;
    if (data_len > room) return;
    memcpy(resp_buf + total, r_buf, data_len);
    total += data_len;
    if ((sw & 0xFF00) != 0x6100) break;
    if (++chain >= FUZZ_MAX_GET_RESPONSE) return;
    apdu = get_response;
    len = sizeof(get_response);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_init();

  while (size >= 3) {
    uint8_t tag = data[0];
    size_t len = (size_t)data[1] | ((size_t)data[2] << 8);
    data += 3;
    size -= 3;
    if (len > size) break; // truncated frame ends the input
    switch (tag) {
    case FUZZ_TAG_APDU:
      if (len <= FUZZ_MAX_APDU_LEN) run_apdu(data, len);
      break;
    case FUZZ_TAG_POWEROFF:
      ck_core_reset();
      break;
    case FUZZ_TAG_STORAGE_FAULT:
      if (len == 2) {
        if (data[1] == FUZZ_FAULT_FAIL_WRITE) {
          ck_test_fail_write(data[0]);
        } else if (data[1] == FUZZ_FAULT_FAIL_READ) {
          ck_test_fail_read(data[0]);
        }
      }
      break;
    default:
      return 0; // unknown tag: ignore the rest so structure stays learnable
    }
    data += len;
    size -= len;
  }
  return 0;
}
