// SPDX-License-Identifier: Apache-2.0
//
// Host-side APDU replay engine for differential fuzzing against real
// hardware. The same APDU stream is sent to the device and to this binary;
// status words and response data are compared by the caller.
//
// Line-based protocol on stdin/stdout, for a long-lived subprocess:
//
//   READY              printed once after card fabrication, flushed
//   RESP <SW><DATA>    one line per input APDU; SW is 4 uppercase hex digits
//                      immediately followed by the hex of the complete
//                      response data (possibly empty). A hex-valid line that
//                      build_capdu rejects gets RESP 6700, mirroring the
//                      device (ccid.c maps malformed APDUs to
//                      SW_WRONG_LENGTH).
//   ERROR <message>    the line is not valid hex or is too long
//
// Control lines start with '!' (they mirror device events that are not
// APDUs):
//
//   !POWEROFF   simulates a CCID slot power-off: expires the applet session
//               exactly like PC_to_RDR_IccPowerOff -> device_applet_session
//               reset does on hardware (clears PIN validation, pending chains
//               and response sources). The runner sends one per connection
//               close; answers "OK".
//
// Input lines carry one hex-encoded raw APDU (case-insensitive, no spaces);
// empty lines are ignored. While the status word is 61xx, GET RESPONSE
// (00 C0 00 00 00) is issued automatically and the chunks are concatenated.
// Card state (applet selection, PIN retries, LittleFS) persists across
// lines so the binary behaves like the card across a sequence.
//
// Library debug output (DBG_MSG/ERR_MSG) goes to stdout via printf, so the
// protocol fd is dup()ed first and stdout is redirected to stderr to keep
// the protocol stream clean regardless of ENABLE_DEBUG_OUTPUT.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "apdu.h"
#include "applets.h"
#include "common.h"
#include "fabrication.h"

#define REPLAY_MAX_APDU_LEN 4096                      // bytes
#define REPLAY_MAX_LINE_LEN (REPLAY_MAX_APDU_LEN * 2) // hex characters
#define REPLAY_MAX_RESPONSE_DATA (64 * 1024)          // well beyond any real card response
#define REPLAY_MAX_GET_RESPONSE 1024                  // guards against a stuck 61xx loop

static int proto_fd = -1;

static uint8_t c_buf[1024]; // CAPDU scratch, mirrors the test/fuzz harnesses
static uint8_t r_buf[APDU_COMMAND_BUFFER_SIZE];
static uint8_t apdu_buf[REPLAY_MAX_APDU_LEN];
static uint8_t resp_buf[REPLAY_MAX_RESPONSE_DATA];
static char out_line[8 + REPLAY_MAX_RESPONSE_DATA * 2 + 2];
static char in_line[REPLAY_MAX_LINE_LEN + 2];

static void proto_write(const char *line, size_t len) {
  while (len > 0) {
    ssize_t written = write(proto_fd, line, len);
    if (written <= 0) _exit(1); // pipe closed or broken; nothing more to do
    line += written;
    len -= (size_t)written;
  }
}

static void proto_error(const char *msg) {
  proto_write("ERROR ", 6);
  proto_write(msg, strlen(msg));
  proto_write("\n", 1);
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void process_apdu_line(const uint8_t *apdu, size_t len) {
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf, .len = 0};
  if (build_capdu(&capdu, apdu, (uint16_t)len) < 0) {
    // Mirror the device: ccid.c maps a malformed APDU to SW_WRONG_LENGTH.
    proto_write("RESP 6700\n", 10);
    return;
  }

  size_t total = 0;
  for (unsigned chain = 0;;) {
    process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_CCID);
    // Truncation past resp_buf would desynchronize the diff; real card
    // responses are orders of magnitude smaller than the 64 KiB buffer.
    size_t room = sizeof(resp_buf) - total;
    size_t take = rapdu.len < room ? rapdu.len : room;
    memcpy(resp_buf + total, rapdu.data, take);
    total += take;
    if ((rapdu.sw & 0xFF00) != 0x6100 || ++chain >= REPLAY_MAX_GET_RESPONSE) break;
    build_capdu(&capdu, get_response, sizeof(get_response));
    rapdu.len = 0;
  }

  char *p = out_line;
  p += sprintf(p, "RESP %04X", rapdu.sw);
  for (size_t i = 0; i < total; ++i)
    p += sprintf(p, "%02X", resp_buf[i]);
  *p++ = '\n';
  proto_write(out_line, (size_t)(p - out_line));
}

int main(void) {
  fflush(stdout);
  proto_fd = dup(STDOUT_FILENO);
  if (proto_fd < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
    perror("redirecting library output to stderr");
    return 1;
  }

  char lfs_root[64];
  snprintf(lfs_root, sizeof(lfs_root), "/tmp/apdu-replay-%d", (int)getpid());
  unlink(lfs_root); // always fabricate a fresh card
  if (card_fabrication_procedure(lfs_root) != 0) {
    proto_error("fabrication-failed");
    return 1;
  }

  proto_write("READY\n", 6);

  while (fgets(in_line, sizeof(in_line), stdin) != NULL) {
    size_t len = strlen(in_line);
    if (len > 0 && in_line[len - 1] != '\n' && !feof(stdin)) {
      // Overlong line: consume the rest so the pipe stays in sync.
      int c;
      while ((c = getchar()) != '\n' && c != EOF)
        ;
      proto_error("too-long");
      continue;
    }
    if (len > 0 && in_line[len - 1] == '\n') in_line[--len] = '\0';
    if (len == 0) continue; // empty lines are ignored

    if (in_line[0] == '!') { // control line: a device event, not an APDU
      if (strcmp(in_line, "!POWEROFF") == 0) {
        // Mirror device_applet_session_expire() as triggered by CCID slot
        // power-off on hardware: clear PIN validation and abandon any
        // pending response/chain state.
        applets_poweroff();
        apdu_response_source_clear();
        apdu_fido_chain_reset();
        apdu_rapdu_chain_reset();
        proto_write("OK\n", 3);
      } else {
        proto_error("unknown-control");
      }
      continue;
    }

    if (len % 2 != 0) {
      proto_error("invalid-hex");
      continue;
    }
    size_t apdu_len = len / 2;
    unsigned i;
    for (i = 0; i < apdu_len; ++i) {
      int hi = hex_nibble(in_line[i * 2]);
      int lo = hex_nibble(in_line[i * 2 + 1]);
      if (hi < 0 || lo < 0) break;
      apdu_buf[i] = (uint8_t)(hi << 4 | lo);
    }
    if (i != apdu_len) {
      proto_error("invalid-hex");
      continue;
    }

    process_apdu_line(apdu_buf, apdu_len);
  }

  unlink(lfs_root);
  return 0;
}
