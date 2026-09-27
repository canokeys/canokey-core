// SPDX-License-Identifier: Apache-2.0
//
// Host-side APDU replay engine for correctness comparisons against real
// hardware. The same APDU stream is sent to the device and to this binary;
// status words and response data are compared by the caller.
//
// Line-based protocol on stdin/stdout, for a long-lived subprocess:
//
//   READY              printed once after card fabrication, flushed
//   RESP <SW><DATA>    one line per input APDU; SW is 4 uppercase hex digits
//                      immediately followed by the hex of the complete
//                      response data (possibly empty). A hex-valid line that
//                      the Rust APDU engine rejects gets RESP 6700, mirroring the
//                      device (Rust CCID maps malformed APDUs to
//                      SW_WRONG_LENGTH).
//   ERROR <message>    the line is not valid hex or is too long
//
// Control lines start with '!' (they mirror device events that are not
// APDUs):
//
//   !POWEROFF   simulates a CCID slot power-off: expires the applet session
//               exactly like the Rust CCID slot reset on hardware (clears PIN
//               validation, pending chains
//               and response sources). The runner sends one per connection
//               close; answers "OK".
//
// Input lines carry one hex-encoded raw APDU (case-insensitive, no spaces);
// empty lines are ignored. While the status word is 61xx, GET RESPONSE
// (00 C0 00 00 00) is issued automatically and the chunks are concatenated.
// Card state (applet selection, PIN retries, records) persists across
// lines so the binary behaves like the card across a sequence.
//
// The host backend uses volatile records and simulated touch; this tool does
// not validate filesystem persistence or physical presence.
//
// Library debug output (DBG_MSG/ERR_MSG) goes to stdout via printf, so the
// protocol fd is dup()ed first and stdout is redirected to stderr to keep
// the protocol stream clean regardless of ENABLE_DEBUG_OUTPUT.

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "core.h"

#define REPLAY_MAX_APDU_LEN 4096                      // bytes
#define REPLAY_MAX_LINE_LEN (REPLAY_MAX_APDU_LEN * 2) // hex characters
#define REPLAY_MAX_RESPONSE_DATA (64 * 1024)          // well beyond any real card response
#define REPLAY_MAX_GET_RESPONSE 1024                  // guards against a stuck 61xx loop

static int proto_fd = -1;

static uint8_t r_buf[288]; // Same short response capacity as the product transport.
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

  size_t total = 0;
  unsigned sw;
  for (unsigned chain = 0;;) {
    int32_t received = ck_core_exchange(1, apdu, len, r_buf, sizeof(r_buf));
    if (received < 2) { proto_error("exchange-failed"); return; }
    size_t data_len = (size_t)received - 2;
    sw = ((unsigned)r_buf[data_len] << 8) | r_buf[data_len + 1];
    // Truncation past resp_buf would desynchronize the diff. Fail explicitly
    // instead of emitting a successful response with incomplete data.
    size_t room = sizeof(resp_buf) - total;
    if (data_len > room) {
      proto_error("response-too-long");
      return;
    }
    memcpy(resp_buf + total, r_buf, data_len);
    total += data_len;
    if ((sw & 0xFF00) != 0x6100) break;
    if (++chain >= REPLAY_MAX_GET_RESPONSE) { proto_error("response-chain-limit"); return; }
    apdu = get_response;
    len = sizeof(get_response);
  }

  char *p = out_line;
  p += sprintf(p, "RESP %04X", sw);
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

  if (ck_core_install() != 0) {
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
        // Same Rust session reset used by the product CCID power-off path.
        ck_core_reset();
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

  return 0;
}
