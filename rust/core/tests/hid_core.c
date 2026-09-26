/* SPDX-License-Identifier: Apache-2.0 */
/* Full Rust HID engine with synchronous packet hardware. No protocol emulation:
 * framing, mailbox ownership, execution cancellation and resync are Rust-owned. */
#include "core.h"
#include "usb_io.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

extern uint8_t CTAPHID_OutEvent(const uint8_t *report);
static uint32_t ticks;
static uint8_t configured = 1;
static uint8_t output[128][64];
static size_t output_count;
static uint8_t scratch[3072], scratch_owner;
static unsigned leases, clears;
static uint8_t injected[2][64];
static uint32_t inject_at[2];
static size_t injection_count, injected_count;
static uint32_t disconnect_at;

uint32_t device_get_tick(void) { return ticks; }
void device_delay(int ms) { assert(ms >= 0); ticks += (uint32_t)ms; }
uint32_t ck_usb_dcd_lock(void) { return 0; }
void ck_usb_dcd_unlock(uint32_t mask) { assert(mask == 0); }
uint8_t ck_usb_configured(void) { return configured; }
uint8_t ck_usb_tx_idle(uint8_t ep) { assert(ep == 0x82); return 1; }
void ck_usb_receive(uint8_t ep) { assert(ep == 2); }
int32_t ck_usb_submit(uint8_t ep, const uint8_t *data, uint16_t n, uint8_t zlp) {
  assert(ep == 0x82 && n == 64 && zlp == 0 && output_count < 128);
  memcpy(output[output_count++], data, 64);
  return 1;
}
uint8_t ck_ccid_idle(void) { return 1; }
uint32_t ck_platform_now(void) { return ticks; }
uint8_t ck_platform_touched(void) { return 0; }
void ck_platform_led(uint8_t on) { (void)on; }
uint8_t ck_platform_progress(void) {
  assert(++ticks < 100000); /* A stuck execution must fail, not hang CI. */
  if (injected_count < injection_count && ticks >= inject_at[injected_count]) {
    assert(CTAPHID_OutEvent(injected[injected_count]));
    injected_count++;
  }
  if (disconnect_at && ticks >= disconnect_at) {
    disconnect_at = 0;
    configured = 0;
    ck_hid_packet_reset();
  }
  return ck_hid_executing() ? ck_hid_progress() : 1;
}
size_t pke_buffer_size(void) { return sizeof(scratch); }
int pke_buffer_acquire(uint8_t owner) {
  if (!owner || scratch_owner) return -1;
  scratch_owner = owner;
  leases++;
  return 0;
}
int pke_buffer_release(uint8_t owner) {
  if (!owner || owner != scratch_owner) return -1;
  for (size_t i = 0; i < sizeof(scratch); ++i) assert(scratch[i] == 0);
  scratch_owner = 0;
  return 0;
}
int pke_buffer_clear(void) {
  assert(scratch_owner);
  memset(scratch, 0, sizeof(scratch));
  clears++;
  return 0;
}
int pke_buffer_read(size_t offset, uint8_t *out, size_t n) {
  if (!scratch_owner || offset > sizeof(scratch) || n > sizeof(scratch) - offset) return -1;
  memcpy(out, scratch + offset, n);
  return 0;
}
int pke_buffer_write(size_t offset, const uint8_t *in, size_t n) {
  if (!scratch_owner || offset > sizeof(scratch) || n > sizeof(scratch) - offset) return -1;
  memcpy(scratch + offset, in, n);
  return 0;
}

static void header(uint8_t report[64], uint32_t cid, uint8_t cmd, uint16_t n) {
  memset(report, 0, 64);
  report[0] = (uint8_t)(cid >> 24); report[1] = (uint8_t)(cid >> 16);
  report[2] = (uint8_t)(cid >> 8); report[3] = (uint8_t)cid;
  report[4] = cmd; report[5] = (uint8_t)(n >> 8); report[6] = (uint8_t)n;
}
static void feed(const uint8_t report[64]) {
  assert(CTAPHID_OutEvent(report));
  CTAPHID_Loop(0);
}
static void drain(void) {
  for (unsigned i = 0; ck_hid_active(); ++i) {
    assert(i < 100);
    CTAPHID_Loop(0);
  }
  assert(!scratch_owner);
}
static void reset(void) {
  ck_hid_packet_reset();
  CTAPHID_Loop(0);
  output_count = injection_count = injected_count = 0;
  disconnect_at = 0;
}
static size_t response(uint32_t cid, uint8_t command, uint8_t *out, size_t capacity) {
  size_t copied = 0, total = 0;
  uint8_t sequence = 0;
  for (size_t i = 0; i < output_count; ++i) {
    const uint8_t *r = output[i];
    uint32_t channel = (uint32_t)r[0] << 24 | (uint32_t)r[1] << 16 | (uint32_t)r[2] << 8 | r[3];
    if (channel != cid || r[4] == 0xbb) continue; /* keepalive */
    size_t start;
    if (!copied) {
      assert(r[4] == command);
      total = (size_t)r[5] << 8 | r[6];
      assert(total && total <= capacity);
      start = 7;
    } else {
      assert(r[4] == sequence++);
      start = 5;
    }
    size_t count = total - copied;
    if (count > 64 - start) count = 64 - start;
    memcpy(out + copied, r + start, count);
    copied += count;
    if (copied == total) return total;
  }
  assert(0 && "missing complete response");
  return 0;
}
static void command(uint32_t cid, uint8_t cmd, const uint8_t *body, size_t length) {
  uint8_t report[64];
  header(report, cid, cmd, (uint16_t)length);
  size_t n = length < 57 ? length : 57;
  memcpy(report + 7, body, n);
  feed(report);
  uint8_t seq = 0;
  for (size_t pos = n; pos < length; pos += n) {
    header(report, cid, seq++, 0);
    n = length - pos;
    if (n > 59) n = 59;
    memcpy(report + 5, body + pos, n);
    feed(report);
  }
  drain();
}
int main(void) {
  assert(ck_core_install() == 0);
  reset();
  uint8_t data[1100], result[1100];
  const uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
  command(UINT32_MAX, 0x86, nonce, sizeof(nonce));
  assert(response(UINT32_MAX, 0x86, result, sizeof(result)) == 17);
  assert(!memcmp(result, nonce, 8));
  uint32_t cid = (uint32_t)result[8] << 24 | (uint32_t)result[9] << 16 | (uint32_t)result[10] << 8 | result[11];
  assert(cid && cid != UINT32_MAX);

  /* Long echo crosses inline storage and exercises PKE lease erasure. */
  output_count = 0;
  for (size_t i = 0; i < 700; ++i) data[i] = (uint8_t)i;
  unsigned old_leases = leases;
  command(cid, 0x81, data, 700);
  assert(response(cid, 0x81, result, sizeof(result)) == 700);
  assert(!memcmp(data, result, 700));
  assert(leases > old_leases && clears == leases);

  output_count = 0;
  data[0] = 4;
  command(cid, 0x90, data, 1);
  assert(response(cid, 0x90, result, sizeof(result)) > 256 && result[0] == 0);

  /* A large real CBOR request must be parsed before crypto can reuse PKE.
   * clientPIN getKeyAgreement plus an ignored 700-byte extension value. */
  output_count = 0;
  const uint8_t pin_header[] = {6, 0xa3, 1, 1, 2, 2, 0x18, 0x7f, 0x59, 2, 0xbc};
  memcpy(data, pin_header, sizeof(pin_header));
  memset(data + sizeof(pin_header), 0xa5, 700);
  command(cid, 0x90, data, sizeof(pin_header) + 700);
  assert(response(cid, 0x90, result, sizeof(result)) > 64 && result[0] == 0);
  assert(clears == leases);

  /* Abandoned fragmented input erases its lease on both sequence failure
   * and timeout; a later valid request must be able to reacquire it. */
  uint8_t partial[64];
  output_count = 0;
  header(partial, cid, 0x90, 700); partial[7] = 6;
  feed(partial);
  assert(scratch_owner);
  header(partial, cid, 1, 0); /* expected sequence zero */
  feed(partial); drain();
  assert(response(cid, 0xbf, result, sizeof(result)) == 1 && result[0] == 4);
  output_count = 0;
  header(partial, cid, 0x90, 700); partial[7] = 6;
  feed(partial);
  assert(scratch_owner);
  ticks += 1000;
  CTAPHID_Loop(0); drain();
  assert(response(cid, 0xbf, result, sizeof(result)) == 1 && result[0] == 5);
  assert(clears == leases);

  /* The real selection command blocks in Rust presence. A foreign request
   * receives BUSY, then the owning channel cancels without reentering CORE. */
  output_count = 0;
  injection_count = 2; injected_count = 0;
  header(injected[0], cid + 1, 0x81, 1);
  header(injected[1], cid, 0x91, 0);
  inject_at[0] = ticks + 3; inject_at[1] = ticks + 6;
  data[0] = 0x0b;
  command(cid, 0x90, data, 1);
  assert(injected_count == 2);
  assert(response(cid + 1, 0xbf, result, sizeof(result)) == 1 && result[0] == 6);
  assert(response(cid, 0x90, result, sizeof(result)) == 1 && result[0] == 0x2d);
  int keepalive = 0;
  for (size_t i = 0; i < output_count; ++i) keepalive |= output[i][4] == 0xbb && output[i][7] == 2;
  assert(keepalive);

  /* Same-channel INIT suppresses the interrupted response, remains queued,
   * and is processed only after the applet borrow unwinds. */
  output_count = 0;
  injection_count = 1; injected_count = 0;
  header(injected[0], cid, 0x86, 8); memcpy(injected[0] + 7, nonce, 8);
  inject_at[0] = ticks + 3;
  command(cid, 0x90, data, 1);
  CTAPHID_Loop(0); drain();
  assert(response(cid, 0x86, result, sizeof(result)) == 17 && !memcmp(result, nonce, 8));
  for (size_t i = 0; i < output_count; ++i) assert(output[i][4] != 0x90);

  output_count = injection_count = injected_count = 0;
  disconnect_at = ticks + 3;
  command(cid, 0x90, data, 1);
  for (size_t i = 0; i < output_count; ++i) assert(output[i][4] != 0x90);
  configured = 1; reset();
  data[0] = 4;
  command(cid, 0x90, data, 1);
  assert(response(cid, 0x90, result, sizeof(result)) > 256 && result[0] == 0);
  puts("Rust HID core: framing, PKE, GetInfo, keepalive, busy, cancel, resync and disconnect passed");
  return 0;
}
