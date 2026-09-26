// SPDX-License-Identifier: Apache-2.0
// Exercise the production ISR/main-loop adapter with deterministic interrupts.
#include "core.h"
#include <assert.h>
#include <ctaphid.h>
#include "usb_io.h"


static uint32_t now, masked;
static uint8_t reset_on_lock;
uint32_t __get_PRIMASK(void) { return masked; }
void __disable_irq(void) {
  masked = 1;
  if (reset_on_lock) { reset_on_lock = 0; ck_hid_packet_reset(); }
}
void __enable_irq(void) { masked = 0; }
static unsigned received, resets, sent;
static uint8_t inject, reset_during_poll, respond, idle = 1;
static const uint8_t *in_flight;
static uint8_t packet[64] = {0x12, 0x34, 0x56, 0x78, 0x81, 0, 1, 0xab};
uint32_t device_get_tick(void) { return now; }
void device_delay(int ms) { now += (uint32_t)ms; }
void ck_hid_reset(void) { resets++; }
uint8_t ck_hid_poll(const uint8_t *input, uint32_t tick, uint32_t clock, uint8_t *out) {
  assert(clock == now);
  if (input) {
    assert(tick <= now);
    assert(memcmp(input, packet, 64) == 0);
    // RX is rearmed before Rust executes. A new packet cannot alter this borrow.
    if (inject == 2) {
      inject = 0;
      uint8_t next[64];
      memcpy(next, packet, 64);
      next[7] ^= 0xff;
      assert(CTAPHID_OutEvent(next));
      assert(memcmp(input, packet, 64) == 0);
    }
    received++;
  }
  if (inject) {
    inject = 0;
    assert(!input);
    assert(CTAPHID_OutEvent(packet));
  }
  if (reset_during_poll) { reset_during_poll = 0; ck_hid_packet_reset(); }
  if (respond) { respond = 0; memset(out, 0x5a, 64); return 3; }
  return 0;
}
uint32_t ck_usb_dcd_lock(void) { uint32_t m=masked;__disable_irq();return m; }
void ck_usb_dcd_unlock(uint32_t m) { if(!m)__enable_irq(); }
uint8_t ck_usb_configured(void) { return 1; }
uint8_t ck_usb_tx_idle(uint8_t ep) { assert(ep==0x82);return idle; }
int32_t ck_usb_submit(uint8_t ep, const uint8_t *out, uint16_t n, uint8_t zlp) {
  assert(ep == 0x82 && !zlp && idle && n == 64 && masked);
  idle = 0;
  in_flight = out;
  sent++;
  return 1;
}
void ck_usb_receive(uint8_t ep) { assert(masked && ep==2); }
int main(void) {
  ck_hid_packet_reset();
  inject = 1;
  CTAPHID_Loop(0); // IRQ arrives during an empty Rust poll
  assert(received == 0 && !CTAPHID_RxCanAccept());
  CTAPHID_Loop(0);
  assert(received == 1 && CTAPHID_RxCanAccept());

  assert(CTAPHID_OutEvent(packet));
  respond = 1;
  CTAPHID_Loop(0);
  assert(sent == 1 && ck_hid_busy());
  assert(CTAPHID_OutEvent(packet));
  now = 1000;
  unsigned before = resets;
  CTAPHID_Loop(0); // timeout releases PKE, not the endpoint-owned report
  assert(resets == before + 1 && !ck_hid_busy() && !idle);
  for (unsigned i = 0; i < 64; i++) assert(in_flight[i] == 0x5a);
  CTAPHID_Loop(0);
  assert(received == 2 && resets == before + 1);
  idle = 1;
  CTAPHID_Loop(0);
  assert(received == 3);

  assert(CTAPHID_OutEvent(packet));
  respond = reset_during_poll = 1;
  CTAPHID_Loop(0);
  assert(sent == 1); // obsolete reply must not cross a USB reset
  CTAPHID_Loop(0);
  assert(CTAPHID_RxCanAccept() && !ck_hid_busy());

  assert(CTAPHID_OutEvent(packet));
  inject = 2;
  CTAPHID_Loop(0);
  assert(!CTAPHID_RxCanAccept());
  ck_hid_packet_reset();
  CTAPHID_Loop(0);

  ck_hid_execution_begin(0x12345678);
  ck_hid_keepalive(1);
  assert(ck_hid_executing() && ck_hid_busy());
  assert(ck_hid_progress());
  assert(in_flight[0] == 0x12 && in_flight[3] == 0x78);
  assert(in_flight[4] == 0xbb && in_flight[6] == 1 && in_flight[7] == 2);
  uint8_t command[64] = {0x12, 0x34, 0x56, 0x78, 0x91};
  assert(CTAPHID_OutEvent(command));
  assert(!ck_hid_progress()); // CANCEL works while IN still owns the keepalive
  assert(in_flight[4] == 0xbb && in_flight[7] == 2);
  idle = 1;
  ck_hid_execution_end();
  assert(!ck_hid_executing());

  ck_hid_execution_begin(0x12345678);
  command[0] = 0x87;
  assert(CTAPHID_OutEvent(command));
  assert(ck_hid_progress()); // foreign CANCEL is busy, not cancellation
  assert(in_flight[0] == 0x87 && in_flight[4] == 0xbf && in_flight[7] == 6);
  idle = 1;
  command[0] = 0x12;
  command[4] = 0x86;
  command[6] = 8;
  assert(CTAPHID_OutEvent(command));
  assert(!ck_hid_progress()); // INIT stays queued for Rust after unwinding
  assert(!CTAPHID_RxCanAccept());
  ck_hid_execution_end();
  ck_hid_packet_reset();
  CTAPHID_Loop(0);

  ck_hid_execution_begin(0x12345678);
  assert(ck_hid_progress());
  ck_hid_execution_end(); // stalled control IN times out without overwriting it
  assert(!idle && in_flight[4] == 0xbb && in_flight[7] == 1);
  assert(!ck_hid_executing());

  idle = 1;
  ck_hid_packet_reset();
  CTAPHID_Loop(0);
  assert(CTAPHID_OutEvent(packet));
  respond = 1;
  CTAPHID_Loop(0);
  idle = 1;
  CTAPHID_Loop(0); // completed command retains a bounded idle lease
  assert(ck_hid_busy());
  now += 1999;
  assert(ck_hid_busy());
  now++;
  assert(!ck_hid_busy());

  // Reset between Rust's epoch check and native submission rejects stale bytes.
  assert(CTAPHID_OutEvent(packet));
  unsigned old_sent = sent;
  reset_on_lock = respond = 1;
  CTAPHID_Loop(0);
  assert(sent == old_sent && !masked);
  CTAPHID_Loop(0);
  // New-connection input queued before main-loop reset acknowledgement survives.
  ck_hid_packet_reset();
  unsigned old_received = received;
  assert(CTAPHID_OutEvent(packet));
  CTAPHID_Loop(0);
  assert(received == old_received + 1);
  // Cooperative APDU waits answer competing HID commands without reentering
  // the core poll/reset, including when an old HID idle lease has expired.
  idle = 1;
  ck_hid_packet_reset();
  CTAPHID_Loop(0);
  unsigned polls_before = received, resets_before = resets;
  uint8_t competing[64] = {0x12,0x34,0x56,0x78,0x90,0,1,4};
  assert(CTAPHID_OutEvent(competing));
  ck_hid_foreign_progress();
  assert(!idle && in_flight[4]==0xbf && in_flight[7]==0x06);
  assert(memcmp(in_flight, competing, 4)==0);
  assert(received==polls_before && resets==resets_before && !ck_hid_executing());
  uint8_t saved[64];memcpy(saved,in_flight,64);
  competing[4]=0x86;competing[6]=8; // INIT may not reset the active APDU.
  assert(CTAPHID_OutEvent(competing));
  ck_hid_foreign_progress();
  assert(memcmp(in_flight,saved,64)==0 && !CTAPHID_RxCanAccept());
  idle=1;ck_hid_foreign_progress();
  assert(in_flight[7]==0x06 && CTAPHID_RxCanAccept());
  idle=1;competing[4]=0x91;competing[6]=0;
  unsigned sent_before=sent;
  assert(CTAPHID_OutEvent(competing));ck_hid_foreign_progress();
  assert(sent==sent_before && CTAPHID_RxCanAccept());
  memset(competing,0,4);competing[4]=0x81;
  assert(CTAPHID_OutEvent(competing));ck_hid_foreign_progress();
  assert(in_flight[7]==0x0b); // Invalid channel, not a valid busy request.
  idle=1;ck_hid_packet_reset();
  ck_hid_foreign_progress();
  assert(resets==resets_before); // Reset cleanup waits until Core unwinds.
  CTAPHID_Loop(0);
  masked = 1;
  respond = 1;
  CTAPHID_Loop(0);
  assert(masked); // never unmask an already masked caller
}
