// SPDX-License-Identifier: Apache-2.0
// Exercise the production ISR/main-loop adapter with deterministic interrupts.
#include "core.h"
#include <assert.h>
#include <ctaphid.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>

USBD_HandleTypeDef usb_device;
static uint32_t now;
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
  if (reset_during_poll) { reset_during_poll = 0; CTAPHID_TxReset(); }
  if (respond) { respond = 0; memset(out, 0x5a, 64); return 3; }
  return 0;
}
uint8_t USBD_CTAPHID_IsIdle(void) { return idle ? USBD_OK : USBD_BUSY; }
uint8_t USBD_CTAPHID_SendReport(USBD_HandleTypeDef *d, uint8_t *out, uint16_t n) {
  assert(d == &usb_device && idle && n == 64);
  idle = 0;
  in_flight = out;
  sent++;
  return USBD_OK;
}
void USBD_CTAPHID_ServiceReceive(void) {}
int main(void) {
  usb_device.dev_state = USBD_STATE_CONFIGURED;
  CTAPHID_Init(NULL);
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
  CTAPHID_TxReset();
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
  CTAPHID_TxReset();
  CTAPHID_Loop(0);

  ck_hid_execution_begin(0x12345678);
  assert(ck_hid_progress());
  ck_hid_execution_end(); // stalled control IN times out without overwriting it
  assert(!idle && in_flight[4] == 0xbb && in_flight[7] == 1);
  assert(!ck_hid_executing());

  idle = 1;
  CTAPHID_TxReset();
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
}
