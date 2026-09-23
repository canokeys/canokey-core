// SPDX-License-Identifier: Apache-2.0
// USB callbacks only queue a report. Rust and PKE are main-loop-only.
#include "core.h"
#include <ctaphid.h>
#include <device.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>

static uint8_t incoming[HID_RPT_SIZE], outgoing[HID_RPT_SIZE];
static volatile uint8_t queued, reset_pending;
static volatile uint32_t epoch;
static uint32_t received_at, sent_at;
static uint8_t active, transmitting;

// One producer (USB ISR), one consumer (main loop); OUT remains NAKed while
// queued is set, including while Rust borrows incoming.
static void barrier(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
uint8_t CTAPHID_RxCanAccept(void) { return !reset_pending && !queued; }
uint8_t CTAPHID_OutEvent(uint8_t *data) {
  if (!CTAPHID_RxCanAccept()) return 0;
  memcpy(incoming, data, sizeof(incoming));
  received_at = device_get_tick();
  barrier();
  queued = 1;
  return 1;
}
void CTAPHID_TxReset(void) {
  epoch++;
  reset_pending = 1;
}
uint8_t CTAPHID_Init(uint8_t (*send_report)(USBD_HandleTypeDef *, uint8_t *, uint16_t)) {
  UNUSED(send_report);
  CTAPHID_TxReset();
  return 0;
}
uint8_t ck_hid_busy(void) { return active; }
uint8_t CTAPHID_Loop(uint8_t wait_for_user) {
  UNUSED(wait_for_user);
  if (reset_pending) {
    // The ISR cannot mutate borrowed Rust state or release its PKE storage.
    ck_hid_reset();
    queued = active = transmitting = 0;
    memset(incoming, 0, sizeof(incoming));
    memset(outgoing, 0, sizeof(outgoing));
    barrier();
    reset_pending = 0;
  }
  if (usb_device.dev_state != USBD_STATE_CONFIGURED) return 0;
  if (USBD_CTAPHID_IsIdle() != USBD_OK) {
    if (transmitting && device_get_tick() - sent_at >= 1000) {
      // CIU FlushEP is a no-op. Release the source/session, but retain the
      // already submitted report until DataIn or USB reset permits reuse.
      ck_hid_reset();
      active = transmitting = 0;
    }
    return 0;
  }
  transmitting = 0;
  uint32_t generation = epoch;
  uint8_t has_input = queued;
  barrier();
  // Freeze whether this poll consumes a report. An IRQ may enqueue while an
  // empty poll runs; clearing queued unconditionally would drop that report.
  uint32_t tick = has_input ? received_at : 0;
  uint8_t result = ck_hid_poll(has_input ? incoming : NULL, tick, device_get_tick(), outgoing);
  if (generation != epoch) return 0;
  active = (result & 2) != 0;
  barrier();
  if (has_input) queued = 0;
  if (result & 1) {
    if (USBD_CTAPHID_SendReport(&usb_device, outgoing, sizeof(outgoing)) != USBD_OK) {
      CTAPHID_TxReset();
      return 0;
    }
    sent_at = device_get_tick();
    transmitting = 1;
  }
  USBD_CTAPHID_ServiceReceive();
  return 0;
}
