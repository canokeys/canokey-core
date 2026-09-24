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
static uint32_t received_at, sent_at, session_last_used;
static uint8_t active, transmitting, session_owned;
// A control report may remain endpoint-owned while Rust builds the final reply.
// It cannot alias outgoing, which is borrowed by ck_hid_poll during execution.
static uint8_t control[HID_RPT_SIZE];
static uint32_t executing_cid, keepalive_at;
static uint8_t executing, cancelled, abandon, keepalive_status;

// One producer (USB ISR), one consumer (main loop); OUT remains NAKed while
// queued is set. Main-loop polls lend Rust a copy before rearming RX.
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
uint8_t ck_hid_active(void) { return active; }
uint8_t ck_hid_busy(void) {
  return active || (session_owned && device_get_tick() - session_last_used < 2000);
}
uint8_t ck_hid_executing(void) { return executing; }
void ck_hid_execution_begin(uint32_t cid) {
  executing_cid = cid;
  executing = active = 1;
  cancelled = abandon = 0;
  keepalive_status = KEEPALIVE_STATUS_PROCESSING;
  keepalive_at = device_get_tick() - 100;
}
void ck_hid_keepalive(uint8_t waiting) { keepalive_status = waiting ? KEEPALIVE_STATUS_UPNEEDED : KEEPALIVE_STATUS_PROCESSING; }
static void send_control(uint32_t cid, uint8_t command, uint8_t value) {
  memset(control, 0, sizeof(control));
  uint32_t wire_cid = htobe32(cid);
  memcpy(control, &wire_cid, sizeof(wire_cid));
  control[4] = command;
  control[6] = 1;
  control[7] = value;
  if (USBD_CTAPHID_SendReport(&usb_device, control, sizeof(control)) != USBD_OK) {
    abandon = 1;
    return;
  }
  sent_at = device_get_tick();
  transmitting = 1;
}
uint8_t ck_hid_progress(void) {
  if (!executing || reset_pending || usb_device.dev_state != USBD_STATE_CONFIGURED) return 0;
  uint8_t idle = USBD_CTAPHID_IsIdle() == USBD_OK;
  if (!idle && transmitting && device_get_tick() - sent_at >= 1000) abandon = 1;
  if (queued) {
    barrier();
    uint32_t cid;
    memcpy(&cid, incoming, sizeof(cid));
    cid = be32toh(cid);
    if (cid == executing_cid && incoming[4] == CTAPHID_INIT && incoming[5] == 0 && incoming[6] == INIT_NONCE_SIZE) {
      // Leave INIT queued for normal Rust processing after this call unwinds.
      // No response from the interrupted command may precede its INIT reply.
      abandon = 1;
    } else if (cid == executing_cid && incoming[4] == CTAPHID_CANCEL && incoming[5] == 0 && incoming[6] == 0) {
      cancelled = 1;
      queued = 0;
    } else if (idle) {
      // Continuations are ignored outside receive; new commands are busy.
      if (incoming[4] & TYPE_MASK) {
        uint8_t error = ERR_CHANNEL_BUSY;
        if (cid == 0 || (cid == CID_BROADCAST && incoming[4] != CTAPHID_INIT)) error = ERR_INVALID_CID;
        else if (cid == executing_cid && incoming[4] == CTAPHID_INIT) error = ERR_INVALID_LEN;
        send_control(cid, CTAPHID_ERROR, error);
        idle = 0;
      }
      queued = 0;
    }
    barrier();
    USBD_CTAPHID_ServiceReceive();
  }
  if (cancelled || abandon) return 0;
  if (idle && device_get_tick() - keepalive_at >= 100) {
    send_control(executing_cid, CTAPHID_KEEPALIVE, keepalive_status);
    keepalive_at = device_get_tick();
  }
  return !abandon;
}
void ck_hid_execution_end(void) {
  // The final Rust reply must not overwrite or race an endpoint-owned keepalive.
  // A stalled IN retains its buffer until DataIn or USB reset, just like normal TX.
  while (!reset_pending && USBD_CTAPHID_IsIdle() != USBD_OK) {
    if (device_get_tick() - sent_at >= 1000) {
      abandon = 1;
      break;
    }
    device_delay(1);
  }
  executing = 0;
}
uint8_t CTAPHID_Loop(uint8_t wait_for_user) {
  UNUSED(wait_for_user);
  if (reset_pending) {
    // The ISR cannot mutate borrowed Rust state or release its PKE storage.
    ck_hid_reset();
    queued = active = transmitting = executing = abandon = session_owned = 0;
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
      active = transmitting = session_owned = 0;
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
  uint8_t report[HID_RPT_SIZE];
  if (has_input) {
    // Rust can execute a presence wait from this poll. Copy before rearming RX
    // so a CANCEL/INIT can arrive without modifying its borrowed input.
    memcpy(report, incoming, sizeof(report));
    barrier();
    queued = 0;
    USBD_CTAPHID_ServiceReceive();
  }
  uint8_t result = ck_hid_poll(has_input ? report : NULL, tick, device_get_tick(), outgoing);
  if (generation != epoch) return 0;
  if (abandon) {
    abandon = 0;
    active = transmitting = session_owned = 0;
    return 0;
  }
  if (active || (result & 2)) {
    session_owned = 1;
    session_last_used = device_get_tick();
  }
  active = (result & 2) != 0;
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
