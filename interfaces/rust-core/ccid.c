// SPDX-License-Identifier: Apache-2.0
// C owns USB/CCID framing only. APDU bytes and card resets enter Rust exclusively
// from CCID_Loop, never from USB interrupt callbacks.
#include "core.h"
#include <ccid.h>
#include <usb_device.h>
#include <usbd_ccid.h>

#define FRAME_CAPACITY 261u
static uint8_t request[10 + FRAME_CAPACITY];
static uint8_t response[10 + 258];
static uint32_t received, expected;
static volatile uint8_t phase; // 0 idle, 1 receiving, 2 queued, 3 responding
static volatile uint8_t reset_pending;
static volatile uint32_t epoch;
static uint8_t active;
static const uint8_t atr[] = {0x3b, 0xf7, 0x11, 0,    0,    0x81, 0x31, 0xfe, 0x65,
                              0x43, 0x61, 0x6e, 0x6f, 0x4b, 0x65, 0x79, 0x99};

uint32_t ccid_get_le32(const uint8_t value[4]) {
  uint32_t v;
  memcpy(&v, value, 4);
  return letoh32(v);
}
void ccid_put_le32(uint8_t out[4], uint32_t value) {
  value = htole32(value);
  memcpy(out, &value, 4);
}
uint8_t CCID_Init(void) {
  // Do not release or mutate buffers here: USB reset can interrupt Rust while
  // it borrows request bytes. Main-loop cleanup owns their lifetime.
  epoch++;
  reset_pending = 1;
  return 0;
}
uint8_t CCID_OutEvent(uint8_t *data, uint8_t length) {
  if (reset_pending || phase >= 2 || !length) return 0;
  if (phase == 0) {
    if (length < 10) return 0;
    expected = ccid_get_le32(data + 1);
    if (expected > FRAME_CAPACITY) {
      memcpy(request, data, 10);
      received = 10;
      expected = 10;
      // Oversized CCID frames are transport errors, not APDU commands.
      request[0] = 0xff;
      phase = 2;
      return 0;
    }
    expected += 10;
    received = 0;
    phase = 1;
  }
  uint32_t n = MIN((uint32_t)length, expected - received);
  memcpy(request + received, data, n);
  received += n;
  if (received == expected) phase = 2;
  return 0;
}
void CCID_InFinished(uint8_t extension) {
  if (!extension) phase = 0;
}
void CCID_Loop(void) {
  if (reset_pending) {
    phase = 3;
    reset_pending = 0;
    ck_core_reset();
    active = 0;
    received = expected = 0;
    phase = 0;
    return;
  }
  if (phase != 2) return;
  uint32_t generation = epoch;
  phase = 3;
  if (reset_pending) return;
  uint32_t payload = 0;
  uint8_t error = 0, type = RDR_TO_PC_SLOTSTATUS, specific = 0, unsupported = 0;
  uint8_t slot = request[5], seq = request[6], command = request[0];
  if (slot) error = SLOTERROR_BAD_SLOT;
  if (!error) switch (command) {
    case PC_TO_RDR_ICCPOWERON:
      type = RDR_TO_PC_DATABLOCK;
      if (expected != 10 || request[8] || request[9]) {
        error = SLOTERROR_BAD_DWLENGTH;
        break;
      }
      if (request[7]) {
        error = SLOTERROR_BAD_POWERSELECT;
        break;
      }
      ck_core_reset();
      active = 1;
      memcpy(response + 10, atr, sizeof(atr));
      payload = sizeof(atr);
      break;
    case PC_TO_RDR_ICCPOWEROFF:
      if (expected != 10) {
        error = SLOTERROR_BAD_DWLENGTH;
        break;
      }
      ck_core_reset();
      active = 0;
      break;
    case PC_TO_RDR_GETSLOTSTATUS:
      if (expected != 10) error = SLOTERROR_BAD_DWLENGTH;
      break;
    case PC_TO_RDR_XFRBLOCK: {
      type = RDR_TO_PC_DATABLOCK;
      if (!active) {
        error = SLOTERROR_ICC_MUTE;
        break;
      }
      if (request[8] || request[9]) {
        error = SLOTERROR_BAD_LEVELPARAMETER;
        break;
      }
      int32_t n = ck_core_exchange(1, request + 10, expected - 10, response + 10, sizeof(response) - 10);
      if (n < 0) {
        error = SLOTERROR_HW_ERROR;
        break;
      }
      payload = (uint32_t)n;
      break;
    }
    case PC_TO_RDR_GETPARAMETERS:
    case PC_TO_RDR_RESETPARAMETERS:
    case PC_TO_RDR_SETPARAMETERS: {
      static const uint8_t parameters[] = {0x11, 0x10, 0, 0x15, 0, 0xfe, 0};
      type = RDR_TO_PC_PARAMETERS;
      specific = 1;
      if (command == PC_TO_RDR_SETPARAMETERS && (request[7] != 1 || expected != 17)) {
        error = SLOTERROR_BAD_PROTOCOLNUM;
        break;
      }
      memcpy(response + 10, parameters, sizeof(parameters));
      payload = sizeof(parameters);
      break;
    }
    default:
      unsupported = 1;
      error = SLOTERROR_CMD_NOT_SUPPORTED;
      break;
    }
  response[0] = type;
  ccid_put_le32(response + 1, payload);
  response[5] = slot;
  response[6] = seq;
  response[7] = (active ? BM_ICC_PRESENT_ACTIVE : BM_ICC_PRESENT_INACTIVE);
  if (error || unsupported) response[7] |= BM_COMMAND_STATUS_FAILED;
  response[8] = error;
  response[9] = specific;
  // A USB reset during Rust execution invalidates this transfer. The next loop
  // clears the Rust session before accepting a command from the new connection.
  if (generation != epoch) return;
  if (CCID_Response_SendData(&usb_device, response, (uint16_t)(payload + 10), 0) != USBD_OK) phase = 0;
}
