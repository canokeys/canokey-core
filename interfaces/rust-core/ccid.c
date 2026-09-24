// SPDX-License-Identifier: Apache-2.0
// C owns USB/CCID framing only. APDU bytes and card resets enter Rust exclusively
// from CCID_Loop, never from USB interrupt callbacks.
#include "core.h"
#include <ccid.h>
#include <device.h>
#include <usb_device.h>
#include <usbd_ccid.h>
#if ENABLE_IFACE_CTAPHID
#include <pke.h>
#endif

#define FRAME_CAPACITY 261u
#define RESPONSE_CAPACITY 258u
#define CCID_MESSAGE_TYPE 0u
#define CCID_LENGTH 1u
#define CCID_SLOT 5u
#define CCID_SEQUENCE 6u
#define CCID_PARAMETER_0 7u
#define CCID_PARAMETER_1 8u
#define CCID_PARAMETER_2 9u
#define CCID_EXTENSION_INTERVAL_MS 500u
#define CCID_PROTOCOL_T1 1u
#define CCID_RX_TIMEOUT_MS 2000u
#define CCID_FIDO_PREFIX (CCID_CMD_HEADER_SIZE + 7u)
enum ccid_phase { CCID_IDLE, CCID_RECEIVING, CCID_QUEUED, CCID_RESPONDING };
static uint8_t request[CCID_CMD_HEADER_SIZE + FRAME_CAPACITY];
static uint8_t response[CCID_CMD_HEADER_SIZE + RESPONSE_CAPACITY];
static uint32_t received, expected;
// USB owns the packet buffer and holds OUT until the main loop consumes it.
static const uint8_t *incoming;
static volatile uint8_t incoming_length;
static uint32_t received_at, last_received;
static uint8_t receive_error;
static volatile uint8_t phase; // enum ccid_phase; accessed by USB callbacks.
static volatile uint8_t reset_pending;
// USB reset increments this generation even during a long Rust call. Its
// eventual reply is discarded if the connection changed while it was running.
static volatile uint32_t epoch;
static uint8_t active;
#if ENABLE_IFACE_CTAPHID
static uint32_t session_last_used;
static uint8_t session_owned, pke_held;
static uint16_t source_length, source_status;
uint8_t ck_ccid_scratch_busy(void) { return pke_held; }
void ck_ccid_source_close(void) {
  if (!pke_held) return;
  // Fail closed if hardware cannot wipe/release the transient request.
  if (pke_buffer_clear() != 0 || pke_buffer_release(PKE_BUFFER_OWNER_CTAP) != 0)
    for (;;) {
    }
  pke_held = 0;
}
int32_t ck_ccid_source_read(size_t offset, uint8_t *out, size_t length) {
  const size_t total = expected - CCID_CMD_HEADER_SIZE;
  if (!pke_held || offset > total || length > total - offset) return -1;
  while (length) {
    size_t n;
    if (offset < 7) {
      n = MIN(length, 7 - offset);
      memcpy(out, request + CCID_CMD_HEADER_SIZE + offset, n);
    } else if (offset < 7u + source_length) {
      n = MIN(length, 7u + source_length - offset);
      if (pke_buffer_read(offset - 7, out, n) != 0) return -1;
    } else {
      n = length;
      memcpy(out, request + CCID_FIDO_PREFIX + offset - 7 - source_length, n);
    }
    offset += n;
    out += n;
    length -= n;
  }
  return 0;
}
#endif
static const uint8_t atr[] = {0x3b, 0xf7, 0x11, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x65,
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
  incoming_length = 0;
  reset_pending = 1;
  return 0;
}
uint8_t ck_ccid_rx_ready(void) { return !reset_pending && !incoming_length; }
uint8_t CCID_OutEvent(uint8_t *data, uint8_t length) {
  // Reports from the new USB connection may queue during deferred cleanup.
  // Init discarded the old notification; neither ISR touches request[].
  if (incoming_length || !length) return 0;
  incoming = data;
  received_at = device_get_tick();
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  incoming_length = length;
  return 0;
}

#if ENABLE_IFACE_CTAPHID
static void begin_source(void) {
  if (request[CCID_SLOT]) {
    receive_error = SLOTERROR_BAD_SLOT;
    return;
  }
  if (!active) {
    receive_error = SLOTERROR_ICC_MUTE;
    return;
  }
  if (request[CCID_PARAMETER_1] || request[CCID_PARAMETER_2]) {
    receive_error = SLOTERROR_BAD_LEVELPARAMETER;
    return;
  }
  int32_t lc = ck_core_extended_begin(request + CCID_CMD_HEADER_SIZE, expected - CCID_CMD_HEADER_SIZE);
  if (lc < 0) {
    source_status = (uint16_t)-lc;
    return;
  }
  if ((size_t)lc > pke_buffer_size() || pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP) != 0) {
    receive_error = SLOTERROR_HW_ERROR;
    return;
  }
  source_length = (uint16_t)lc;
  pke_held = 1;
}
static uint32_t stage_fragment(const uint8_t *data, uint32_t length) {
  if (received < CCID_FIDO_PREFIX) {
    length = MIN(length, CCID_FIDO_PREFIX - received);
    memcpy(request + received, data, length);
  } else if (!source_status) {
    if (received < CCID_FIDO_PREFIX + source_length) {
      length = MIN(length, CCID_FIDO_PREFIX + source_length - received);
      if (pke_buffer_write(received - CCID_FIDO_PREFIX, data, length) != 0) receive_error = SLOTERROR_HW_ERROR;
    } else {
      // Le occupies at most two bytes, directly after the saved APDU prefix.
      size_t offset = received - (CCID_FIDO_PREFIX + source_length);
      memcpy(request + CCID_FIDO_PREFIX + offset, data, length);
    }
  }
  return length;
}
#endif

static void expire_receive(void) {
  receive_error = SLOTERROR_BAD_DWLENGTH;
#if ENABLE_IFACE_CTAPHID
  ck_ccid_source_close();
#endif
  // A partial header has no reliable slot/sequence for an error response.
  phase = received < CCID_CMD_HEADER_SIZE ? CCID_IDLE : CCID_QUEUED;
}

// Header and ordinary short APDUs stay in request[]. Only a validated extended
// FIDO body can use PKE, and every call here runs in the main loop.
static void receive_packet(const uint8_t *data, uint8_t length, uint32_t tick) {
  if (phase == CCID_RECEIVING && tick - last_received >= CCID_RX_TIMEOUT_MS) {
    expire_receive();
    return;
  }
  if (phase == CCID_IDLE) {
    received = 0;
    expected = CCID_CMD_HEADER_SIZE;
    receive_error = 0;
#if ENABLE_IFACE_CTAPHID
    source_length = source_status = 0;
#endif
    phase = CCID_RECEIVING;
  }
  last_received = tick;
  while (length && received < expected) {
    uint32_t n = MIN((uint32_t)length, expected - received);
    if (received < CCID_CMD_HEADER_SIZE) {
      n = MIN(n, CCID_CMD_HEADER_SIZE - received);
      memcpy(request + received, data, n);
    } else if (!receive_error && expected <= sizeof(request)) {
      memcpy(request + received, data, n);
#if ENABLE_IFACE_CTAPHID
    } else if (!receive_error) {
      n = stage_fragment(data, n);
#endif
    }
    received += n;
    data += n;
    length -= n;
    if (received == CCID_CMD_HEADER_SIZE) {
      uint32_t payload = ccid_get_le32(request + CCID_LENGTH);
      expected = payload > UINT32_MAX - CCID_CMD_HEADER_SIZE ? UINT32_MAX : payload + CCID_CMD_HEADER_SIZE;
#if ENABLE_IFACE_CTAPHID
      uint32_t maximum = CK_CTAP_MAX_REQUEST + 9u;
#else
      uint32_t maximum = FRAME_CAPACITY;
#endif
      if (payload > maximum || (payload > FRAME_CAPACITY && request[CCID_MESSAGE_TYPE] != PC_TO_RDR_XFRBLOCK))
        receive_error = SLOTERROR_BAD_DWLENGTH;
    }
#if ENABLE_IFACE_CTAPHID
    if (received == CCID_FIDO_PREFIX && expected > sizeof(request) && !receive_error) begin_source();
#endif
  }
  if (length) receive_error = SLOTERROR_BAD_DWLENGTH;
#if ENABLE_IFACE_CTAPHID
  if (receive_error) ck_ccid_source_close();
#endif
  if (received == expected) phase = CCID_QUEUED;
}
void CCID_InFinished(uint8_t extension) {
  if (!extension) phase = CCID_IDLE;
}
#ifdef RUST_CORE_SERVICES
// Link timing only: never dispatch an APDU or reenter Rust from this callback.
static uint8_t send_time_extension(void) {
  static uint32_t last;
  static uint8_t extension[CCID_CMD_HEADER_SIZE];
  if (reset_pending || phase != CCID_RESPONDING) return 0;
  uint32_t now = device_get_tick();
  if (now - last >= CCID_EXTENSION_INTERVAL_MS) {
    last = now;
    extension[CCID_MESSAGE_TYPE] = RDR_TO_PC_DATABLOCK;
    extension[CCID_SLOT] = request[CCID_SLOT];
    extension[CCID_SEQUENCE] = request[CCID_SEQUENCE];
    extension[CCID_PARAMETER_0] = BM_COMMAND_STATUS_TIME_EXTN;
    extension[CCID_PARAMETER_1] = 1;
    CCID_Response_SendData(&usb_device, extension, sizeof(extension), 1);
  }
  return 1;
}
#if defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
// Crypto may run for many seconds without returning to the main loop. The
// timer handles only CCID link maintenance; no Rust or crypto state is touched.
void CCID_TimeExtensionLoop(void) {
  if (send_time_extension()) device_set_timeout(CCID_TimeExtensionLoop, CCID_EXTENSION_INTERVAL_MS);
}
#endif
uint8_t ck_ccid_progress(void) {
#if defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
  return !reset_pending && phase == CCID_RESPONDING;
#else
  return send_time_extension();
#endif
}
#endif
#if ENABLE_IFACE_CTAPHID
uint8_t ck_ccid_idle(void) {
  // A queued CCID packet cannot steal the native owner's unexpired lease.
  // CCID_Loop has not consumed it or acquired any request scratch yet.
  if (ck_hid_busy()) return 1;
  // Preserve CCID chains, response cursors and PIN grants during ordinary
  // multi-command use. Foreign HID may clean up an idle session after 2 s.
  return !reset_pending && !incoming_length && phase == CCID_IDLE &&
         (!session_owned || device_get_tick() - session_last_used >= 2000);
}
#endif
void CCID_Loop(void) {
  if (reset_pending) {
    // Block USB OUT while reset_pending is cleared and Rust resets its session.
    phase = CCID_RESPONDING;
#if ENABLE_IFACE_CTAPHID
    ck_ccid_source_close();
#endif
    ck_core_reset();
    active = 0;
#if ENABLE_IFACE_CTAPHID
    session_owned = 0;
#endif
    received = expected = 0;
    phase = CCID_IDLE;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    reset_pending = 0;
    USBD_CCID_ServiceReceive();
    return;
  }
#if ENABLE_IFACE_CTAPHID
  if (ck_hid_active()) return;
  if (ck_hid_busy() && ((phase != CCID_IDLE && request[CCID_MESSAGE_TYPE] == PC_TO_RDR_XFRBLOCK) ||
                        (phase == CCID_IDLE && incoming_length && incoming[0] == PC_TO_RDR_XFRBLOCK))) return;
#endif
  if (phase < CCID_QUEUED && incoming_length) {
    uint8_t length = incoming_length;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    uint32_t generation = epoch;
    // Keep the borrowed endpoint buffer NAKed throughout staging/validation.
    receive_packet(incoming, length, received_at);
    if (generation != epoch) return;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    incoming_length = 0;
    USBD_CCID_ServiceReceive();
  }
  if (phase == CCID_RECEIVING && device_get_tick() - last_received >= CCID_RX_TIMEOUT_MS && !incoming_length) {
    expire_receive();
  }
  if (phase != CCID_QUEUED) return;
  uint32_t generation = epoch;
  phase = CCID_RESPONDING;
  if (reset_pending) return;
  uint32_t payload = 0;
  uint8_t error = receive_error, type = RDR_TO_PC_SLOTSTATUS, specific = 0, unsupported = 0;
  uint8_t slot = request[CCID_SLOT], seq = request[CCID_SEQUENCE], command = request[CCID_MESSAGE_TYPE];
  if (command == PC_TO_RDR_XFRBLOCK || command == PC_TO_RDR_ICCPOWERON) type = RDR_TO_PC_DATABLOCK;
  if (slot) error = SLOTERROR_BAD_SLOT;
  if (!error) switch (command) {
    case PC_TO_RDR_ICCPOWERON:
      type = RDR_TO_PC_DATABLOCK;
      if (expected != CCID_CMD_HEADER_SIZE || request[CCID_PARAMETER_1] || request[CCID_PARAMETER_2]) {
        error = SLOTERROR_BAD_DWLENGTH;
        break;
      }
      if (request[CCID_PARAMETER_0]) {
        error = SLOTERROR_BAD_POWERSELECT;
        break;
      }
#if ENABLE_IFACE_CTAPHID
      // Slot discovery must remain responsive, but cannot reset the native
      // owner's authorization. Its first APDU will acquire core after the lease.
      session_owned = !ck_hid_busy();
      if (session_owned) ck_core_reset();
      session_last_used = device_get_tick();
#else
      ck_core_reset();
#endif
      active = 1;
      memcpy(response + CCID_CMD_HEADER_SIZE, atr, sizeof(atr));
      payload = sizeof(atr);
      break;
    case PC_TO_RDR_ICCPOWEROFF:
      if (expected != CCID_CMD_HEADER_SIZE) {
        error = SLOTERROR_BAD_DWLENGTH;
        break;
      }
#if ENABLE_IFACE_CTAPHID
      if (!ck_hid_busy()) ck_core_reset();
      session_owned = 0;
#else
      ck_core_reset();
#endif
      active = 0;
      break;
    case PC_TO_RDR_GETSLOTSTATUS:
      if (expected != CCID_CMD_HEADER_SIZE) error = SLOTERROR_BAD_DWLENGTH;
      break;
    case PC_TO_RDR_XFRBLOCK: {
      type = RDR_TO_PC_DATABLOCK;
      if (!active) {
        error = SLOTERROR_ICC_MUTE;
        break;
      }
      if (request[CCID_PARAMETER_1] || request[CCID_PARAMETER_2]) {
        error = SLOTERROR_BAD_LEVELPARAMETER;
        break;
      }
#if defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
      device_set_timeout(CCID_TimeExtensionLoop, CCID_EXTENSION_INTERVAL_MS);
#endif
      int32_t n;
#if ENABLE_IFACE_CTAPHID
      if (expected > sizeof(request)) {
        if (source_status) {
          response[CCID_CMD_HEADER_SIZE] = HI(source_status);
          response[CCID_CMD_HEADER_SIZE + 1] = LO(source_status);
          n = 2;
        } else {
          n = ck_core_exchange_ccid_source(expected - CCID_CMD_HEADER_SIZE, response + CCID_CMD_HEADER_SIZE,
                                           RESPONSE_CAPACITY);
        }
      } else
#endif
        n = ck_core_exchange(1, request + CCID_CMD_HEADER_SIZE, expected - CCID_CMD_HEADER_SIZE,
                             response + CCID_CMD_HEADER_SIZE, RESPONSE_CAPACITY);
#if defined(RUST_CORE_OPENPGP) || defined(RUST_CORE_PIV)
      device_set_timeout(NULL, 0);
#endif
#if ENABLE_IFACE_CTAPHID
      session_owned = 1;
      session_last_used = device_get_tick();
#endif
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
      static const uint8_t parameters[] = {0x11, 0x10, 0x00, 0x15, 0x00, 0xfe, 0x00};
      type = RDR_TO_PC_PARAMETERS;
      specific = CCID_PROTOCOL_T1;
      if (command == PC_TO_RDR_SETPARAMETERS &&
          (request[CCID_PARAMETER_0] != CCID_PROTOCOL_T1 || expected != CCID_CMD_HEADER_SIZE + sizeof(parameters))) {
        error = SLOTERROR_BAD_PROTOCOLNUM;
        break;
      }
      memcpy(response + CCID_CMD_HEADER_SIZE, parameters, sizeof(parameters));
      payload = sizeof(parameters);
      break;
    }
    default:
      // CMD_NOT_SUPPORTED is zero; keep failure status separate from bError.
      unsupported = 1;
      error = SLOTERROR_CMD_NOT_SUPPORTED;
      break;
    }
#if ENABLE_IFACE_CTAPHID
  ck_ccid_source_close();
#endif
  response[CCID_MESSAGE_TYPE] = type;
  ccid_put_le32(response + CCID_LENGTH, payload);
  response[CCID_SLOT] = slot;
  response[CCID_SEQUENCE] = seq;
  response[CCID_PARAMETER_0] = (active ? BM_ICC_PRESENT_ACTIVE : BM_ICC_PRESENT_INACTIVE);
  if (error || unsupported) response[CCID_PARAMETER_0] |= BM_COMMAND_STATUS_FAILED;
  response[CCID_PARAMETER_1] = error;
  response[CCID_PARAMETER_2] = specific;
  // A USB reset during Rust execution invalidates this transfer. The next loop
  // clears the Rust session before accepting a command from the new connection.
  if (generation != epoch) return;
  if (CCID_Response_SendData(&usb_device, response, (uint16_t)(payload + CCID_CMD_HEADER_SIZE), 0) != USBD_OK)
    phase = CCID_IDLE;
}
