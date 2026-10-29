// SPDX-License-Identifier: Apache-2.0
#include "nfc.h"

#if ENABLE_NFC

#include "apdu.h"
#include "device.h"
#include "pke.h"
#include "ctap.h"

#if NFC_CHIP == NFC_CHIP_NA

void nfc_init(void) {}
void nfc_loop(void) {}
void nfc_handler(void) {}

#else

#define WTX_PERIOD 150
#define WTX_LOCK_RETRY_PERIOD 1
#define NFC_RECOVERY_PERIOD 200
#define NFC_RUNTIME_IRQ_MASK (MAIN_IRQ_FIFO | MAIN_IRQ_RX_START)
enum { NFC_RECOVERY_NONE, NFC_RECOVERY_REQUESTED, NFC_RECOVERY_SILENCED, NFC_RECOVERY_UNSILENCE };

enum { NFC_SEND_FAILED = -1, NFC_SEND_ABORTED = -2, NFC_MAX_RETRANSMITS = 2 };

static volatile uint32_t state_spinlock;
static volatile enum { TO_RECEIVE, TO_SEND } next_state;
static uint8_t block_number, rx_frame_size, rx_frame_buf[32];
static uint8_t retransmit_prologue, retransmit_data[29];
static struct {
  uint16_t size, sent;
  uint8_t sending, retries, cached_len;
  // RX and TX never overlap. Reuse the byte once the request is complete.
  union { uint8_t aggregate, rx_mode; };
} tx_state;
static volatile uint8_t cleanup_pending;
static uint32_t apdu_buffer_rx_size;
// RX envelope state is separate from the ownership flag in CAPDU.
enum { RX_INLINE, RX_PKE, RX_DISCARD, RX_MALFORMED };
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static volatile uint8_t apdu_processing;
static volatile uint8_t idle_recovery_state;
static volatile uint8_t idle_recovery_forced;
static volatile uint8_t irq_config_pending;

static void send_wtx(void);
static void request_idle_recovery(void);
static void request_unsilence(void);

static void restart_idle_timeout(void) {
  idle_recovery_state = NFC_RECOVERY_NONE;
  device_set_timeout(request_idle_recovery, NFC_RECOVERY_PERIOD);
}

static void reset_tx_state(void) {
  memset(&tx_state, 0, sizeof(tx_state));
  retransmit_prologue = 0; // invalid: all supported block types have bit1 set
}

static void reset_nfc_state(void) {
  block_number = 1;
  apdu_buffer_rx_size = 0;
  reset_tx_state();
  next_state = TO_RECEIVE;
}

static void stop_apdu_wtx(void) {
  apdu_processing = 0;
  device_set_timeout(NULL, 0);
}

static void reset_nfc_session(void) {
  cleanup_pending = 1; // latch cancellation until synchronous command work has unwound
  device_set_timeout(NULL, 0);
  reset_nfc_state();
  // Only the main loop may close PKE/response sources.
}

static void close_rx_request(void *ctx) {
  UNUSED(ctx);
  if (apdu_cmd.pke_backed != 1) return;
  apdu_cmd.pke_backed = 0; // idempotent, and never clear a later crypto owner's registers
  pke_buffer_clear();
  pke_buffer_release(PKE_BUFFER_OWNER_CTAP);
}

// Cancellation stays latched until main-loop cleanup; repeated RF events
// cannot wrap a generation counter and accidentally revive an old command.
static int rx_cancelled(void *ctx) { UNUSED(ctx); return cleanup_pending; }

static int process_nfc_apdu(CAPDU *cmd, RAPDU *rapdu) {
  if (cleanup_pending) return -1;
  const apdu_request_source_t source = {
      .read = apdu_request_read_pke, .cancelled = rx_cancelled, .close = close_rx_request,
      .len = cmd->lc};
  apdu_processing = 1;
  device_set_timeout(send_wtx, WTX_PERIOD);
  process_apdu_source_from(cmd, rapdu, APDU_TRANSPORT_NFC, cmd->pke_backed == 1 ? &source : NULL);
  stop_apdu_wtx();
  if (cleanup_pending) return -1;
  restart_idle_timeout();
  return 0;
}

// Keep only the envelope in shared memory; CTAP consumes PKE before crypto.
// Rejections still drain legal I-blocks through the final block. A malformed
// APDU is an ISO status, not a reason to tear down the RF activation.
static int append_rx(const uint8_t *data, size_t len) {
  if (len > UINT32_MAX - apdu_buffer_rx_size) return -1;
  while (len) {
    const uint32_t pos = apdu_buffer_rx_size;
    // Seven bytes alone are Case 2E (Le, not Lc). Do not start staging until
    // a body byte arrives, even when the header spans multiple I-blocks.
    if (pos == 7 && tx_state.rx_mode == RX_INLINE) {
      if (!((shared_io_buffer[0] == 0 || shared_io_buffer[0] == 0x80) && shared_io_buffer[1] == 0xC0)) {
        // Close an abandoned generator before new RX staging can touch PKE.
        apdu_response_source_clear();
        apdu_rapdu_chain_reset();
      }
      if (shared_io_buffer[4] == 0) {
        const uint16_t lc = ((uint16_t)shared_io_buffer[5] << 8) | shared_io_buffer[6];
        if (lc > APDU_COMMAND_BUFFER_SIZE - 9) {
          memcpy(&apdu_cmd.cla, shared_io_buffer, 4);
          apdu_cmd.lc = lc;
          apdu_cmd.extended = 1;
          tx_state.rx_mode = RX_DISCARD;
          apdu_resp.sw = SW_WRONG_LENGTH;
          if (apdu_cmd.cla == 0x80 && apdu_cmd.ins == CTAP_INS_MSG) {
            apdu_resp.sw = SW_FILE_NOT_FOUND;
            if (apdu_fido_selected()) {
              // Abandon old command chaining before acquiring the new RX staging.
              apdu_fido_chain_reset();
              apdu_resp.sw = SW_WRONG_P1P2;
              if (!(apdu_cmd.p1 & 0x7F) && !apdu_cmd.p2) {
                apdu_resp.sw = SW_NO_ERROR;
                if (lc <= CTAP_MAX_REQUEST_SIZE) {
                  apdu_resp.sw = SW_UNABLE_TO_PROCESS;
                  if (pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP) == 0) {
                    apdu_cmd.pke_backed = 1;
                    tx_state.rx_mode = RX_PKE;
                  }
                }
              }
            }
          }
        }
      }
    }
    size_t n;
    if (tx_state.rx_mode == RX_MALFORMED) {
      n = len;
    } else if (tx_state.rx_mode != RX_INLINE) {
      const uint32_t end = 7u + apdu_cmd.lc;
      if (pos < end) {
        n = MIN(len, end - pos);
        if (tx_state.rx_mode == RX_PKE && pke_buffer_write(pos - 7, data, n) < 0) {
          close_rx_request(NULL);
          tx_state.rx_mode = RX_DISCARD;
          apdu_resp.sw = SW_UNABLE_TO_PROCESS;
        }
      } else {
        if (pos >= end + 2) {
          tx_state.rx_mode = RX_MALFORMED;
          continue;
        }
        n = MIN(len, end + 2 - pos);
        memcpy(shared_io_buffer + pos - end, data, n);
      }
    } else {
      const uint32_t end = pos < 7 ? 7 : APDU_COMMAND_BUFFER_SIZE;
      if (pos >= end) {
        tx_state.rx_mode = RX_MALFORMED;
        continue;
      }
      n = MIN(len, end - pos);
      memcpy(shared_io_buffer + pos, data, n);
    }
    apdu_buffer_rx_size += n;
    data += n;
    len -= n;
  }
  return 0;
}

// Hide internal short-buffer chunking only within this command's Le budget.
static void prepare_tx(RAPDU *rapdu) {
  tx_state.sent = 0;
  apdu_cmd.le -= MIN(apdu_cmd.le, rapdu->len);
  tx_state.aggregate = apdu_cmd.extended && apdu_cmd.le && HI(rapdu->sw) == 0x61;
  tx_state.size = rapdu->len;
  if (!tx_state.aggregate) {
    shared_io_buffer[tx_state.size++] = HI(rapdu->sw);
    shared_io_buffer[tx_state.size++] = LO(rapdu->sw);
  }
}

static int load_next_aggregated_chunk(void) {
  CAPDU capdu = {
      .data = shared_io_buffer, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .le = MIN(apdu_cmd.le, 0x100u), .lc = 0, .extended = 0};
  RAPDU rapdu = {.data = shared_io_buffer};

  if (process_nfc_apdu(&capdu, &rapdu) < 0) return NFC_SEND_ABORTED;

  prepare_tx(&rapdu);
  return tx_state.aggregate;
}

void nfc_init(void) {
  reset_nfc_state();
  cleanup_pending = 0;
  tx_state.rx_mode = RX_INLINE;
  apdu_cmd.pke_backed = 0;
  // NFC interface uses shared_io_buffer w/o calling acquire_apdu_buffer(), because NFC mode is exclusive with USB mode
  apdu_cmd.data = shared_io_buffer;
  apdu_resp.data = shared_io_buffer;
  // FM11NT may already hold the reader's first frame by the time platform initialization
  // finishes, so the FIFO is deliberately not flushed here.
  idle_recovery_forced = 0;
  const uint8_t irq_mask = NFC_RUNTIME_IRQ_MASK;
  irq_config_pending = fm_write_regs(FM_REG_MAIN_IRQ_MASK, &irq_mask, 1) != FM_STATUS_OK;
  if (irq_config_pending) ERR_MSG("Failed to update FM11NT IRQ mask\n");
  restart_idle_timeout();
}

static void nfc_error_handler(int code __attribute__((unused))) {
  DBG_MSG("NFC Error %d\n", code);
  reset_nfc_session();
  idle_recovery_forced = 1; // errors always escalate to an RF-silence recovery
  idle_recovery_state = NFC_RECOVERY_REQUESTED;
}

static void request_idle_recovery(void) {
  idle_recovery_state = NFC_RECOVERY_REQUESTED;
}

static void request_unsilence(void) {
  idle_recovery_state = NFC_RECOVERY_UNSILENCE;
}

static int do_nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  if (len > 29) return -1;

  uint8_t tx_frame_buf[30];
  tx_frame_buf[0] = prologue;
  if (data != NULL) memcpy(tx_frame_buf + 1, data, len);

  if (fm_write_fifo(tx_frame_buf, len + 1) != FM_STATUS_OK) return -1;
  if (cleanup_pending) return NFC_SEND_ABORTED;
  // Rule 11 retries the last transmitted block, including R(ACK)/S(WTX),
  // not merely the last I-block from an earlier APDU. The local frame also
  // avoids aliasing when the retransmit cache itself is the input.
  retransmit_prologue = prologue;
  tx_state.cached_len = len;
  memcpy(retransmit_data, tx_frame_buf + 1, len);
  // Consume this turn just before TXEN: i2c_stop() can unmask a GPIO IRQ
  // carrying the reader's next frame before the register write returns.
  // Never overwrite that IRQ's newly published TO_SEND afterwards.
  next_state = TO_RECEIVE;
  const uint8_t val = 0x55;
  if (fm_write_regs(FM_REG_RF_TXEN, &val, 1) != FM_STATUS_OK) return -1;
  return 0;
}

static int nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  for (;;) {
    if (cleanup_pending) return NFC_SEND_ABORTED;
    if (device_spinlock_lock(&state_spinlock, true) != 0) return -1;
    if (next_state == TO_SEND) {
      const int ret = !cleanup_pending ? do_nfc_send_frame(prologue, data, len) : NFC_SEND_ABORTED;
      device_spinlock_unlock(&state_spinlock);
      return ret;
    }
    device_spinlock_unlock(&state_spinlock);
  }
}

static int send_apdu_buffer(uint8_t resend) {
  if (resend) {
    if (retransmit_prologue == 0 || tx_state.retries >= NFC_MAX_RETRANSMITS) return NFC_SEND_FAILED;
    ++tx_state.retries;
    return nfc_send_frame(retransmit_prologue, retransmit_data, tx_state.cached_len);
  }

  if (tx_state.aggregate && tx_state.sent == tx_state.size) {
    const int more = load_next_aggregated_chunk();
    if (more < 0) return more;
    tx_state.aggregate = (uint8_t)more;
  }

  uint8_t send_len = (uint8_t)MIN(tx_state.size - tx_state.sent, 29);
  if (send_len == 0) return -1;
  uint8_t prologue = block_number | 0x02;
  if (tx_state.size - tx_state.sent > send_len || tx_state.aggregate) prologue |= PCB_I_CHAINING;
  const int ret = nfc_send_frame(prologue, shared_io_buffer + tx_state.sent, send_len);
  if (ret < 0) return ret;
  tx_state.sent += send_len;
  tx_state.retries = 0;
  if (tx_state.size == tx_state.sent && !tx_state.aggregate) {
    tx_state.sending = 0;
  }
  return 0;
}

static void send_wtx(void) {
  if (!apdu_processing || cleanup_pending) return;

  int send_failed = 0;
  if (device_spinlock_lock(&state_spinlock, false) != 0) {
    if (apdu_processing && !cleanup_pending) device_set_timeout(send_wtx, WTX_LOCK_RETRY_PERIOD);
    return;
  }
  if (next_state == TO_SEND) {
    uint8_t wtxm = 1;
    tx_state.retries = 0;
    if (do_nfc_send_frame(S_WTX, &wtxm, 1) != 0 && !cleanup_pending)
      send_failed = 1;
  }
  device_spinlock_unlock(&state_spinlock);

  if (send_failed) {
    nfc_error_handler(-19);
    return;
  }
  if (apdu_processing) device_set_timeout(send_wtx, WTX_PERIOD);
}

void nfc_loop(void) {
  if (apdu_processing) return; // never reclaim sources underneath a reentrant command
  if (cleanup_pending) {
    cleanup_pending = 0;
    close_rx_request(NULL);
    apdu_cmd.pke_backed = 0;
    apdu_buffer_rx_size = 0;
    tx_state.rx_mode = RX_INLINE;
    // An IRQ can interrupt FIFO writes; discard any TX bookkeeping written
    // by that old call after the IRQ reset, while retaining a new RX frame.
    reset_tx_state();
    device_applet_context_reset();
    if (cleanup_pending) return; // another RF reset interrupted cleanup
  }
  if (idle_recovery_state != NFC_RECOVERY_NONE) {
    if (idle_recovery_state == NFC_RECOVERY_REQUESTED) {
      // A transport error or a stale in-flight session counts as dirty; a session that completed
      // cleanly must keep its block-number/retransmit state, because the reader may still hold
      // the same ISO-DEP activation and neither a reset nor an RF silence would be RF-invisible.
      const uint8_t dirty = idle_recovery_forced || next_state == TO_SEND || apdu_buffer_rx_size != 0 || tx_state.sending;
      if (!dirty) {
        idle_recovery_state = NFC_RECOVERY_NONE;
        restart_idle_timeout();
        return;
      }
      // Latch the recovery as forced before touching session state: an IRQ landing anywhere
      // inside this sequence is then drained in nfc_handler() instead of being handled as
      // normal activity and leaving a stale frame behind. The latch also makes an I2C NACK
      // retry the full silence sequence instead of falling into the clean path once
      // reset_nfc_session() has cleared the dirty flags.
      idle_recovery_forced = 1;
      reset_nfc_session();
      const uint8_t silence = 0x33;
      if (fm_write_regs(FM_REG_RESET_SILENCE, &silence, 1) != FM_STATUS_OK) return; // stay REQUESTED, keep forced
      // Enter SILENCED before releasing the latch so no IRQ can observe the not-forced
      // REQUESTED state and cancel the recovery.
      idle_recovery_state = NFC_RECOVERY_SILENCED;
      idle_recovery_forced = 0; // one-shot: cleared only once the silence actually took effect
      // Mask FM11NT interrupts at the chip for the silent period: the level GPIO IRQ then
      // cannot storm the CPU, and no IRQ flag needs in-ISR draining. The mask is restored
      // via irq_config_pending after the unsilence. Best-effort: if this write fails, the
      // drain fallback in nfc_handler() still covers the interrupt source.
      const uint8_t irq_off = 0xFF; // FM11NT masks are active-high.
      fm_write_regs(FM_REG_MAIN_IRQ_MASK, &irq_off, 1);
      // Keep the RF interface silent long enough for the reader to observe card removal.
      // TIM1 is free here: reset_nfc_session() stopped the APDU processing and its WTX timer.
      device_set_timeout(request_unsilence, NFC_RECOVERY_PERIOD);
      return;
    }
    if (idle_recovery_state == NFC_RECOVERY_UNSILENCE) {
      const uint8_t unsilence = 0xCC;
      if (fm_write_regs(FM_REG_RESET_SILENCE, &unsilence, 1) != FM_STATUS_OK) return; // stay UNSILENCE, retry
      irq_config_pending = 1;
      restart_idle_timeout();
      return;
    }
    return; // NFC_RECOVERY_SILENCED: wait for the unsilence timer
  }
  if (irq_config_pending) {
    const uint8_t irq_mask = NFC_RUNTIME_IRQ_MASK;
    if (fm_write_regs(FM_REG_MAIN_IRQ_MASK, &irq_mask, 1) == FM_STATUS_OK) irq_config_pending = 0;
    if (irq_config_pending) return;
  }
  if (next_state == TO_RECEIVE) return;

  if ((rx_frame_buf[0] & PCB_MASK) == PCB_I_BLOCK) {
    if (rx_frame_size < 3 || (rx_frame_buf[0] & 0xEE) != 0x02) { // no CID/NAD/RFU bits
      nfc_error_handler(-6);
      return;
    }
    if (tx_state.sending) {
      nfc_error_handler(-22);
      return;
    }
    // A repeated chained I-block must not append its payload a second time.
    if ((rx_frame_buf[0] & 1) == block_number) goto acknowledge;
    block_number ^= 1;

    const int received = append_rx(rx_frame_buf + 1, rx_frame_size - 3);
    if (received < 0) {
      nfc_error_handler(-3);
      return;
    }
    if (cleanup_pending) return;

    if (rx_frame_buf[0] & PCB_I_CHAINING) {
      tx_state.retries = 0;
      if (nfc_send_frame(R_ACK | block_number, NULL, 0) == NFC_SEND_FAILED) nfc_error_handler(-11);
      return;
    }
    {
      CAPDU *capdu = &apdu_cmd;
      RAPDU *rapdu = &apdu_resp;

      int malformed = tx_state.rx_mode == RX_MALFORMED;
      if (tx_state.rx_mode == RX_PKE || tx_state.rx_mode == RX_DISCARD) {
        const uint32_t end = 7u + capdu->lc;
        malformed = apdu_buffer_rx_size != end && apdu_buffer_rx_size != end + 2;
        capdu->le = 0x10000;
        if (apdu_buffer_rx_size == end + 2) {
          const uint16_t le = ((uint16_t)shared_io_buffer[0] << 8) | shared_io_buffer[1];
          if (le) capdu->le = le;
        }
      } else if (!malformed) {
        malformed = build_capdu(capdu, shared_io_buffer, apdu_buffer_rx_size) < 0;
      }
      LL = 0;
      if (malformed) {
        close_rx_request(NULL);
        apdu_fido_chain_reset();
        apdu_response_source_clear();
        apdu_rapdu_chain_reset();
        SW = SW_WRONG_LENGTH;
      } else if (tx_state.rx_mode != RX_DISCARD) {
        CAPDU command = *capdu; // dispatch clamps Le; preserve the NFC response budget
        if (process_nfc_apdu(&command, rapdu) < 0) return;
      }
      if (!malformed && tx_state.rx_mode == RX_DISCARD && SW == SW_NO_ERROR) {
        shared_io_buffer[0] = 0x39; // CTAP2_ERR_REQUEST_TOO_LARGE
        LL = 1;
      }
      capdu->pke_backed = 0;
      tx_state.rx_mode = RX_INLINE;
      // Only FIDO's extended responses hide internal GET RESPONSE chunks.
      capdu->extended = capdu->extended && apdu_fido_selected();
      prepare_tx(rapdu);
      apdu_buffer_rx_size = 0;
      tx_state.sent = 0;
      tx_state.sending = 1;
      if (send_apdu_buffer(0) == NFC_SEND_FAILED) nfc_error_handler(-12);
    }
  } else if ((rx_frame_buf[0] & PCB_MASK) == PCB_R_BLOCK) {
    if (rx_frame_size != 3 || (rx_frame_buf[0] & 0xEE) != R_ACK) {
      nfc_error_handler(-6);
      return;
    }
    if ((rx_frame_buf[0] & R_BLOCK_MASK) == R_ACK) {
      if ((rx_frame_buf[0] & 1) != block_number) { // continue chaining
        // Rule 13: an ACK advances only an outgoing response chain. Ignore
        // unsolicited ACKs without resetting selection or an incoming APDU.
        if (!tx_state.sending) {
          next_state = TO_RECEIVE;
          return;
        }
        block_number ^= 1;
        if (send_apdu_buffer(0) == NFC_SEND_FAILED) nfc_error_handler(-13);
      } else { // re-send
        if (send_apdu_buffer(1) == NFC_SEND_FAILED) nfc_error_handler(-14);
      }
    } else {
      if ((rx_frame_buf[0] & 1) != block_number) {
        // Rule 12: a different-BN R(NAK) requests R(ACK), even while
        // sending a chained response. It never consumes response bytes.
        goto acknowledge;
      } else { // re-send
        if (send_apdu_buffer(1) == NFC_SEND_FAILED) nfc_error_handler(-17);
      }
    }
  } else {
    // S-Block
  }
  return;
acknowledge:
  tx_state.retries = 0;
  if (nfc_send_frame(R_ACK | block_number, NULL, 0) == NFC_SEND_FAILED) nfc_error_handler(-11);
}

void nfc_handler(void) {
  uint8_t irq[3];
  // A forced (error-triggered) recovery must not be delayed or cancelled by IRQ-side session
  // resets, so it is guarded as well; a plain idle-timer REQUESTED still lets normal activity
  // cancel the recovery.
  if (idle_recovery_state == NFC_RECOVERY_SILENCED || idle_recovery_state == NFC_RECOVERY_UNSILENCE ||
      (idle_recovery_state == NFC_RECOVERY_REQUESTED && idle_recovery_forced)) {
    // Fallback for a failed FFFA mask write: the GPIO IRQ is level-triggered and the HAL clears
    // only the GPIO latch, not the FM11NT interrupt source. Drain the source without acting on
    // it, so a still-asserted INT line can neither storm the CPU nor cancel the recovery.
    fm_read_regs(FM_REG_MAIN_IRQ, irq, sizeof(irq));
    return;
  }
  if (fm_read_regs(FM_REG_MAIN_IRQ, irq, sizeof(irq)) != FM_STATUS_OK) {
    nfc_error_handler(-8);
    return;
  }
  if (!is_nfc()) {
    ERR_MSG("IRQ %02x in non-NFC mode\n", irq[0]);
    return;
  }

  if (irq[2] & AUX_IRQ_ERROR_MASK) {
    DBG_MSG("AUX: %02X\n", irq[2]);
    nfc_error_handler(-1);
    return;
  }
  if (irq[1] & FIFO_IRQ_OVERFLOW) {
    nfc_error_handler(-20);
    return;
  }
  if (irq[2] & AUX_IRQ_HALT) {
    // HALT and a later activation can both latch while the RF-powered MCU
    // boots. Use live NFC_STATE (FM11NT082C section 3.3.3.12), not IRQ
    // priority, to avoid discarding RX_DONE from the new activation.
    uint8_t rf_status = 0;
    if ((irq[0] & MAIN_IRQ_ACTIVE) &&
        fm_read_regs(FM_REG_RF_STATUS, &rf_status, 1) != FM_STATUS_OK) {
      nfc_error_handler(-23);
      return;
    }
    const uint8_t rf_state = rf_status >> 4;
    if (rf_state != 9 && rf_state != 10) { // not after RATS/PPS
      idle_recovery_state = NFC_RECOVERY_NONE;
      reset_nfc_session();
      return;
    }
  }
  if (irq[0] & MAIN_IRQ_ACTIVE) {
    reset_nfc_session();
    restart_idle_timeout();
  } else if ((irq[0] & 0x3F) && !apdu_processing) {
    restart_idle_timeout();
  }
  if (irq[0] & MAIN_IRQ_RX_DONE) {
    uint8_t frame_size, frame[sizeof(rx_frame_buf)];
    if (fm_read_regs(FM_REG_FIFO_WORDCNT, &frame_size, 1) != FM_STATUS_OK) {
      nfc_error_handler(-9);
      return;
    }
    if (frame_size == 0) {
      nfc_error_handler(-21);
      return;
    } else if (frame_size > sizeof(frame)) {
      nfc_error_handler(-5);
      return;
    } else if (fm_read_fifo(frame, frame_size) != FM_STATUS_OK) {
      nfc_error_handler(-10);
      return;
    } else {
      // The main loop may still be appending this frame to PKE. Drain a
      // reader retry/presence check without changing its bytes or length.
      if (next_state == TO_SEND) {
        return;
      }
      memcpy(rx_frame_buf, frame, frame_size);
      rx_frame_size = frame_size;
      next_state = TO_SEND;
    }
  }
}

#endif // NFC_CHIP != NFC_CHIP_NA

#endif // ENABLE_NFC
