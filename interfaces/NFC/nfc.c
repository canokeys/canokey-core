// SPDX-License-Identifier: Apache-2.0
#include "nfc.h"

#if ENABLE_NFC

#include "apdu.h"
#include "device.h"

#if NFC_CHIP == NFC_CHIP_NA

void nfc_init(void) {}
void nfc_loop(void) {}
void nfc_handler(void) {}

#else

#define WTX_PERIOD 150
#define WTX_LOCK_RETRY_PERIOD 1

enum { NFC_SEND_FAILED = -1, NFC_SEND_ABORTED = -2, NFC_MAX_RETRANSMITS = 2 };

static volatile uint32_t state_spinlock;
static volatile enum { TO_RECEIVE, TO_SEND } next_state;
static uint8_t block_number, rx_frame_size, rx_frame_buf[32], tx_frame_buf[32];
static uint8_t inf_sending, retransmit_count;
static uint8_t aggregate_get_response, aggregate_fido_responses;
static uint16_t apdu_buffer_rx_size, apdu_buffer_tx_size;
static uint16_t apdu_buffer_sent, last_sent;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static volatile uint8_t apdu_processing;
static volatile uint8_t apdu_transport_failed;
static volatile uint8_t session_generation;
#if NFC_CHIP == NFC_CHIP_FM11NT
static volatile uint8_t fast_recovery_pending;
static volatile uint8_t irq_config_pending;
#endif

static void send_wtx(void);

static void reset_nfc_state(void) {
  block_number = 1;
  apdu_buffer_rx_size = 0;
  apdu_buffer_tx_size = 0;
  apdu_buffer_sent = 0;
  last_sent = 0;
  inf_sending = 0;
  retransmit_count = 0;
  aggregate_get_response = 0;
  next_state = TO_RECEIVE;
}

static void stop_apdu_wtx(void) {
  apdu_processing = 0;
  device_set_timeout(NULL, 0);
}

#if NFC_CHIP == NFC_CHIP_FM11NT
static void reset_nfc_session(void) {
  ++session_generation;
  if (apdu_processing) apdu_transport_failed = 1;
  stop_apdu_wtx();
  reset_nfc_state();
  aggregate_fido_responses = 0;
  fast_recovery_pending = 0;
}

#endif

static int process_nfc_apdu(CAPDU *capdu, RAPDU *rapdu) {
  apdu_transport_failed = 0;
  apdu_processing = 1;
  device_set_timeout(send_wtx, WTX_PERIOD);
  process_apdu_from(capdu, rapdu, APDU_TRANSPORT_NFC);
  stop_apdu_wtx();
  return apdu_transport_failed ? -1 : 0;
}

static void update_fido_response_mode(const uint8_t *cmd, uint16_t len) {
  static const uint8_t fido_aid[] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};

  if (len < 5 || cmd[0] != 0x00 || cmd[1] != 0xA4 || cmd[2] != 0x04 || cmd[3] != 0x00) return;

  const uint16_t aid_end = 5 + cmd[4];
  aggregate_fido_responses = cmd[4] == sizeof(fido_aid) && len >= aid_end &&
                             memcmp(cmd + 5, fido_aid, sizeof(fido_aid)) == 0 && len == aid_end;
}

static int load_next_aggregated_chunk(void) {
  CAPDU capdu = {
      .data = shared_io_buffer, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .le = 0x100, .lc = 0, .extended = 0};
  RAPDU rapdu = {.data = shared_io_buffer};

  if (process_nfc_apdu(&capdu, &rapdu) < 0) return NFC_SEND_ABORTED;

  apdu_buffer_sent = 0;
  if (HI(rapdu.sw) == 0x61) {
    apdu_buffer_tx_size = rapdu.len;
    return 1;
  }

  shared_io_buffer[rapdu.len] = HI(rapdu.sw);
  shared_io_buffer[rapdu.len + 1] = LO(rapdu.sw);
  apdu_buffer_tx_size = rapdu.len + 2;
  return 0;
}

__attribute__((minsize)) void nfc_init(void) {
  reset_nfc_state();
  aggregate_fido_responses = 0;
  // NFC interface uses shared_io_buffer w/o calling acquire_apdu_buffer(), because NFC mode is exclusive with USB mode
  apdu_cmd.data = shared_io_buffer;
  apdu_resp.data = shared_io_buffer;
#if NFC_CHIP != NFC_CHIP_FM11NT
  // FM11NT may already hold the reader's first frame by the time platform initialization finishes.
  fm_write_regs(FM_REG_FIFO_FLUSH, &block_number, 1); // writing anything to this reg will flush FIFO buffer
#else
  const uint8_t irq_mask = MAIN_IRQ_FIFO | MAIN_IRQ_RX_START;
  irq_config_pending = fm_write_regs(FM_REG_MAIN_IRQ_MASK, &irq_mask, 1) != FM_STATUS_OK;
  if (irq_config_pending) ERR_MSG("Failed to update FM11NT IRQ mask\n");
#endif
}

__attribute__((minsize)) static void nfc_error_handler(int code __attribute__((unused))) {
  DBG_MSG("NFC Error %d\n", code);
  ++session_generation;
  if (apdu_processing) apdu_transport_failed = 1;
  stop_apdu_wtx();
  reset_nfc_state();
#if NFC_CHIP == NFC_CHIP_FM11NT
  if (!fast_recovery_pending) {
    uint8_t data = 0x77;
    if (fm_write_regs(FM_REG_FIFO_FLUSH, &data, 1) == FM_STATUS_OK &&
        fm_write_regs(FM_REG_RF_TXEN, &data, 1) == FM_STATUS_OK) {
      fast_recovery_pending = 1;
      return;
    }
  }

  uint8_t data = 0x55;
  fm_write_regs(FM_REG_RESET_SILENCE, &data, 1);
  fast_recovery_pending = 1;
  irq_config_pending = 1;
#else
  fm_write_regs(FM_REG_FIFO_FLUSH, &block_number, 1);
#endif
}

static int do_nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  if (len > 29) return -1;

  tx_frame_buf[0] = prologue;
  if (data != NULL) memcpy(tx_frame_buf + 1, data, len);

  DBG_MSG("TX: ");
  PRINT_HEX(tx_frame_buf, len + 1);

  if (fm_write_fifo(tx_frame_buf, len + 1) != FM_STATUS_OK) return -1;
  const uint8_t val = 0x55;
  if (fm_write_regs(FM_REG_RF_TXEN, &val, 1) != FM_STATUS_OK) return -1;
  return 0;
}

__attribute__((minsize)) static int nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  const uint8_t generation = session_generation;
  for (;;) {
    if (generation != session_generation) return NFC_SEND_ABORTED;
    if (device_spinlock_lock(&state_spinlock, true) != 0) return -1;
    if (next_state == TO_SEND) {
      const int ret = generation == session_generation ? do_nfc_send_frame(prologue, data, len) : NFC_SEND_ABORTED;
      if (ret == 0) next_state = TO_RECEIVE;
      device_spinlock_unlock(&state_spinlock);
      return ret;
    }
    device_spinlock_unlock(&state_spinlock);
  }
}

static int send_apdu_buffer(uint8_t resend) {
  if (resend) {
    if (last_sent == 0 || retransmit_count >= NFC_MAX_RETRANSMITS) return NFC_SEND_FAILED;
    ++retransmit_count;
    return nfc_send_frame(tx_frame_buf[0], NULL, last_sent);
  }

  if (aggregate_get_response && apdu_buffer_sent == apdu_buffer_tx_size) {
    const int more = load_next_aggregated_chunk();
    if (more < 0) return more;
    aggregate_get_response = (uint8_t)more;
  }

  last_sent = apdu_buffer_tx_size - apdu_buffer_sent;
  if (last_sent == 0) return -1;
  if (last_sent > 29) last_sent = 29;
  uint8_t prologue = block_number | 0x02;
  if (apdu_buffer_tx_size - apdu_buffer_sent > last_sent || aggregate_get_response) prologue |= PCB_I_CHAINING;
  const int ret = nfc_send_frame(prologue, shared_io_buffer + apdu_buffer_sent, last_sent);
  if (ret < 0) return ret;
  apdu_buffer_sent += last_sent;
  retransmit_count = 0;
  if (apdu_buffer_tx_size == apdu_buffer_sent && !aggregate_get_response) inf_sending = 0;
  return 0;
}

static void send_wtx(void) {
  if (!apdu_processing || apdu_transport_failed) return;

  int send_failed = 0;
  if (device_spinlock_lock(&state_spinlock, false) != 0) {
    if (apdu_processing && !apdu_transport_failed) device_set_timeout(send_wtx, WTX_LOCK_RETRY_PERIOD);
    return;
  }
  if (next_state == TO_SEND) {
    uint8_t wtxm = 1;
    if (do_nfc_send_frame(S_WTX, &wtxm, 1) == 0)
      next_state = TO_RECEIVE;
    else
      send_failed = 1;
  }
  device_spinlock_unlock(&state_spinlock);

  if (send_failed) {
    nfc_error_handler(-19);
    return;
  }
  if (apdu_processing) device_set_timeout(send_wtx, WTX_PERIOD);
}

__attribute__((minsize)) void nfc_loop(void) {
#if NFC_CHIP == NFC_CHIP_FM11NT
  if (irq_config_pending) {
    const uint8_t irq_mask = MAIN_IRQ_FIFO | MAIN_IRQ_RX_START;
    if (fm_write_regs(FM_REG_MAIN_IRQ_MASK, &irq_mask, 1) == FM_STATUS_OK) irq_config_pending = 0;
    if (irq_config_pending) return;
  }
#endif
  if (next_state == TO_RECEIVE) return;

  if ((rx_frame_buf[0] & PCB_MASK) == PCB_I_BLOCK) {
    if (inf_sending) {
      nfc_error_handler(-22);
      return;
    }
    block_number ^= 1;

    if (rx_frame_size < 3) {
      nfc_error_handler(-6);
      return;
    }
    const uint16_t payload_len = rx_frame_size - 3;
    if (apdu_buffer_rx_size + payload_len > APDU_COMMAND_BUFFER_SIZE) {
      nfc_error_handler(-3);
      return;
    }
    memcpy(shared_io_buffer + apdu_buffer_rx_size, rx_frame_buf + 1, payload_len);
    apdu_buffer_rx_size += payload_len;

    if (rx_frame_buf[0] & PCB_I_CHAINING) {
      if (nfc_send_frame(R_ACK | block_number, NULL, 0) == NFC_SEND_FAILED) nfc_error_handler(-11);
    } else {

      CAPDU *capdu = &apdu_cmd;
      RAPDU *rapdu = &apdu_resp;

      // Case-3 FIDO SELECT readers do not necessarily follow 61xx with GET
      // RESPONSE. Keep continuous T=CL responses for that APDU profile only.
      update_fido_response_mode(shared_io_buffer, apdu_buffer_rx_size);
      if (build_capdu(&apdu_cmd, shared_io_buffer, apdu_buffer_rx_size) < 0) {
        LL = 0;
        SW = SW_WRONG_LENGTH;
      } else if (process_nfc_apdu(capdu, rapdu) < 0) {
        // The IRQ/WTX path already recovered the transport failure.
        return;
      }

      aggregate_get_response = aggregate_fido_responses && capdu->extended && HI(SW) == 0x61;
      if (aggregate_get_response) {
        apdu_buffer_tx_size = LL;
      } else {
        apdu_buffer_tx_size = LL + 2;
        shared_io_buffer[LL] = HI(SW);
        shared_io_buffer[LL + 1] = LO(SW);
      }

      apdu_buffer_rx_size = 0;
      apdu_buffer_sent = 0;
      inf_sending = 1;
      if (send_apdu_buffer(0) == NFC_SEND_FAILED) nfc_error_handler(-12);
    }
  } else if ((rx_frame_buf[0] & PCB_MASK) == PCB_R_BLOCK) {
    if ((rx_frame_buf[0] & R_BLOCK_MASK) == R_ACK) {
      if ((rx_frame_buf[0] & 1) != block_number) { // continue chaining
        block_number ^= 1;
        if (send_apdu_buffer(0) == NFC_SEND_FAILED) nfc_error_handler(-13);
      } else { // re-send
        if (send_apdu_buffer(1) == NFC_SEND_FAILED) nfc_error_handler(-14);
      }
    } else {
      if ((rx_frame_buf[0] & 1) != block_number) {
        if (inf_sending) { // continue chaining
          block_number ^= 1;
          if (send_apdu_buffer(0) == NFC_SEND_FAILED) nfc_error_handler(-15);
        } else { // card presence check reply
          if (nfc_send_frame(R_ACK | block_number, NULL, 0) == NFC_SEND_FAILED) nfc_error_handler(-16);
        }
      } else { // re-send
        if (send_apdu_buffer(1) == NFC_SEND_FAILED) nfc_error_handler(-17);
      }
    }
  } else {
    // S-Block
  }
}

__attribute__((minsize)) void nfc_handler(void) {
  uint8_t irq[3];
#if NFC_CHIP == NFC_CHIP_FM11NT
  uint8_t received_frame = 0;
#endif
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
#if NFC_CHIP == NFC_CHIP_FM11NT
  if (irq[2] & AUX_IRQ_HALT) {
    reset_nfc_session();
    return;
  }
  if (irq[0] & MAIN_IRQ_ACTIVE) reset_nfc_session();
  if (irq[0] & MAIN_IRQ_TX_DONE) DBG_MSG("NFC TX done\n");
#endif

  if (irq[0] & MAIN_IRQ_RX_DONE) {
    if (fm_read_regs(FM_REG_FIFO_WORDCNT, &rx_frame_size, 1) != FM_STATUS_OK) {
      nfc_error_handler(-9);
      return;
    }
    if (rx_frame_size == 0) {
      nfc_error_handler(-21);
      return;
    } else if (rx_frame_size > sizeof(rx_frame_buf)) {
      nfc_error_handler(-5);
      return;
    } else if (fm_read_fifo(rx_frame_buf, rx_frame_size) != FM_STATUS_OK) {
      nfc_error_handler(-10);
      return;
    } else {
      DBG_MSG("RX: ");
      PRINT_HEX(rx_frame_buf, rx_frame_size);
      if (next_state == TO_SEND) DBG_MSG("Wrong State!\n");
      next_state = TO_SEND;
#if NFC_CHIP == NFC_CHIP_FM11NT
      received_frame = 1;
#endif
    }
  }
#if NFC_CHIP == NFC_CHIP_FM11NT
  if (received_frame) fast_recovery_pending = 0;
#endif
}

#endif // NFC_CHIP != NFC_CHIP_NA

#endif // ENABLE_NFC
