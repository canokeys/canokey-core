// SPDX-License-Identifier: Apache-2.0
#include "nfc.h"

#if ENABLE_NFC

#include "apdu.h"
#include "ctap.h"
#include "device.h"

#if NFC_CHIP == NFC_CHIP_NA

void nfc_init(void) {}
void nfc_loop(void) {}
void nfc_handler(void) {}

#else

#define WTX_PERIOD 150
#define WTX_LOCK_RETRY_PERIOD 1

static volatile uint32_t state_spinlock;
static volatile enum { TO_RECEIVE, TO_SEND } next_state;
static uint8_t block_number, rx_frame_size, rx_frame_buf[32], tx_frame_buf[32];
static uint8_t inf_sending;
static uint8_t aggregate_get_response;
static uint16_t apdu_buffer_rx_size, apdu_buffer_tx_size;
static uint16_t apdu_buffer_sent, last_sent;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;
static volatile uint8_t apdu_processing;
static volatile uint8_t apdu_transport_failed;
#if NFC_CHIP == NFC_CHIP_FM11NT
static volatile uint8_t fast_recovery_pending;
#endif

static void send_wtx(void);

static void reset_nfc_state(void) {
  block_number = 1;
  apdu_buffer_rx_size = 0;
  apdu_buffer_tx_size = 0;
  apdu_buffer_sent = 0;
  last_sent = 0;
  inf_sending = 0;
  aggregate_get_response = 0;
  next_state = TO_RECEIVE;
}

static void stop_apdu_wtx(void) {
  apdu_processing = 0;
  device_set_timeout(NULL, 0);
}

#if NFC_CHIP == NFC_CHIP_FM11NT
static void reset_nfc_session(void) {
  if (apdu_processing) apdu_transport_failed = 1;
  stop_apdu_wtx();
  reset_nfc_state();
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

static uint8_t is_native_u2f_apdu(const CAPDU *capdu) {
  if (capdu->cla != 0x00) return 0;

  switch (capdu->ins) {
  case 0x01: // U2F_REGISTER
  case 0x02: // U2F_AUTHENTICATE
  case 0x03: // U2F_VERSION
    return 1;
  case 0xA4: // U2F_SELECT, distinct from ISO SELECT by P1/P2
    return !(capdu->p1 == 0x04 && capdu->p2 == 0x00);
  default:
    return 0;
  }
}

static uint8_t is_fido_nfc_apdu(const CAPDU *capdu) {
  return ((capdu->cla & 0xEF) == 0x80 && capdu->ins == CTAP_INS_MSG) || is_native_u2f_apdu(capdu);
}

static int load_next_aggregated_chunk(void) {
  CAPDU capdu = {
      .data = shared_io_buffer, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .le = 0x100, .lc = 0, .extended = 0};
  RAPDU rapdu = {.data = shared_io_buffer};

  if (process_nfc_apdu(&capdu, &rapdu) < 0) return -1;

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

void nfc_init(void) {
  reset_nfc_state();
  state_spinlock = 0;
  apdu_processing = 0;
  apdu_transport_failed = 0;
  // NFC interface uses shared_io_buffer w/o calling acquire_apdu_buffer(), because NFC mode is exclusive with USB mode
  apdu_cmd.data = shared_io_buffer;
  apdu_resp.data = shared_io_buffer;
#if NFC_CHIP != NFC_CHIP_FM11NT
  // FM11NT may already hold the reader's first frame by the time platform initialization finishes.
  fm_write_regs(FM_REG_FIFO_FLUSH, &block_number, 1); // writing anything to this reg will flush FIFO buffer
#else
  fast_recovery_pending = 0;
  uint8_t irq_mask;
  if (fm_read_regs(FM_REG_MAIN_IRQ_MASK, &irq_mask, 1) == FM_STATUS_OK) {
    irq_mask |= MAIN_IRQ_RX_START | MAIN_IRQ_TX_DONE;
    if (fm_write_regs(FM_REG_MAIN_IRQ_MASK, &irq_mask, 1) != FM_STATUS_OK)
      ERR_MSG("Failed to update FM11NT IRQ mask\n");
  } else {
    ERR_MSG("Failed to read FM11NT IRQ mask\n");
  }
#endif
}

static void nfc_error_handler(int code __attribute__((unused))) {
  DBG_MSG("NFC Error %d\n", code);
  if (apdu_processing) apdu_transport_failed = 1;
  stop_apdu_wtx();
  reset_nfc_state();
#if NFC_CHIP == NFC_CHIP_FM11NT
  if (!fast_recovery_pending) {
    uint8_t data = 0x77; // return the RF state machine to IDLE
    int recovery_failed = fm_write_regs(FM_REG_RF_TXEN, &data, 1) != FM_STATUS_OK;
    if (fm_write_regs(FM_REG_FIFO_FLUSH, &data, 1) != FM_STATUS_OK) recovery_failed = 1;
    if (!recovery_failed) {
      fast_recovery_pending = 1;
      return;
    }
  }

  uint8_t data = 0x55; // repeated failure: fall back to an FM11NT soft reset
  fm_write_regs(FM_REG_RESET_SILENCE, &data, 1);
  fast_recovery_pending = 1;
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

static int nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  for (;;) {
    if (device_spinlock_lock(&state_spinlock, true) != 0) return -1;
    if (next_state == TO_SEND) {
      const int ret = do_nfc_send_frame(prologue, data, len);
      if (ret == 0) next_state = TO_RECEIVE;
      device_spinlock_unlock(&state_spinlock);
      return ret;
    }
    device_spinlock_unlock(&state_spinlock);
  }
}

static int send_apdu_buffer(uint8_t resend) {
  if (resend)
    apdu_buffer_sent -= last_sent;
  else if (aggregate_get_response && apdu_buffer_sent == apdu_buffer_tx_size) {
    const int more = load_next_aggregated_chunk();
    if (more < 0) {
      return -1;
    }
    aggregate_get_response = (uint8_t)more;
  }
  last_sent = apdu_buffer_tx_size - apdu_buffer_sent;
  if (last_sent == 0) return -1;
  if (last_sent > 29) last_sent = 29;
  uint8_t prologue = block_number | 0x02;
  if (apdu_buffer_tx_size - apdu_buffer_sent > last_sent || aggregate_get_response) prologue |= PCB_I_CHAINING;
  if (nfc_send_frame(prologue, shared_io_buffer + apdu_buffer_sent, last_sent) < 0) return -1;
  apdu_buffer_sent += last_sent;
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

void nfc_loop(void) {
  if (next_state == TO_RECEIVE) return;

  if ((rx_frame_buf[0] & PCB_MASK) == PCB_I_BLOCK) {
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
      if (nfc_send_frame(R_ACK | block_number, NULL, 0) < 0) nfc_error_handler(-11);
    } else {

      CAPDU *capdu = &apdu_cmd;
      RAPDU *rapdu = &apdu_resp;

      if (build_capdu(&apdu_cmd, shared_io_buffer, apdu_buffer_rx_size) < 0) {
        LL = 0;
        SW = SW_WRONG_LENGTH;
      } else if (process_nfc_apdu(capdu, rapdu) < 0) {
        // The IRQ/WTX path already recovered the transport failure.
        return;
      }

      // The 7644370f implementation's 1340-byte APDU buffer hid response
      // paging from extended FIDO clients. Keep that behavior by consuming
      // 61xx internally while emitting one chained T=CL response.
      aggregate_get_response = capdu->extended && is_fido_nfc_apdu(capdu) && HI(SW) == 0x61;
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
      if (send_apdu_buffer(0) < 0) nfc_error_handler(-12);
    }
  } else if ((rx_frame_buf[0] & PCB_MASK) == PCB_R_BLOCK) {
    if ((rx_frame_buf[0] & R_BLOCK_MASK) == R_ACK) {
      if ((rx_frame_buf[0] & 1) != block_number) { // continue chaining
        block_number ^= 1;
        if (send_apdu_buffer(0) < 0) nfc_error_handler(-13);
      } else { // re-send
        if (send_apdu_buffer(1) < 0) nfc_error_handler(-14);
      }
    } else {
      if ((rx_frame_buf[0] & 1) != block_number) {
        if (inf_sending) { // continue chaining
          block_number ^= 1;
          if (send_apdu_buffer(0) < 0) nfc_error_handler(-15);
        } else { // card presence check reply
          if (nfc_send_frame(R_ACK | block_number, NULL, 0) < 0) nfc_error_handler(-16);
        }
      } else { // re-send
        if (send_apdu_buffer(1) < 0) nfc_error_handler(-17);
      }
    }
  } else {
    // S-Block
  }
}

void nfc_handler(void) {
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
