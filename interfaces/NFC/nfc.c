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

static volatile uint32_t state_spinlock;
static volatile enum { TO_RECEIVE, TO_SEND } next_state;
static uint8_t block_number, rx_frame_size, rx_frame_buf[32], tx_frame_buf[32];
static uint8_t inf_sending;
static uint8_t aggregate_get_response;
static uint16_t apdu_buffer_rx_size, apdu_buffer_tx_size;
static uint16_t apdu_buffer_sent, last_sent;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

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

static int load_next_aggregated_chunk(void) {
  CAPDU capdu = {
      .data = shared_io_buffer, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .le = 0x100, .lc = 0, .extended = 0};
  RAPDU rapdu = {.data = shared_io_buffer};

  device_set_timeout(send_wtx, WTX_PERIOD);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  device_set_timeout(NULL, 0);

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
  block_number = 1;
  apdu_buffer_rx_size = 0;
  apdu_buffer_tx_size = 0;
  last_sent = 0;
  inf_sending = 0;
  aggregate_get_response = 0;
  state_spinlock = 0;
  next_state = TO_RECEIVE;
  // NFC interface uses shared_io_buffer w/o calling acquire_apdu_buffer(), because NFC mode is exclusive with USB mode
  apdu_cmd.data = shared_io_buffer;
  apdu_resp.data = shared_io_buffer;
  fm_write_regs(FM_REG_FIFO_FLUSH, &block_number, 1); // writing anything to this reg will flush FIFO buffer
}

static void nfc_error_handler(int code __attribute__((unused))) {
  DBG_MSG("NFC Error %d\n", code);
  block_number = 1;
  apdu_buffer_rx_size = 0;
  apdu_buffer_tx_size = 0;
  last_sent = 0;
  inf_sending = 0;
  aggregate_get_response = 0;
  state_spinlock = 0;
  next_state = TO_RECEIVE;
#if NFC_CHIP == NFC_CHIP_FM11NT
  uint8_t data = 0x77; // set NFC to IDLE
  fm_write_regs(FM_REG_RF_TXEN, &data, 1);
  data = 0x55; // reset
  fm_write_regs(FM_REG_RESET_SILENCE, &data, 1);
#endif
}

static void do_nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  if (len > 29) return;

  tx_frame_buf[0] = prologue;
  if (data != NULL) memcpy(tx_frame_buf + 1, data, len);

  DBG_MSG("TX: ");
  PRINT_HEX(tx_frame_buf, len + 1);

  fm_write_fifo(tx_frame_buf, len + 1);
  const uint8_t val = 0x55;
  fm_write_regs(FM_REG_RF_TXEN, &val, 1);
}

void nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  for (int retry = 1; retry;) {
    if (device_spinlock_lock(&state_spinlock, true) != 0) return;
    if (next_state == TO_SEND) {
      do_nfc_send_frame(prologue, data, len);
      next_state = TO_RECEIVE;
      retry = 0;
    } else {
      DBG_MSG("Wrong State!\n");
    }
    device_spinlock_unlock(&state_spinlock);
  }
}

static void send_apdu_buffer(uint8_t resend) {
  if (resend)
    apdu_buffer_sent -= last_sent;
  else if (aggregate_get_response && apdu_buffer_sent == apdu_buffer_tx_size) {
    const int more = load_next_aggregated_chunk();
    if (more < 0) {
      nfc_error_handler(-7);
      return;
    }
    aggregate_get_response = (uint8_t)more;
  }
  last_sent = apdu_buffer_tx_size - apdu_buffer_sent;
  if (last_sent == 0) {
    nfc_error_handler(-2);
    return;
  }
  if (last_sent > 29) last_sent = 29;
  uint8_t prologue = block_number | 0x02;
  if (apdu_buffer_tx_size - apdu_buffer_sent > last_sent || aggregate_get_response) prologue |= PCB_I_CHAINING;
  nfc_send_frame(prologue, shared_io_buffer + apdu_buffer_sent, last_sent);
  apdu_buffer_sent += last_sent;
  if (apdu_buffer_tx_size == apdu_buffer_sent && !aggregate_get_response) inf_sending = 0;
}

static void send_wtx(void) {
  if (device_spinlock_lock(&state_spinlock, false) != 0) return;
  if (next_state == TO_SEND) {
    uint8_t WTXM = 1;
    do_nfc_send_frame(S_WTX, &WTXM, 1);
    next_state = TO_RECEIVE;
  }
  device_spinlock_unlock(&state_spinlock);
  device_set_timeout(send_wtx, WTX_PERIOD);
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
      nfc_send_frame(R_ACK | block_number, NULL, 0);
    } else {

      CAPDU *capdu = &apdu_cmd;
      RAPDU *rapdu = &apdu_resp;

      if (build_capdu(&apdu_cmd, shared_io_buffer, apdu_buffer_rx_size) < 0) {
        LL = 0;
        SW = SW_WRONG_LENGTH;
      } else {
        device_set_timeout(send_wtx, WTX_PERIOD);
        process_apdu_from(capdu, rapdu, APDU_TRANSPORT_NFC);
        device_set_timeout(NULL, 0);
      }

      aggregate_get_response = capdu->extended && is_native_u2f_apdu(capdu) && HI(SW) == 0x61;
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
      send_apdu_buffer(0);
    }
  } else if ((rx_frame_buf[0] & PCB_MASK) == PCB_R_BLOCK) {
    if ((rx_frame_buf[0] & R_BLOCK_MASK) == R_ACK) {
      if ((rx_frame_buf[0] & 1) != block_number) { // continue chaining
        block_number ^= 1;
        send_apdu_buffer(0);
      } else { // re-send
        send_apdu_buffer(1);
      }
    } else {
      if ((rx_frame_buf[0] & 1) != block_number) {
        if (inf_sending) { // continue chaining
          block_number ^= 1;
          send_apdu_buffer(0);
        } else { // card presence check reply
          nfc_send_frame(R_ACK | block_number, NULL, 0);
        }
      } else { // re-send
        send_apdu_buffer(1);
      }
    }
  } else {
    // S-Block
  }
}

void nfc_handler(void) {
  uint8_t irq[3];
  fm_read_regs(FM_REG_MAIN_IRQ, irq, sizeof(irq));
  if (!is_nfc()) {
    ERR_MSG("IRQ %02x in non-NFC mode\n", irq[0]);
    return;
  }

  if (irq[0] & MAIN_IRQ_RX_DONE) {
    fm_read_regs(FM_REG_FIFO_WORDCNT, &rx_frame_size, 1);
    if (rx_frame_size > 32) {
      nfc_error_handler(-5);
      return;
    }
    fm_read_fifo(rx_frame_buf, rx_frame_size);
    DBG_MSG("RX: ");
    PRINT_HEX(rx_frame_buf, rx_frame_size);
    if (next_state == TO_SEND) DBG_MSG("Wrong State!\n");
    next_state = TO_SEND;
  }
  if (irq[2] & AUX_IRQ_ERROR_MASK) {
    DBG_MSG("AUX: %02X\n", irq[2]);
    nfc_error_handler(-1);
  }
}

#endif // NFC_CHIP != NFC_CHIP_NA

#endif // ENABLE_NFC
