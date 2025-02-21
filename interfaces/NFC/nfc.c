// SPDX-License-Identifier: Apache-2.0
#include "nfc.h"
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
static uint16_t apdu_buffer_rx_size, apdu_buffer_tx_size;
static uint16_t apdu_buffer_sent, last_sent;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

void nfc_init(void) {
  block_number = 1;
  apdu_buffer_rx_size = 0;
  apdu_buffer_tx_size = 0;
  last_sent = 0;
  inf_sending = 0;
  state_spinlock = 0;
  next_state = TO_RECEIVE;
  // NFC interface uses global_buffer w/o calling acquire_apdu_buffer(), because NFC mode is exclusive with USB mode
  apdu_cmd.data = global_buffer;
  apdu_resp.data = global_buffer;
  fm_write_regs(FM_REG_FIFO_FLUSH, &block_number, 1); // writing anything to this reg will flush FIFO buffer
}

static void nfc_error_handler(int code __attribute__((unused))) {
  DBG_MSG("NFC Error %d\n", code);
  block_number = 1;
  apdu_buffer_rx_size = 0;
  apdu_buffer_tx_size = 0;
  last_sent = 0;
  inf_sending = 0;
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
  if (resend) apdu_buffer_sent -= last_sent;
  last_sent = apdu_buffer_tx_size - apdu_buffer_sent;
  if (last_sent == 0) {
    nfc_error_handler(-2);
    return;
  }
  if (last_sent > 29) last_sent = 29;
  uint8_t prologue = block_number | 0x02;
  if (apdu_buffer_tx_size - apdu_buffer_sent > last_sent) prologue |= PCB_I_CHAINING;
  nfc_send_frame(prologue, global_buffer + apdu_buffer_sent, last_sent);
  apdu_buffer_sent += last_sent;
  if (apdu_buffer_tx_size == apdu_buffer_sent) inf_sending = 0;
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

    if (rx_frame_buf[0] & PCB_I_CHAINING) {
      memcpy(global_buffer + apdu_buffer_rx_size, rx_frame_buf + 1, rx_frame_size - 3);
      if (apdu_buffer_rx_size + rx_frame_size - 3 > APDU_BUFFER_SIZE) {
        nfc_error_handler(-3);
        return;
      }
      apdu_buffer_rx_size += rx_frame_size - 3;
      nfc_send_frame(R_ACK | block_number, NULL, 0);
    } else {
      memcpy(global_buffer + apdu_buffer_rx_size, rx_frame_buf + 1, rx_frame_size - 3);
      if (apdu_buffer_rx_size + rx_frame_size - 3 > APDU_BUFFER_SIZE) {
        nfc_error_handler(-4);
        return;
      }
      apdu_buffer_rx_size += rx_frame_size - 3;

      CAPDU *capdu = &apdu_cmd;
      RAPDU *rapdu = &apdu_resp;

      if (build_capdu(&apdu_cmd, global_buffer, apdu_buffer_rx_size) < 0) {
        LL = 0;
        SW = SW_WRONG_LENGTH;
      } else {
        device_set_timeout(send_wtx, WTX_PERIOD);
        process_apdu(capdu, rapdu);
        device_set_timeout(NULL, 0);
      }

      apdu_buffer_tx_size = LL + 2;
      global_buffer[LL] = HI(SW);
      global_buffer[LL + 1] = LO(SW);

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

#endif
