#include "nfc.h"
#include "apdu.h"
#include "device.h"

static volatile uint32_t state_spinlock;
static volatile uint8_t has_frame, nfc_state;
static uint8_t block_number, frame_size, frame_buf[32], apdu_buffer[APDU_BUFFER_SIZE];
static uint16_t apdu_buffer_size, apdu_buffer_sent, last_sent;
static CAPDU apdu_cmd;
static RAPDU apdu_resp;

void nfc_init(void) {
  block_number = 1;
  has_frame = 0;
  apdu_buffer_size = 0;
  last_sent = 0;
  state_spinlock = 0;
  nfc_state = NFC_STATE_IDLE;
  apdu_cmd.data = apdu_buffer;
  apdu_resp.data = apdu_buffer;
  fm_write_reg(REG_REGU_CFG, (uint8_t[]){0x3F}, 1);
}

void nfc_setup(void) {
  // set ATQA=4400 and SAK=04/20
  fm_write_eeprom(0x3A0, (uint8_t[]){0x44, 0x00, 0x04, 0x20}, 4);
  device_delay(15);
  // set ATS: FSCI=2, DS=1, DR=1, FWI=8, SFGI=8
  // set NFC: L4, no active interrupt
  fm_write_eeprom(0x3B0, (uint8_t[]){0x05, 0x72, 0x03, 0x00, 0xF7, 0x84, 0x00}, 7);
  device_delay(15);
  // regu_cfg
  fm_write_eeprom(0x391, (uint8_t[]){0x37}, 1);
  device_delay(15);
}

void nfc_handler(void) {
  uint8_t irq[3];
  fm_read_reg(REG_MAIN_IRQ, irq, sizeof(irq));

  if (irq[0] & MAIN_IRQ_RX_DONE) {
    fm_read_reg(REG_FIFO_WORDCNT, &frame_size, 1);
    fm_read_fifo(frame_buf, frame_size);
    has_frame = 1;
  }
}

int nfc_send_frame(uint8_t prologue, uint8_t *data, uint8_t len) {
  if (len > 29) return -1;

  frame_buf[0] = prologue;
  memcpy(frame_buf + 1, data, len);

  uint8_t val = 0x55;
  fm_write_fifo(frame_buf, len + 1);
  fm_write_reg(REG_RF_TXEN, &val, 1);

  nfc_state = NFC_STATE_IDLE;
  device_spinlock_unlock(&state_spinlock);

  return 0;
}

void send_apdu_buffer(uint8_t resend) {
  if (resend) apdu_buffer_size -= apdu_buffer_sent -= last_sent;
  last_sent = apdu_buffer_size - apdu_buffer_sent;
  if (last_sent > 29) last_sent = 29;
  uint8_t prologue = block_number | 0x02;
  if (apdu_buffer_size - apdu_buffer_sent > last_sent) prologue |= PCB_I_CHAINING;
  nfc_send_frame(prologue, apdu_buffer + apdu_buffer_sent, last_sent);
  apdu_buffer_sent += last_sent;

  if (apdu_buffer_sent == apdu_buffer_size) apdu_buffer_size = 0;
}

void nfc_loop(void) {
  if (has_frame == 0) return;
  has_frame = 0;

  device_spinlock_lock(&state_spinlock, true);
  nfc_state = NFC_STATE_BUSY;

  PRINT_HEX(frame_buf, frame_size);

  if ((frame_buf[0] & PCB_MASK) == PCB_I_BLOCK) {
    block_number ^= 1;

    if (frame_buf[0] & PCB_I_CHAINING) {
      memcpy(apdu_buffer + apdu_buffer_size, frame_buf + 1, frame_size - 3);
      apdu_buffer_size += frame_size - 3;
      nfc_send_frame(R_ACK | block_number, NULL, 0);
    } else {
      memcpy(apdu_buffer + apdu_buffer_size, frame_buf + 1, frame_size - 3);
      apdu_buffer_size += frame_size - 3;

      DBG_MSG("C: ");
      PRINT_HEX(apdu_buffer, apdu_buffer_size);

      CAPDU *capdu = &apdu_cmd;
      RAPDU *rapdu = &apdu_resp;

      if (build_capdu(&apdu_cmd, apdu_buffer, apdu_buffer_size) < 0) {
        LL = 0;
        SW = SW_CHECKING_ERROR;
      } else
        process_apdu(capdu, rapdu);

      apdu_buffer_size = LL + 2;
      apdu_buffer[LL] = HI(SW);
      apdu_buffer[LL + 1] = LO(SW);

      DBG_MSG("R: ");
      PRINT_HEX(apdu_buffer, apdu_buffer_size);

      apdu_buffer_sent = 0;
      send_apdu_buffer(0);
    }
  } else if ((frame_buf[0] & PCB_MASK) == PCB_R_BLOCK) {
    if ((frame_buf[0] & R_BLOCK_MASK) == R_ACK) {
      if ((frame_buf[0] & 1) != block_number) {
        block_number ^= 1;
        send_apdu_buffer(0);
      } else
        send_apdu_buffer(1);
    } else {
      if ((frame_buf[0] & 1) != block_number)
        nfc_send_frame(R_ACK | block_number, NULL, 0);
      else
        send_apdu_buffer(1);
    }
  } else {
    nfc_send_frame(R_NAK | block_number, NULL, 0);
  }
}

void nfc_wtx(void) {
  if (device_spinlock_lock(&state_spinlock, false) != 0) return;
  if (nfc_state == NFC_STATE_BUSY) nfc_send_frame(S_WTX, NULL, 0);
  device_spinlock_unlock(&state_spinlock);
}
