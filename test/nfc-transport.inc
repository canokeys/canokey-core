// SPDX-License-Identifier: Apache-2.0
// Compile the real FM11NT transport into the APDU integration test. Renaming
// hardware hooks avoids replacing device-sim's USB timer or linking a fake NFC
// implementation in place of the code being exercised.
static uint8_t nfc_test_irq[3], nfc_test_rx[32], nfc_test_rx_len;
static uint8_t nfc_test_tx[32], nfc_test_tx_len;
static void (*nfc_test_timer)(void);
static unsigned nfc_test_releases;
static int nfc_test_io_fail;
static unsigned nfc_test_reset_on_read, nfc_test_reset_on_release;
static bool nfc_test_reset_on_tx;
static bool nfc_test_read_succeeds_after_reset;
static void (*nfc_test_on_tx_enable)(void);
static unsigned nfc_test_fail_read, nfc_test_fail_write;
static unsigned nfc_test_retry_on_write;
static uint8_t nfc_test_rf_status;
static uint8_t nfc_test_main_irq_mask;
void nfc_test_handler(void);
void nfc_test_loop(void);
static void nfc_test_halt(void) {
  nfc_test_irq[2] = AUX_IRQ_HALT;
  nfc_test_handler();
}
static int nfc_test_read_request(void *ctx, size_t offset, uint8_t *buf, size_t len) {
  if (nfc_test_fail_read && --nfc_test_fail_read == 0) return -1;
  if (nfc_test_reset_on_read && --nfc_test_reset_on_read == 0) {
    unsigned released = nfc_test_releases;
    nfc_test_halt();
    nfc_test_loop(); // synchronous parser must prevent reentrant cleanup
    assert_int_equal(nfc_test_releases, released);
    if (!nfc_test_read_succeeds_after_reset) return -1;
  }
  return apdu_request_read_pke(ctx, offset, buf, len);
}
static int nfc_test_write_request(size_t offset, const void *buf, size_t len) {
  if (nfc_test_fail_write && --nfc_test_fail_write == 0) return -1;
  if (nfc_test_retry_on_write && --nfc_test_retry_on_write == 0) {
    nfc_test_rx[0] = R_NAK;
    nfc_test_rx[1] = nfc_test_rx[2] = 0; // CRC bytes must not replace request data
    nfc_test_rx_len = 3;
    nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
    nfc_test_handler();
  }
  return pke_buffer_write(offset, buf, len);
}
static void nfc_test_timeout(void (*callback)(void), uint16_t timeout) { nfc_test_timer = timeout ? callback : NULL; }
static fm_status_t nfc_test_read_regs(uint16_t reg, uint8_t *buf, uint8_t len) {
  if (nfc_test_io_fail) return FM_STATUS_NACK;
  memset(buf, 0, len);
  if (reg == FM_REG_MAIN_IRQ) {
    memcpy(buf, nfc_test_irq, len);
    memset(nfc_test_irq, 0, 3);
  }
  if (reg == FM_REG_FIFO_WORDCNT) *buf = nfc_test_rx_len;
  if (reg == FM_REG_RF_STATUS) *buf = nfc_test_rf_status;
  return FM_STATUS_OK;
}
static fm_status_t nfc_test_write_regs(uint16_t reg, const uint8_t *buf, uint8_t len) {
  (void)buf;
  (void)len;
  if (!nfc_test_io_fail && reg == FM_REG_MAIN_IRQ_MASK) nfc_test_main_irq_mask = *buf;
  if (reg == FM_REG_RF_TXEN && nfc_test_on_tx_enable) {
    void (*callback)(void) = nfc_test_on_tx_enable;
    nfc_test_on_tx_enable = NULL;
    callback();
  }
  return nfc_test_io_fail ? FM_STATUS_NACK : FM_STATUS_OK;
}
static fm_status_t nfc_test_read_fifo(uint8_t *buf, uint8_t len) {
  memcpy(buf, nfc_test_rx, len);
  return FM_STATUS_OK;
}
static fm_status_t nfc_test_write_fifo(uint8_t *buf, uint8_t len) {
  memcpy(nfc_test_tx, buf, len);
  nfc_test_tx_len = len;
  if (nfc_test_reset_on_tx) {
    nfc_test_reset_on_tx = false;
    nfc_test_halt();
  }
  return FM_STATUS_OK;
}
static int nfc_test_release(uint8_t owner) {
  ++nfc_test_releases;
  if (nfc_test_reset_on_release && --nfc_test_reset_on_release == 0) nfc_test_halt();
  int ret = pke_buffer_release(owner);
  uint8_t poison[64];
  memset(poison, 0xA5, sizeof(poison));
  for (size_t off = 0; off < pke_buffer_size(); off += sizeof(poison))
    assert_int_equal(pke_buffer_write(off, poison, MIN(sizeof(poison), pke_buffer_size() - off)), 0);
  return ret;
}
#undef NFC_CHIP
#define NFC_CHIP NFC_CHIP_FM11NT
#define nfc_init nfc_test_init
#define nfc_loop nfc_test_loop
#define nfc_handler nfc_test_handler
#define device_set_timeout nfc_test_timeout
#define fm_read_regs nfc_test_read_regs
#define fm_write_regs nfc_test_write_regs
#define fm_read_fifo nfc_test_read_fifo
#define fm_write_fifo nfc_test_write_fifo
#define apdu_request_read_pke nfc_test_read_request
#define pke_buffer_release nfc_test_release
#define pke_buffer_write nfc_test_write_request
#include "../interfaces/NFC/nfc.c"
#undef nfc_init
#undef nfc_loop
#undef nfc_handler
#undef device_set_timeout
#undef fm_read_regs
#undef fm_write_regs
#undef fm_read_fifo
#undef fm_write_fifo
#undef pke_buffer_release
#undef pke_buffer_write
#undef apdu_request_read_pke

static void nfc_test_frame(uint8_t pcb, const uint8_t *data, size_t len) {
  assert_true(len <= 29);
  nfc_test_rx[0] = pcb;
  if (len) memcpy(nfc_test_rx + 1, data, len);
  nfc_test_rx_len = len + 3; // FM11NT RX includes CRC; TX hardware appends it.
  nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
  nfc_test_tx_len = 0;
  nfc_test_handler();
  nfc_test_loop();
}

static size_t nfc_test_exchange(const uint8_t *cmd, size_t len, size_t first, uint8_t *out, size_t capacity) {
  for (size_t off = 0; off < len;) {
    size_t n = MIN(off == 0 ? first : 29, len - off);
    uint8_t pcb = 0x02 | (block_number ^ 1) | (off + n < len ? PCB_I_CHAINING : 0);
    nfc_test_frame(pcb, cmd + off, n);
    if (off + n < len) {
      assert_int_equal(nfc_test_tx[0], R_ACK | block_number);
      // Duplicate an I-block: neither the PKE nor inline offset may advance.
      uint32_t received = apdu_buffer_rx_size;
      nfc_test_frame(pcb, cmd + off, n);
      assert_int_equal(apdu_buffer_rx_size, received);
      assert_int_equal(nfc_test_tx[0], R_ACK | block_number);
    }
    off += n;
  }
  size_t written = 0;
  for (;;) {
    assert_true(nfc_test_tx_len > 0);
    assert_int_equal(nfc_test_tx[0] & PCB_MASK, PCB_I_BLOCK);
    assert_true(written + nfc_test_tx_len - 1 <= capacity);
    memcpy(out + written, nfc_test_tx + 1, nfc_test_tx_len - 1);
    written += nfc_test_tx_len - 1;
    uint8_t saved[32];
    size_t saved_len = nfc_test_tx_len;
    memcpy(saved, nfc_test_tx, saved_len);
    // Retry every response frame, including refill boundaries and the final
    // frame. A forward-only source must never be read again for a retry.
    nfc_test_frame(R_NAK | block_number, NULL, 0);
    assert_int_equal(nfc_test_tx_len, saved_len);
    assert_memory_equal(nfc_test_tx, saved, saved_len);
    if (!(saved[0] & PCB_I_CHAINING)) break;
    nfc_test_frame(R_ACK | (block_number ^ 1), NULL, 0);
  }
  return written;
}

static void nfc_test_fixture(bool le) {
  device_applet_session_clear();
  init_apdu_buffer();
  assert_int_equal(ctap_install(1), 0);
  set_nfc_state(1);
  nfc_test_releases = 0;
  nfc_test_io_fail = 0;
  nfc_test_reset_on_read = nfc_test_reset_on_release = 0;
  nfc_test_reset_on_tx = false;
  nfc_test_read_succeeds_after_reset = false;
  nfc_test_on_tx_enable = NULL;
  nfc_test_fail_read = nfc_test_fail_write = 0;
  nfc_test_retry_on_write = 0;
  nfc_test_rf_status = 0;
  nfc_test_init();
  uint8_t select[] = {0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1, 0};
  uint8_t response[32];
  size_t n = nfc_test_exchange(select, le ? 14 : 13, 4, response, sizeof(response));
  assert_int_equal(n, 8);
  assert_memory_equal(response, "U2F_V2\x90\x00", 8);
}

static void test_nfc_recovery_irq_mask(void **unused) {
  (void)unused;
  nfc_test_fixture(false);
  nfc_error_handler(-1);
  nfc_test_loop();
  assert_int_equal(idle_recovery_state, NFC_RECOVERY_SILENCED);
  assert_int_equal(nfc_test_main_irq_mask, 0xFF);
  assert_non_null(nfc_test_timer);
  nfc_test_timer();
  nfc_test_loop();
  nfc_test_loop();
  assert_int_equal(nfc_test_main_irq_mask, NFC_RUNTIME_IRQ_MASK);
}

static void test_nfc_first_extended_select(void **unused) {
  (void)unused;
  nfc_test_fixture(false);
  nfc_test_init();
  device_applet_context_reset();
  uint8_t command[288] = {0, 0xA4, 4, 1, 0, 1, 23};
  uint8_t response[16];
  size_t n = nfc_test_exchange(command, sizeof(command), 29, response, sizeof(response));
  assert_int_equal(n, 2);
  assert_memory_equal(response, "\x6A\x86", 2);
}

static void test_nfc_envelope_length_controls(void **unused) {
  (void)unused;
  nfc_test_fixture(false);
  nfc_test_init();
  device_applet_context_reset();
  uint8_t command[288] = {0x80, 0x10, 0, 0, 0, 1, 23, 0x7F};
  uint8_t response[16];
  size_t n = nfc_test_exchange(command, 264, 29, response, sizeof(response));
  assert_int_equal(n, 2);
  assert_memory_equal(response, "\x67\x00", 2);
  memset(command + 4, 0, sizeof(command) - 4);
  command[4] = 1;
  command[5] = 0x7F;
  n = nfc_test_exchange(command, sizeof(command), 29, response, sizeof(response));
  assert_int_equal(n, 2);
  assert_memory_equal(response, "\x67\x00", 2);
}

static size_t nfc_test_extended(uint8_t *apdu, const uint8_t *body, size_t len, uint32_t le) {
  const uint8_t header[] = {0x80, 0x10, 0, 0, 0};
  memcpy(apdu, header, sizeof(header));
  apdu[5] = len >> 8;
  apdu[6] = len;
  memcpy(apdu + 7, body, len);
  apdu[7 + len] = le >> 8;
  apdu[8 + len] = le;
  return len + 9;
}

static void nfc_test_receive_during_tx_enable(void) {
  // GPIO may preempt the main loop when i2c_stop() unmasks it after TXEN.
  // An R-block occupies the next turn even if the interrupted TX call
  // has not returned yet.
  nfc_test_rx[0] = R_ACK | (block_number ^ 1);
  nfc_test_rx_len = 3;
  nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
  nfc_test_handler();
}

static void test_nfc_irq_rx_handoff(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  const uint8_t info[] = {0x80, 0x10, 0, 0, 1, CTAP_GET_INFO, 0};
  nfc_test_on_tx_enable = nfc_test_receive_during_tx_enable;
  nfc_test_frame(0x02 | (block_number ^ 1), info, sizeof(info));
  assert_int_equal(next_state, TO_SEND);
  assert_int_equal(rx_frame_size, 3);
  const uint16_t sent = transfer_state.sent;
  nfc_test_loop();
  assert_true(transfer_state.sent > sent);

  // Pending receive bytes belong to the main loop until it sends a reply.
  // A retry/presence check must be drained without replacing that request.
  nfc_test_fixture(true);
  nfc_test_rx[0] = 0x02 | (block_number ^ 1);
  memcpy(nfc_test_rx + 1, info, sizeof(info));
  nfc_test_rx_len = sizeof(info) + 3;
  nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
  nfc_test_handler();
  uint8_t saved[32];
  const uint8_t saved_len = rx_frame_size;
  memcpy(saved, rx_frame_buf, saved_len);
  nfc_test_rx[0] = R_NAK | block_number;
  nfc_test_rx_len = 3;
  nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
  nfc_test_handler();
  assert_int_equal(rx_frame_size, saved_len);
  assert_memory_equal(rx_frame_buf, saved, saved_len);
  nfc_test_loop();
  assert_true(transfer_state.sending);
  assert_int_equal(nfc_test_tx[1], 0); // CTAP success, not a damaged request
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_retry_last_rx_ack(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  uint8_t body[279] = {0x7F}, cmd[288];
  size_t len = nfc_test_extended(cmd, body, sizeof(body), 0);
  nfc_test_frame(0x12 | (block_number ^ 1), cmd, 29);
  const uint8_t ack = R_ACK | block_number;
  assert_int_equal(nfc_test_tx_len, 1);
  assert_int_equal(nfc_test_tx[0], ack);
  const uint32_t received = apdu_buffer_rx_size;
  // Retry the actual last block (R-ACK), not the SELECT response that
  // happened to be the most recently cached I-block.
  nfc_test_frame(R_NAK | block_number, NULL, 0);
  assert_int_equal(nfc_test_tx_len, 1);
  assert_int_equal(nfc_test_tx[0], ack);
  assert_int_equal(apdu_buffer_rx_size, received);
  nfc_test_frame(R_ACK | block_number, NULL, 0);
  assert_int_equal(nfc_test_tx_len, 1);
  assert_int_equal(nfc_test_tx[0], ack);
  assert_int_equal(apdu_buffer_rx_size, received);
  // A new request frame must reset the retry budget and retain all data.
  for (size_t off = 29; off < len;) {
    size_t n = MIN(len - off, 29);
    nfc_test_frame(0x02 | (block_number ^ 1) | (off + n < len ? 0x10 : 0), cmd + off, n);
    off += n;
  }
  assert_int_equal(nfc_test_tx_len, 4);
  assert_memory_equal(nfc_test_tx + 1, "\xF1\x90\x00", 3);
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_shared_buffer_staging_bytes(void **unused) {
  (void)unused;
  const size_t lengths[] = {255, 256, 257, 259, 279, 280, 281, 343, 413, 1296};
  uint8_t body[1296], cmd[1305], staged[1296];
  struct { uint8_t before[32], data[APDU_COMMAND_BUFFER_SIZE], after[32]; } guarded;
  for (size_t i = 0; i < sizeof(body); ++i) body[i] = (uint8_t)(i * 73 + i / 251);
  body[0] = 0x7F; // unknown CTAP command: response cannot hide corrupted staging
  for (size_t l = 0; l < sizeof(lengths) / sizeof(*lengths); ++l) {
    for (size_t first = 1; first <= 29; ++first) {
      nfc_test_fixture(true);
      uint8_t *original = shared_io_buffer;
      memset(&guarded, 0xCD, sizeof(guarded));
      shared_io_buffer = guarded.data;
      nfc_test_init();
      apdu_rapdu_chain_reset();
      // Leave a real streamed response pending before reusing the buffer.
      const uint8_t info[] = {0x80, 0x10, 0, 0, 1, CTAP_GET_INFO, 1};
      nfc_test_frame(0x02 | (block_number ^ 1), info, sizeof(info));
      assert_true(apdu_response_source_active());
      const size_t len = nfc_test_extended(cmd, body, lengths[l], 0);
      nfc_test_retry_on_write = 2; // IRQ while PKE reads from rx_frame_buf
      for (size_t off = 0; off < len;) {
        const size_t n = MIN(off ? 29 : first, len - off);
        const bool more = off + n < len;
        nfc_test_frame(0x02 | (block_number ^ 1) | (more ? PCB_I_CHAINING : 0), cmd + off, n);
        off += n;
        for (size_t j = 0; j < 32; ++j) {
          assert_int_equal(guarded.before[j], 0xCD);
          assert_int_equal(guarded.after[j], 0xCD);
        }
        if (!more) break; // dispatch releases and deliberately poisons PKE
        assert_int_equal(apdu_buffer_rx_size, off);
        if (off <= 7 || lengths[l] <= APDU_COMMAND_BUFFER_SIZE - 9) {
          assert_memory_equal(shared_io_buffer, cmd, off);
        } else {
          const size_t received = MIN(off - 7, lengths[l]);
          assert_int_equal(transfer_state.rx_mode, RX_PKE);
          assert_int_equal(pke_buffer_read(0, staged, received), 0);
          assert_memory_equal(staged, body, received);
        }
      }
      assert_int_equal(nfc_test_tx_len, 4);
      assert_memory_equal(nfc_test_tx + 1, "\xF1\x90\x00", 3);
      assert_false(apdu_response_source_active());
      shared_io_buffer = original;
      nfc_test_halt();
      nfc_test_loop();
      set_nfc_state(0);
      device_applet_session_clear();
    }
  }
}


static void test_nfc_ack_without_response_chain(void **unused) {
  (void)unused;
  for (unsigned receiving = 0; receiving < 2; ++receiving) {
    nfc_test_fixture(true);
    const uint8_t command[] = {0x80, 0x10, 0, 0, 0, 0, 1, 0x7F, 0, 0};
    if (receiving)
      nfc_test_frame(0x12 | (block_number ^ 1), command, 7);
    const uint8_t bn = block_number;
    const uint32_t received = apdu_buffer_rx_size;
    const uint8_t cached_pcb = retransmit_prologue;
    assert_false(transfer_state.sending);
    // A different-BN ACK is meaningful only for an outgoing I-block chain.
    // It must not advance a completed response or abort an incoming command.
    nfc_test_frame(R_ACK | (bn ^ 1), NULL, 0);
    assert_false(cleanup_pending);
    assert_int_equal(next_state, TO_RECEIVE);
    assert_int_equal(block_number, bn);
    assert_int_equal(apdu_buffer_rx_size, received);
    assert_int_equal(retransmit_prologue, cached_pcb);
    assert_int_equal(nfc_test_tx_len, 0);
    if (receiving) {
      nfc_test_frame(0x02 | (bn ^ 1), command + 7, sizeof(command) - 7);
      assert_int_equal(nfc_test_tx_len, 4);
      assert_memory_equal(nfc_test_tx + 1, "\xF1\x90\x00", 3);
    }
  }
  nfc_test_halt();
  nfc_test_loop();
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_nak_does_not_advance_tx(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  const uint8_t info[] = {0x80, 0x10, 0, 0, 0, 0, 1, CTAP_GET_INFO, 0, 0};
  nfc_test_frame(0x02 | (block_number ^ 1), info, sizeof(info));
  assert_true(transfer_state.sending);
  const uint8_t bn = block_number;
  const uint16_t sent = transfer_state.sent;
  const uint16_t size = transfer_state.size;
  // ISO-DEP Rule 12 applies even during a chained response. R(NAK) is
  // never an acknowledgement permitting the response source to advance.
  nfc_test_frame(R_NAK | (bn ^ 1), NULL, 0);
  assert_int_equal(nfc_test_tx_len, 1);
  assert_int_equal(nfc_test_tx[0], R_ACK | bn);
  assert_int_equal(block_number, bn);
  assert_int_equal(transfer_state.sent, sent);
  assert_int_equal(transfer_state.size, size);
  assert_true(transfer_state.sending);
  // Only the subsequent R(ACK) advances to the next I-block.
  nfc_test_frame(R_ACK | (bn ^ 1), NULL, 0);
  assert_int_equal(block_number, bn ^ 1);
  assert_int_equal(transfer_state.sent, sent + 29);
  assert_int_equal(nfc_test_tx[0] & PCB_MASK, PCB_I_BLOCK);
  nfc_test_halt();
  nfc_test_loop();
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_coalesced_activation(void **unused) {
  (void)unused;
  const uint8_t select[] = {0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1, 0};
  // The same latched event set can describe either ordering. Live state
  // distinguishes an old HALT followed by RATS/PPS from a current HALT.
  for (unsigned state = 0; state < 16; ++state) {
    nfc_test_fixture(true);
    nfc_test_rf_status = (state << 4) | 4;
    nfc_test_rx[0] = 0x02;
    memcpy(nfc_test_rx + 1, select, sizeof(select));
    nfc_test_rx_len = sizeof(select) + 3;
    nfc_test_tx_len = 0;
    nfc_test_irq[0] = MAIN_IRQ_ACTIVE | MAIN_IRQ_RX_DONE;
    nfc_test_irq[2] = AUX_IRQ_HALT;
    nfc_test_handler();
    nfc_test_loop();
    if (state == 9 || state == 10) {
      assert_int_equal(nfc_test_tx_len, 9);
      assert_memory_equal(nfc_test_tx + 1, "U2F_V2\x90\x00", 8);
    } else {
      assert_int_equal(nfc_test_tx_len, 0);
      assert_int_equal(next_state, TO_RECEIVE);
    }
  }
  // Without a new activation, HALT must still cancel a queued RX frame.
  nfc_test_fixture(true);
  nfc_test_rf_status = 0x90;
  nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
  nfc_test_irq[2] = AUX_IRQ_HALT;
  nfc_test_tx_len = 0;
  nfc_test_handler();
  nfc_test_loop();
  assert_int_equal(nfc_test_tx_len, 0);
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_extended_envelope_and_recovery(void **unused) {
  (void)unused;
  uint8_t body[PKE_BUFFER_SIZE + 1], cmd[PKE_BUFFER_SIZE + 12], out[2048], reference[2048];
  memset(body, 0, sizeof(body));
  body[0] = CTAP_GET_INFO;
  size_t reference_len = 0;
  for (unsigned select_le = 0; select_le < 2; ++select_le) {
    nfc_test_fixture(select_le);
    for (unsigned split = 1; split <= 29; ++split) {
      const size_t lengths[] = {1, 255, 256, 279, 280, 281, 288, 413, PKE_BUFFER_SIZE - 1, PKE_BUFFER_SIZE};
      for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
        size_t len = nfc_test_extended(cmd, body, lengths[i], 0);
        for (unsigned case3 = 0; case3 < 2; ++case3) {
          size_t n = nfc_test_exchange(cmd, len - 2 * case3, split, out, sizeof(out));
          assert_memory_equal(out + n - 2, "\x90\x00", 2);
          assert_int_equal(out[0], 0);
          if (!reference_len) {
            memcpy(reference, out, n);
            reference_len = n;
          }
          assert_int_equal(n, reference_len);
          assert_memory_equal(out, reference, n);
          assert_false(apdu_response_source_active());
        }
      }
    }
  }
  // A standalone extended request abandons old short-APDU reassembly before
  // staging new bytes in the same PKE registers.
  const uint8_t chained[] = {0x90, 0x10, 0, 0, 1, CTAP_GET_INFO};
  size_t n = nfc_test_exchange(chained, sizeof(chained), 2, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x90\x00", 2);
  assert_false(apdu_session_can_preempt());
  size_t extended_len = nfc_test_extended(cmd, body, 413, 0);
  n = nfc_test_exchange(cmd, extended_len, 7, out, sizeof(out));
  assert_int_equal(n, reference_len);
  assert_memory_equal(out, reference, n);
  assert_true(apdu_session_can_preempt());
  // A finite Le is a real APDU limit. Internal short chunks are not.
  const uint32_t limits[] = {1, 255, 256, 257, 65535, 65536};
  for (size_t i = 0; i < sizeof(limits) / sizeof(*limits); ++i) {
    size_t len = nfc_test_extended(cmd, body, 413, limits[i]);
    size_t n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
    if (limits[i] >= reference_len - 2) {
      assert_int_equal(n, reference_len);
      assert_memory_equal(out, reference, n);
      continue;
    }
    assert_int_equal(n, limits[i] + 2);
    assert_int_equal(out[n - 2], 0x61);
    assert_memory_equal(out, reference, n - 2);
    const uint8_t more[] = {0, 0xC0, 0, 0, 0, 0, 0}; // Case 2E, Le=65536
    n = nfc_test_exchange(more, sizeof(more), 1, out, sizeof(out));
    assert_int_equal(n, reference_len - limits[i]);
    assert_memory_equal(out, reference + limits[i], n);
  }
  size_t len = nfc_test_extended(cmd, body, sizeof(body), 0);
  n = nfc_test_exchange(cmd, len, 5, out, sizeof(out));
  assert_int_equal(n, 3);
  assert_memory_equal(out, "\x39\x90\x00", 3);
  len = nfc_test_extended(cmd, body, 413, 0);
  n = nfc_test_exchange(cmd, len - 1, 6, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x67\x00", 2);
  for (unsigned le = 0; le < 2; ++le) {
    const uint8_t case2[] = {0x80, 0x10, 0, 0, 0, le ? 0xFF : 0, le ? 0xFF : 0};
    unsigned releases = nfc_test_releases;
    n = nfc_test_exchange(case2, sizeof(case2), 3, out, sizeof(out));
    assert_int_equal(n, 2);
    assert_memory_equal(out, "\x67\x00", 2);
    assert_int_equal(nfc_test_releases, releases);
  }
  // A nonzero length is mandatory when an extended body follows the header.
  const uint8_t zero_lc[] = {0x80, 0x10, 0, 0, 0, 0, 0, 4, 0, 0};
  n = nfc_test_exchange(zero_lc, sizeof(zero_lc), 1, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x67\x00", 2);
  len = nfc_test_extended(cmd, body, 413, 0);
  cmd[len] = 0;
  n = nfc_test_exchange(cmd, len + 1, 6, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x67\x00", 2);
  // The envelope total exceeds uint16_t even though its Lc fits in two bytes.
  static uint8_t largest[UINT16_MAX + 9];
  memset(largest, 0, sizeof(largest));
  memcpy(largest, "\x80\x10\0\0\0\xFF\xFF\x04", 8);
  unsigned before = nfc_test_releases;
  n = nfc_test_exchange(largest, sizeof(largest), 2, out, sizeof(out));
  assert_int_equal(n, 3);
  assert_memory_equal(out, "\x39\x90\x00", 3);
  assert_int_equal(nfc_test_releases, before);
  // Failed acquisition drains the request without clearing another owner.
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  len = nfc_test_extended(cmd, body, 413, 0);
  n = nfc_test_exchange(cmd, len, 3, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x69\x00", 2);
  assert_int_equal(nfc_test_releases, before);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
  // Mid-RX reset is IRQ-only: PKE cannot be reclaimed until main-loop cleanup.
  nfc_test_frame(0x12 | (block_number ^ 1), cmd, 29);
  assert_int_equal(apdu_cmd.pke_backed, 1);
  unsigned releases = nfc_test_releases;
  nfc_test_irq[2] = AUX_IRQ_HALT;
  nfc_test_handler();
  assert_int_equal(nfc_test_releases, releases);
  nfc_test_loop();
  assert_int_equal(nfc_test_releases, releases + 1);
  assert_false(apdu_fido_selected());
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_extended_mc_ga(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  const uint8_t private_key[32] = {1};
  uint8_t cert[600];
  memset(cert, 0xCC, sizeof(cert));
  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, private_key, sizeof(private_key)), 0);
  assert_int_equal(write_file(CTAP_CERT_FILE, cert, 0, sizeof(cert), 1), 0);
  uint8_t body[1200], cmd[1210], out[2048], auth[512];
  credential_id cid;
  size_t auth_len;
  size_t len = build_third_party_payment_make_credential(body, false, true);
  // Extend the semantic exclusion list with foreign credential handles.
  ++body[1];
  uint8_t *p = body + len;
  *p++ = 5;
  *p++ = 0x84;
  credential_id foreign = {0};
  for (unsigned i = 0; i < 4; ++i) {
    *p++ = 0xA2;
    put_cbor_text(&p, "id");
    put_cbor_bytes(&p, (uint8_t *)&foreign, sizeof(foreign));
    put_cbor_text(&p, "type");
    put_cbor_text(&p, "public-key");
  }
  len = nfc_test_extended(cmd, body, p - body, 0);
  assert_true(len > 422);
  size_t n = nfc_test_exchange(cmd, len, 3, out, sizeof(out));
  assert_true(n > sizeof(cert));
  assert_int_equal(out[0], 0);
  assert_memory_equal(out + n - 2, "\x90\x00", 2);
  assert_int_equal(test_cbor_get_auth_data(out, n - 2, MC_RESP_AUTH_DATA, auth, sizeof(auth), &auth_len), 0);
  memcpy(&cid, auth + 37 + AAGUID_SIZE + sizeof(uint16_t), sizeof(cid));
  assert_int_equal(nfc_test_releases, 1);
  len = build_third_party_payment_get_assertion(body, &cid);
  // Unknown, bounded CBOR data also exercises external-source skipping.
  ++body[1];
  p = body + len;
  *p++ = 0x18;
  *p++ = 0x40;
  *p++ = 0x59;
  *p++ = 1;
  *p++ = 0x2C;
  memset(p, 0xEE, 300);
  p += 300;
  len = nfc_test_extended(cmd, body, p - body, 0);
  n = nfc_test_exchange(cmd, len, 1, out, sizeof(out));
  assert_int_equal(out[0], 0);
  assert_memory_equal(out + n - 2, "\x90\x00", 2);
  assert_int_equal(test_cbor_get_auth_data(out, n - 2, GA_RESP_AUTH_DATA, auth, sizeof(auth), &auth_len), 0);
  assert_int_equal(nfc_test_releases, 2);
  assert_false(apdu_response_source_active());
  set_nfc_state(0);
  device_applet_session_clear();
}

#include <psa/crypto.h>

static void nfc_test_descriptor(uint8_t **p, const credential_id *cid) {
  *(*p)++ = 0xA2;
  put_cbor_text(p, "id");
  put_cbor_bytes(p, (const uint8_t *)cid, sizeof(*cid));
  put_cbor_text(p, "type");
  put_cbor_text(p, "public-key");
}

static void nfc_test_pin_auth(uint8_t **p, bool mc, unsigned protocol) {
  uint8_t hash[32] = {0}, auth[32];
  cp_reset_pin_uv_auth_token();
  cp_begin_using_uv_auth_token(true);
  cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA);
  cp_test_authenticate_pin_token(hash, sizeof(hash), auth, protocol);
  *(*p)++ = mc ? MC_REQ_PIN_UV_AUTH_PARAM : GA_REQ_PIN_UV_AUTH_PARAM;
  put_cbor_bytes(p, auth, protocol == 1 ? 16 : 32);
  *(*p)++ = mc ? MC_REQ_PIN_PROTOCOL : GA_REQ_PIN_UV_AUTH_PROTOCOL;
  *(*p)++ = protocol;
}

static size_t nfc_test_mc_body(uint8_t *body, int alg, uint8_t user, bool rk, const credential_id *excluded,
                               unsigned protocol) {
  uint8_t zero[32] = {0}, *p = body;
  credential_id foreign = {0};
  *p++ = CTAP_MAKE_CREDENTIAL;
  *p++ = protocol ? 0xA9 : 0xA7;
  *p++ = MC_REQ_CLIENT_DATA_HASH;
  put_cbor_bytes(&p, zero, sizeof(zero));
  *p++ = MC_REQ_RP;
  *p++ = 0xA1;
  put_cbor_text(&p, "id");
  put_cbor_text(&p, "example.com");
  *p++ = MC_REQ_USER;
  *p++ = 0xA1;
  put_cbor_text(&p, "id");
  put_cbor_bytes(&p, &user, 1);
  *p++ = MC_REQ_PUB_KEY_CRED_PARAMS;
  *p++ = 0x81;
  *p++ = 0xA2;
  put_cbor_text(&p, "alg");
  put_cbor_int(&p, alg);
  put_cbor_text(&p, "type");
  put_cbor_text(&p, "public-key");
  *p++ = MC_REQ_EXCLUDE_LIST;
  *p++ = 0x84;
  for (unsigned i = 0; i < 4; ++i)
    nfc_test_descriptor(&p, i == 3 && excluded ? excluded : &foreign);
  *p++ = MC_REQ_EXTENSIONS;
  *p++ = 0xA2;
  put_cbor_text(&p, "hmac-secret");
  *p++ = 0xF5;
  put_cbor_text(&p, "largeBlobKey");
  *p++ = 0xF5;
  *p++ = MC_REQ_OPTIONS;
  *p++ = 0xA1;
  put_cbor_text(&p, "rk");
  *p++ = rk ? 0xF5 : 0xF4;
  if (protocol) nfc_test_pin_auth(&p, true, protocol);
  assert_true(p - body > 413);
  return p - body;
}

static size_t nfc_test_ga_body(uint8_t *body, const credential_id *cid, int match, unsigned protocol) {
  uint8_t zero[32] = {0}, *p = body;
  credential_id foreign = {0};
  *p++ = CTAP_GET_ASSERTION;
  *p++ = protocol ? 0xA7 : 0xA5;
  *p++ = GA_REQ_RP_ID;
  put_cbor_text(&p, "example.com");
  *p++ = GA_REQ_CLIENT_DATA_HASH;
  put_cbor_bytes(&p, zero, sizeof(zero));
  *p++ = GA_REQ_ALLOW_LIST;
  *p++ = 0x84;
  for (int i = 0; i < 4; ++i)
    nfc_test_descriptor(&p, i == match ? cid : &foreign);
  *p++ = GA_REQ_EXTENSIONS;
  *p++ = 0xA1;
  put_cbor_text(&p, "largeBlobKey");
  *p++ = 0xF5;
  *p++ = GA_REQ_OPTIONS;
  *p++ = 0xA1;
  put_cbor_text(&p, "up");
  *p++ = 0xF5;
  if (protocol) nfc_test_pin_auth(&p, false, protocol);
  assert_true(p - body > 413);
  return p - body;
}

static void nfc_test_verify_signature(const uint8_t *auth, size_t auth_len, const uint8_t client_hash[32],
                                      const uint8_t *der, size_t der_len, const uint8_t pub[65]) {
  assert_true(der_len >= 8 && der[0] == 0x30 && der[1] + 2u == der_len);
  uint8_t raw[64] = {0};
  size_t off = 2;
  for (unsigned i = 0; i < 2; ++i) {
    assert_int_equal(der[off++], 2);
    size_t n = der[off++];
    assert_true(n && off + n <= der_len);
    if (n == 33) {
      assert_int_equal(der[off++], 0);
      --n;
    }
    assert_true(n <= 32);
    memcpy(raw + i * 32 + 32 - n, der + off, n);
    off += n;
  }
  assert_int_equal(off, der_len);
  uint8_t message[256] = {0}, digest[32];
  assert_true(auth_len + 32 <= sizeof(message));
  memcpy(message, auth, auth_len);
  memcpy(message + auth_len, client_hash, 32);
  sha256_raw(message, auth_len + 32, digest);
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_bits(&attrs, 256);
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_HASH);
  psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
  mbedtls_svc_key_id_t key = 0;
  assert_int_equal(psa_import_key(&attrs, pub, 65, &key), PSA_SUCCESS);
  assert_int_equal(psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), digest, 32, raw, 64), PSA_SUCCESS);
  assert_int_equal(psa_destroy_key(key), PSA_SUCCESS);
}

static void nfc_test_assertion_signature(const uint8_t *response, size_t len, const uint8_t pub[65]) {
  test_cbor_view value;
  const uint8_t *auth, *der;
  size_t auth_len, der_len;
  uint8_t hash[32] = {0};
  assert_int_equal(test_cbor_map_lookup_int_key(response + 1, len - 3, GA_RESP_AUTH_DATA, &value), 0);
  assert_int_equal(test_cbor_get_byte_string(value, &auth, &auth_len), 0);
  assert_int_equal(test_cbor_map_lookup_int_key(response + 1, len - 3, GA_RESP_SIGNATURE, &value), 0);
  assert_int_equal(test_cbor_get_byte_string(value, &der, &der_len), 0);
  nfc_test_verify_signature(auth, auth_len, hash, der, der_len, pub);
}

#include "nfc-mc-422.inc"

static void test_nfc_extended_make_credential(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  uint8_t pin[16] = {0}, hash[32], auth[32], cert[600];
  ecc_key_t attestation = {0};
  attestation.pri[0] = 1;
  assert_int_equal(ecc_complete_key(SECP256R1, &attestation), 0);
  uint8_t pub[65] = {4};
  memcpy(pub + 1, attestation.pub, 64);
  memset(cert, 0xCC, sizeof(cert));
  assert_int_equal(write_file(CTAP_CERT_FILE, cert, 0, sizeof(cert), 1), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, attestation.pri, 32), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, PIN_ATTR, pin, sizeof(pin)), 0);
  memset(hash, 0x11, sizeof(hash));
  for (unsigned split = 1; split <= 29; ++split) {
    cp_reset_pin_uv_auth_token();
    cp_begin_using_uv_auth_token(true);
    cp_set_permission(CP_PERMISSION_MC);
    cp_test_authenticate_pin_token(hash, sizeof(hash), auth, 1);
    uint8_t cmd[sizeof(nfc_mc_422)], out[2048];
    memcpy(cmd, nfc_mc_422, sizeof(cmd));
    memcpy(cmd + NFC_MC_422_AUTH_OFFSET, auth, 16);
    unsigned releases = nfc_test_releases;
    // Real hardware can deliver a retry while append_rx still reads the
    // current frame into PKE. Its CRC must not corrupt the clientDataHash.
    nfc_test_retry_on_write = 2;
    size_t n = nfc_test_exchange(cmd, sizeof(cmd), split, out, sizeof(out));
    assert_true(n > sizeof(cert));
    assert_int_equal(out[0], 0);
    assert_memory_equal(out + n - 2, "\x90\x00", 2);
    assert_int_equal(nfc_test_releases, releases + 1);
    test_cbor_view value, stmt;
    const uint8_t *auth_data, *der;
    size_t auth_len, der_len;
    assert_int_equal(test_cbor_map_lookup_int_key(out + 1, n - 3, MC_RESP_AUTH_DATA, &value), 0);
    assert_int_equal(test_cbor_get_byte_string(value, &auth_data, &auth_len), 0);
    assert_true(auth_len >= 37);
    assert_true(auth_data[32] & FLAGS_UV);
    assert_int_equal(test_cbor_map_lookup_int_key(out + 1, n - 3, MC_RESP_ATT_STMT, &stmt), 0);
    assert_int_equal(test_cbor_map_lookup_text_key(stmt, "sig", &value), 0);
    assert_int_equal(test_cbor_get_byte_string(value, &der, &der_len), 0);
    nfc_test_verify_signature(auth_data, auth_len, hash, der, der_len, pub);
    // This same request must be rejected if its authorization is corrupted.
    cmd[NFC_MC_422_AUTH_OFFSET] ^= 1;
    cp_begin_using_uv_auth_token(true);
    n = nfc_test_exchange(cmd, sizeof(cmd), split, out, sizeof(out));
    assert_int_equal(n, 3);
    assert_int_equal(out[0], CTAP2_ERR_PIN_AUTH_INVALID);
  }
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_large_lists_and_continuations(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  const uint8_t private_key[32] = {1};
  uint8_t cert[600];
  memset(cert, 0xCC, sizeof(cert));
  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, private_key, sizeof(private_key)), 0);
  assert_int_equal(write_file(CTAP_CERT_FILE, cert, 0, sizeof(cert), 1), 0);
  uint8_t body[1200], cmd[1210], out[4096], auth[2400], pub[65] = {4};
  credential_id cid[2];
  size_t auth_len;
  uint8_t pin[16] = {0};
  assert_int_equal(write_attr(CTAP_CERT_FILE, PIN_ATTR, pin, sizeof(pin)), 0);
  for (unsigned protocol = 1; protocol <= 2; ++protocol) {
    size_t len = nfc_test_mc_body(body, COSE_ALG_ES256, protocol, true, NULL, protocol);
    len = nfc_test_extended(cmd, body, len, 0);
    size_t n = nfc_test_exchange(cmd, len, protocol, out, sizeof(out));
    assert_int_equal(out[0], 0);
    assert_true(n > sizeof(cert));
    assert_int_equal(test_cbor_get_auth_data(out, n - 2, MC_RESP_AUTH_DATA, auth, sizeof(auth), &auth_len), 0);
    size_t key_start = 37 + AAGUID_SIZE + 2 + sizeof(credential_id);
    memcpy(&cid[protocol - 1], auth + 37 + AAGUID_SIZE + 2, sizeof(credential_id));
    test_cbor_view v;
    const uint8_t *xy;
    size_t xy_len;
    for (int i = 0; i < 2; ++i) {
      assert_int_equal(test_cbor_map_lookup_int_key(auth + key_start, auth_len - key_start, COSE_KEY_LABEL_X - i, &v),
                       0);
      assert_int_equal(test_cbor_get_byte_string(v, &xy, &xy_len), 0);
      assert_int_equal(xy_len, 32);
      memcpy(pub + 1 + i * 32, xy, 32);
    }
    for (int match = -1; match < 4; match += match < 0 ? 1 : 3) {
      len = nfc_test_ga_body(body, &cid[protocol - 1], match, protocol);
      len = nfc_test_extended(cmd, body, len, 0);
      n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
      assert_memory_equal(out + n - 2, "\x90\x00", 2);
      if (match < 0) {
        assert_int_equal(n, 3);
        assert_int_equal(out[0], CTAP2_ERR_NO_CREDENTIALS);
      } else {
        assert_int_equal(out[0], 0);
        nfc_test_assertion_signature(out, n, pub);
        assert_int_equal(test_cbor_map_lookup_int_key(out + 1, n - 3, GA_RESP_LARGE_BLOB_KEY, &v), 0);
        assert_int_equal(test_cbor_get_byte_string(v, &xy, &xy_len), 0);
        assert_int_equal(xy_len, 32);
      }
    }
    len = nfc_test_mc_body(body, COSE_ALG_ES256, 3, true, &cid[protocol - 1], protocol);
    len = nfc_test_extended(cmd, body, len, 0);
    n = nfc_test_exchange(cmd, len, 2, out, sizeof(out));
    assert_int_equal(n, 3);
    assert_int_equal(out[0], CTAP2_ERR_CREDENTIAL_EXCLUDED);
  }
  assert_int_equal(write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0), 0);
  // Discoverable GA and GNA use parsed assertion state after RX PKE was poisoned.
  uint8_t *p = body, hash[32] = {0};
  *p++ = CTAP_GET_ASSERTION;
  *p++ = 0xA2;
  *p++ = GA_REQ_RP_ID;
  put_cbor_text(&p, "example.com");
  *p++ = GA_REQ_CLIENT_DATA_HASH;
  put_cbor_bytes(&p, hash, sizeof(hash));
  size_t len = nfc_test_extended(cmd, body, p - body, 0), n = nfc_test_exchange(cmd, len, 1, out, sizeof(out));
  assert_int_equal(out[0], 0);
  test_cbor_view value;
  uint64_t count;
  assert_int_equal(test_cbor_map_lookup_int_key(out + 1, n - 3, GA_RESP_NUMBER_OF_CREDENTIALS, &value), 0);
  assert_int_equal(test_cbor_get_uint(value, &count), 0);
  assert_int_equal(count, 2);
  body[0] = CTAP_GET_NEXT_ASSERTION;
  len = nfc_test_extended(cmd, body, 1, 0);
  n = nfc_test_exchange(cmd, len, 4, out, sizeof(out));
  assert_int_equal(out[0], 0);
  n = nfc_test_exchange(cmd, len, 4, out, sizeof(out));
  assert_int_equal(out[0], CTAP2_ERR_NOT_ALLOWED);
#if !CTAP_RESTRICT_ALGORITHMS
  // Both public-key and signature responses span many internal short chunks.
  len = nfc_test_mc_body(body, COSE_ALG_ML_DSA_65, 4, true, NULL, 0);
  len = nfc_test_extended(cmd, body, len, 0);
  n = nfc_test_exchange(cmd, len, 5, out, sizeof(out));
  assert_int_equal(out[0], 0);
  assert_true(n > MLDSA_PK_BYTES + sizeof(cert));
  assert_int_equal(test_cbor_get_auth_data(out, n - 2, MC_RESP_AUTH_DATA, auth, sizeof(auth), &auth_len), 0);
  memcpy(&cid[0], auth + 37 + AAGUID_SIZE + 2, sizeof(credential_id));
  len = nfc_test_ga_body(body, &cid[0], 3, 0);
  len = nfc_test_extended(cmd, body, len, 0);
  n = nfc_test_exchange(cmd, len, 6, out, sizeof(out));
  assert_int_equal(out[0], 0);
  assert_true(n > MLDSA_SIG_BYTES);
  const uint8_t *sig;
  size_t sig_len;
  assert_int_equal(test_cbor_map_lookup_int_key(out + 1, n - 3, GA_RESP_SIGNATURE, &value), 0);
  assert_int_equal(test_cbor_get_byte_string(value, &sig, &sig_len), 0);
  assert_int_equal(sig_len, MLDSA_SIG_BYTES);
#endif
  assert_false(apdu_response_source_active());
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_deferred_cancellation(void **unused) {
  (void)unused;
  uint8_t body[1200], cmd[1210], out[1024];
  for (unsigned phase = 0; phase < 5; ++phase) {
    nfc_test_fixture(true);
    memset(body, 0, sizeof(body));
    body[0] = CTAP_GET_INFO;
    size_t body_len = (phase < 2 || phase == 4) ? nfc_test_mc_body(body, COSE_ALG_ES256, 9, true, NULL, 0) : 413;
    size_t len = nfc_test_extended(cmd, body, body_len, 0);
    if (phase == 0) nfc_test_reset_on_read = 12; // inside MC's external CBOR parser
    if (phase == 1) nfc_test_reset_on_release = 1;
    if (phase == 4) {
      nfc_test_reset_on_read = 12;
      nfc_test_read_succeeds_after_reset = true;
    }
    for (size_t off = 0; off < len;) {
      size_t n = MIN(29, len - off);
      if (phase == 3 && off + n == len) nfc_test_reset_on_tx = true;
      nfc_test_frame(0x02 | (block_number ^ 1) | (off + n < len ? PCB_I_CHAINING : 0), cmd + off, n);
      off += n;
    }
    if (phase == 2) {
      assert_true(apdu_response_source_active());
      nfc_test_halt();
    } else if (phase < 2 || phase == 4)
      assert_int_equal(nfc_test_tx_len, 0);
    if (phase == 4) {
      assert_int_equal(apdu_resp.len, 1);
      assert_int_equal(apdu_resp.data[0], CTAP2_ERR_KEEPALIVE_CANCEL);
    }
    assert_true(cleanup_pending);
    assert_int_equal(nfc_test_releases, 1);
    nfc_test_loop();
    assert_false(cleanup_pending);
    assert_false(apdu_fido_selected());
    assert_false(apdu_response_source_active());
    assert_int_equal(transfer_state.size, 0);
    assert_int_equal(transfer_state.sent, 0);
    assert_int_equal(transfer_state.cached_len, 0);
    assert_int_equal(nfc_test_releases, 1);
    body[0] = CTAP_GET_INFO;
    len = nfc_test_extended(cmd, body, 413, 0);
    size_t n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
    assert_int_equal(n, 2);
    assert_memory_equal(out, "\x6A\x82", 2);
    const uint8_t select[] = {0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1, 0};
    n = nfc_test_exchange(select, sizeof(select), 3, out, sizeof(out));
    assert_int_equal(n, 8);
    n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
    assert_int_equal(out[0], 0);
    assert_memory_equal(out + n - 2, "\x90\x00", 2);
  }
  set_nfc_state(0);
  device_applet_session_clear();
}

// Errors must finish inside the current activation, without executing CTAP or
// disturbing another PKE owner. Retry on the same activation after each fault.
static void test_nfc_drain_validation_and_control(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  uint8_t body[PKE_BUFFER_SIZE + 1] = {CTAP_GET_INFO};
  uint8_t cmd[PKE_BUFFER_SIZE + 80], out[2048];
  size_t len, n;
  const size_t lengths[] = {1, 413, PKE_BUFFER_SIZE + 1};
  for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
    for (unsigned field = 2; field <= 3; ++field) {
      len = nfc_test_extended(cmd, body, lengths[i], 0);
      cmd[field] = 1;
      unsigned releases = nfc_test_releases;
      n = nfc_test_exchange(cmd, len, 1, out, sizeof(out));
      assert_int_equal(n, 2);
      assert_memory_equal(out, "\x6A\x86", 2);
      assert_int_equal(nfc_test_releases, releases);
      assert_true(apdu_fido_selected());
    }
  }
  // P1=80 only advertises client polling capability; synchronous completion
  // still returns the final response, without an unimplemented 9100 promise.
  len = nfc_test_extended(cmd, body, 413, 0);
  cmd[2] = 0x80;
  n = nfc_test_exchange(cmd, len, 6, out, sizeof(out));
  assert_int_equal(out[0], 0);
  assert_memory_equal(out + n - 2, "\x90\x00", 2);
  for (unsigned fault = 0; fault < 2; ++fault) {
    if (fault) nfc_test_fail_read = 1;
    else nfc_test_fail_write = 3;
    len = nfc_test_extended(cmd, body, 413, 0);
    unsigned releases = nfc_test_releases;
    n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
    assert_int_equal(n, 2);
    assert_memory_equal(out, "\x69\x00", 2);
    assert_int_equal(nfc_test_releases, releases + 1);
    assert_true(apdu_fido_selected());
    n = nfc_test_exchange(cmd, len, 2, out, sizeof(out));
    assert_int_equal(out[0], 0);
  }
  // Extra bytes span several chained I-blocks, including after the expected
  // Le. The transport must drain them all rather than silence the RF field.
  for (unsigned shape = 0; shape < 4; ++shape) {
    len = nfc_test_extended(cmd, body, shape == 0 ? PKE_BUFFER_SIZE + 1 : 413, 0);
    if (shape < 2) {
      memset(cmd + len, 0xEE, 60);
      len += 60;
    } else if (shape == 2) {
      cmd[4] = 0xFF; // impossible short envelope longer than 261 bytes
    } else {
      cmd[5] = cmd[6] = 0; // invalid zero extended Lc, oversized envelope
    }
    n = nfc_test_exchange(cmd, len, 3, out, sizeof(out));
    assert_int_equal(n, 2);
    assert_memory_equal(out, "\x67\x00", 2);
    assert_true(apdu_fido_selected());
  }
  // A rejected new command closes an unfinished response exactly once.
  // Its old generator must not survive into a later GET RESPONSE or staging.
  static const uint8_t pending[300] = {0};
  stream_ctx = (streaming_source_ctx){.data = pending, .total = sizeof(pending)};
  apdu_response_source_set(sizeof(pending), SW_NO_ERROR, streaming_source_read, streaming_source_close, &stream_ctx);
  len = nfc_test_extended(cmd, body, PKE_BUFFER_SIZE + 1, 0);
  n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
  assert_memory_equal(out, "\x39\x90\x00", n);
  assert_int_equal(stream_ctx.closes, 1);
  assert_false(apdu_response_source_active());
  const uint8_t no_more[] = {0, 0xC0, 0, 0, 0};
  n = nfc_test_exchange(no_more, sizeof(no_more), 3, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x69\x86", 2);
  // A new small extended request abandons an unfinished short APDU chain.
  const uint8_t chained[] = {0x90, 0x10, 0, 0, 1, CTAP_GET_INFO};
  nfc_test_exchange(chained, sizeof(chained), 2, out, sizeof(out));
  len = nfc_test_extended(cmd, body, 1, 0);
  n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
  assert_int_equal(out[0], 0);
  assert_true(apdu_session_can_preempt());
  const uint8_t bad_end[] = {0x80, 0x12, 0, 0};
  n = nfc_test_exchange(bad_end, sizeof(bad_end), 2, out, sizeof(out));
  assert_memory_equal(out, "\x6A\x86", n);
  assert_true(apdu_fido_selected());
  const uint8_t end[] = {0x80, 0x12, 1, 0};
  n = nfc_test_exchange(end, sizeof(end), 2, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x90\x00", 2);
  assert_false(apdu_fido_selected());
  unsigned releases = nfc_test_releases;
  len = nfc_test_extended(cmd, body, 413, 0);
  n = nfc_test_exchange(cmd, len, 5, out, sizeof(out));
  assert_int_equal(n, 2);
  assert_memory_equal(out, "\x6A\x82", 2);
  assert_int_equal(nfc_test_releases, releases);
  const uint8_t select[] = {0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1, 0};
  nfc_test_exchange(select, sizeof(select), 2, out, sizeof(out));
  n = nfc_test_exchange(cmd, len, 5, out, sizeof(out));
  assert_int_equal(out[0], 0);
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_large_blob_stream(void **unused) {
  (void)unused;
  nfc_test_fixture(true);
  uint8_t blob[MAX_FRAGMENT_LENGTH], actual[MAX_FRAGMENT_LENGTH];
  uint8_t body[PKE_BUFFER_SIZE], cmd[PKE_BUFFER_SIZE + 9], out[PKE_BUFFER_SIZE + 32];
  for (size_t i = 0; i < sizeof(blob) - 16; ++i) blob[i] = (uint8_t)i;
  uint8_t hash[32];
  sha256_raw(blob, sizeof(blob) - 16, hash);
  memcpy(blob + sizeof(blob) - 16, hash, 16);
  uint8_t *p;
  size_t len, n;
  for (unsigned protocol = 0; protocol <= 2; ++protocol) {
    p = body;
    *p++ = CTAP_LARGE_BLOBS;
    *p++ = protocol ? 0xA5 : 0xA3;
    *p++ = LB_REQ_SET;
    *p++ = 0x59;
    *p++ = HI(sizeof(blob));
    *p++ = LO(sizeof(blob));
    memcpy(p, blob, sizeof(blob));
    p += sizeof(blob);
    *p++ = LB_REQ_OFFSET;
    *p++ = 0;
    *p++ = LB_REQ_LENGTH;
    put_cbor_int(&p, sizeof(blob));
    uint8_t *auth_ptr = NULL;
    if (protocol) {
      uint8_t pin[16] = {0}, auth[32], message[70];
      assert_int_equal(write_attr(CTAP_CERT_FILE, PIN_ATTR, pin, sizeof(pin)), 0);
      memset(message, 0xFF, 32);
      message[32] = CTAP_LARGE_BLOBS;
      memset(message + 33, 0, 5); // subcommand and little-endian offset
      sha256_raw(blob, sizeof(blob), message + 38);
      cp_reset_pin_uv_auth_token();
      cp_begin_using_uv_auth_token(true);
      cp_set_permission(CP_PERMISSION_LBW);
      cp_test_authenticate_pin_token(message, sizeof(message), auth, protocol);
      *p++ = LB_REQ_PIN_UV_AUTH_PARAM;
      auth_ptr = p + (protocol == 1 ? 1 : 2);
      put_cbor_bytes(&p, auth, protocol == 1 ? 16 : 32);
      *p++ = LB_REQ_PIN_UV_AUTH_PROTOCOL;
      *p++ = protocol;
    }
    len = nfc_test_extended(cmd, body, p - body, 0);
    unsigned releases = nfc_test_releases;
    n = nfc_test_exchange(cmd, len, 1, out, sizeof(out));
    assert_int_equal(n, 3);
    assert_memory_equal(out, "\x00\x90\x00", 3);
    assert_int_equal(nfc_test_releases, releases + 1);
    assert_int_equal(read_file(LB_FILE, actual, 0, sizeof(actual)), sizeof(actual));
    assert_memory_equal(actual, blob, sizeof(blob));
    if (auth_ptr) {
      cmd[7 + (auth_ptr - body)] ^= 1;
      n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
      assert_int_equal(n, 3);
      assert_int_equal(out[0], CTAP2_ERR_PIN_AUTH_INVALID);
      assert_int_equal(read_file(LB_FILE, actual, 0, sizeof(actual)), sizeof(actual));
      assert_memory_equal(actual, blob, sizeof(blob));
    }
  }
  p = body;
  *p++ = CTAP_LARGE_BLOBS;
  *p++ = 0xA2;
  *p++ = LB_REQ_GET;
  put_cbor_int(&p, sizeof(blob));
  *p++ = LB_REQ_OFFSET;
  *p++ = 0;
  len = nfc_test_extended(cmd, body, p - body, 0);
  n = nfc_test_exchange(cmd, len, 3, out, sizeof(out));
  assert_int_equal(n, sizeof(blob) + 8);
  assert_int_equal(out[0], 0);
  assert_memory_equal(out + n - 2, "\x90\x00", 2);
  test_cbor_view value;
  const uint8_t *bytes;
  size_t bytes_len;
  assert_int_equal(test_cbor_map_lookup_int_key(out + 1, n - 3, LB_RESP_CONFIG, &value), 0);
  assert_int_equal(test_cbor_get_byte_string(value, &bytes, &bytes_len), 0);
  assert_int_equal(bytes_len, sizeof(blob));
  assert_memory_equal(bytes, blob, sizeof(blob));
  assert_false(apdu_response_source_active());
  // Short response chaining and both GET RESPONSE classes retain identical
  // content while retries exercise every file-stream refill boundary.
  uint8_t short_cmd[64], joined[PKE_BUFFER_SIZE + 32];
  memcpy(short_cmd, "\x80\x10\0\0", 4);
  short_cmd[4] = p - body;
  memcpy(short_cmd + 5, body, p - body);
  short_cmd[5 + (p - body)] = 0;
  size_t got = nfc_test_exchange(short_cmd, 6 + (p - body), 4, joined, sizeof(joined));
  assert_int_equal(joined[got - 2], 0x61);
  got -= 2;
  for (unsigned cls = 0; apdu_response_source_active(); cls ^= 0x80) {
    uint8_t more[] = {cls, 0xC0, 0, 0, 0};
    size_t part = nfc_test_exchange(more, sizeof(more), 2, joined + got, sizeof(joined) - got);
    got += part - 2;
  }
  assert_int_equal(got, n - 2);
  assert_memory_equal(joined, out, got);
  set_nfc_state(0);
  device_applet_session_clear();
}

// Pad an otherwise semantic request with an unknown outer key up to M. The
// parser must skip the value without retaining transport bytes after close.
static size_t nfc_test_pad_message(uint8_t *body, uint8_t *p) {
  ++body[1];
  *p++ = 0x18;
  *p++ = 0x40;
  *p++ = 0x59;
  size_t padding = PKE_BUFFER_SIZE - (p - body) - 2;
  *p++ = HI(padding);
  *p++ = LO(padding);
  memset(p, 0x55, padding);
  return PKE_BUFFER_SIZE;
}

static void test_nfc_other_ctap_handlers(void **unused) {
  (void)unused;
  uint8_t body[PKE_BUFFER_SIZE], cmd[PKE_BUFFER_SIZE + 9], out[2048];
  for (unsigned protocol = 1; protocol <= 2; ++protocol) {
    for (unsigned handler = 0; handler < 3; ++handler) {
      nfc_test_fixture(true);
      uint8_t pin[16] = {0}, auth[32], message[64];
      assert_int_equal(write_attr(CTAP_CERT_FILE, PIN_ATTR, pin, sizeof(pin)), 0);
      cp_reset_pin_uv_auth_token();
      cp_begin_using_uv_auth_token(true);
      cp_set_permission(CP_PERMISSION_CM | CP_PERMISSION_ACFG);
      uint8_t *p = body, *auth_ptr = NULL;
      if (handler == 0) {
        *p++ = CTAP_CLIENT_PIN;
        *p++ = 0xA2;
        *p++ = CP_REQ_PIN_UV_AUTH_PROTOCOL;
        *p++ = protocol;
        *p++ = CP_REQ_SUB_COMMAND;
        *p++ = CP_CMD_GET_KEY_AGREEMENT;
      } else {
        bool config = handler == 2;
        const uint8_t params[] = {0xA1, 0x18, 0x20, 1}; // unknown subCommandParams key
        size_t message_len = 0;
        if (config) {
          memset(message, 0xFF, 32);
          message_len = 32;
          message[message_len++] = CTAP_CONFIG;
        }
        message[message_len++] = config ? CONFIG_CMD_TOGGLE_ALWAYS_UV : CM_CMD_GET_CREDS_METADATA;
        memcpy(message + message_len, params, sizeof(params));
        message_len += sizeof(params);
        cp_test_authenticate_pin_token(message, message_len, auth, protocol);
        *p++ = config ? CTAP_CONFIG : CTAP_CREDENTIAL_MANAGEMENT;
        *p++ = 0xA4;
        *p++ = 1; // subCommand
        *p++ = config ? CONFIG_CMD_TOGGLE_ALWAYS_UV : CM_CMD_GET_CREDS_METADATA;
        *p++ = 2; // subCommandParams
        memcpy(p, params, sizeof(params));
        p += sizeof(params);
        *p++ = 3; // pinUvAuthProtocol
        *p++ = protocol;
        *p++ = 4; // pinUvAuthParam
        auth_ptr = p + (protocol == 1 ? 1 : 2);
        put_cbor_bytes(&p, auth, protocol == 1 ? 16 : 32);
      }
      size_t body_len = nfc_test_pad_message(body, p);
      size_t len = nfc_test_extended(cmd, body, body_len, 0);
      unsigned released = nfc_test_releases;
      size_t n = nfc_test_exchange(cmd, len, protocol, out, sizeof(out));
      assert_true(n >= 3);
      assert_int_equal(out[0], 0);
      assert_memory_equal(out + n - 2, "\x90\x00", 2);
      assert_int_equal(nfc_test_releases, released + 1);
      if (auth_ptr) {
        // The authorized raw parameters above include an ignored field.
        // A corrupted authorization must fail without applying the command.
        cmd[7 + (auth_ptr - body)] ^= 1;
        n = nfc_test_exchange(cmd, len, 7, out, sizeof(out));
        assert_int_equal(n, 3);
        assert_int_equal(out[0], CTAP2_ERR_PIN_AUTH_INVALID);
      }
    }
  }
  // Unknown containers remain skippable at the required four total levels,
  // while excessive nesting must fail without consuming the device stack.
  nfc_test_fixture(true);
  for (unsigned depth = 3; depth <= 64; depth = 64) {
    uint8_t *p = body;
    *p++ = CTAP_CLIENT_PIN;
    *p++ = 0xA3;
    *p++ = CP_REQ_PIN_UV_AUTH_PROTOCOL;
    *p++ = 1;
    *p++ = CP_REQ_SUB_COMMAND;
    *p++ = CP_CMD_GET_PIN_RETRIES;
    *p++ = 0x18;
    *p++ = 0x40;
    for (unsigned i = 0; i < depth; ++i) *p++ = 0x81;
    *p++ = 0;
    size_t len = nfc_test_extended(cmd, body, p - body, 0);
    size_t n = nfc_test_exchange(cmd, len, 2, out, sizeof(out));
    assert_true(n >= 3);
    assert_int_equal(out[0], depth == 3 ? 0 : CTAP2_ERR_INVALID_CBOR);
    if (depth == 64) break;
  }
  // Short command chaining uses the same logical M limit as standalone
  // extended requests, including the command byte.
  nfc_test_fixture(true);
  memset(body, 0, sizeof(body));
  body[0] = CTAP_GET_INFO;
  for (unsigned extra = 0; extra <= 1; ++extra) {
    for (size_t off = 0; off < PKE_BUFFER_SIZE + extra;) {
      size_t count = MIN(255, PKE_BUFFER_SIZE + extra - off);
      bool last = off + count == PKE_BUFFER_SIZE + extra;
      cmd[0] = last ? 0x80 : 0x90;
      cmd[1] = CTAP_INS_MSG;
      cmd[2] = cmd[3] = 0;
      cmd[4] = count;
      for (size_t i = 0; i < count; ++i) cmd[5 + i] = off + i ? 0 : CTAP_GET_INFO;
      cmd[5 + count] = 0;
      size_t n = nfc_test_exchange(cmd, 6 + count, 4, out, sizeof(out));
      if (!last) {
        assert_int_equal(n, 2);
        assert_memory_equal(out, "\x90\x00", 2);
      } else if (extra) {
        assert_int_equal(n, 3);
        assert_memory_equal(out, "\x39\x90\x00", 3);
      } else {
        assert_true(n > 3);
        assert_int_equal(out[0], 0);
      }
      off += count;
    }
  }
  set_nfc_state(0);
  device_applet_session_clear();
}

static void test_nfc_command_and_frame_errors(void **unused) {
  (void)unused;
  uint8_t body[413] = {0}, cmd[422], out[2048];
  const uint8_t commands[] = {CTAP_SELECTION, CTAP_GET_NEXT_ASSERTION, CTAP_RESET, 0x7F};
  for (size_t i = 0; i < sizeof(commands); ++i) {
    nfc_test_fixture(true);
    body[0] = commands[i];
    size_t len = nfc_test_extended(cmd, body, sizeof(body), 0);
    size_t n = nfc_test_exchange(cmd, len, 6, out, sizeof(out));
    assert_int_equal(n, 3);
    assert_memory_equal(out + 1, "\x90\x00", 2);
    assert_int_equal(nfc_test_releases, 1);
    if (commands[i] == CTAP_SELECTION) assert_int_equal(out[0], 0);
    else if (commands[i] == CTAP_GET_NEXT_ASSERTION) assert_int_equal(out[0], CTAP2_ERR_NOT_ALLOWED);
    else if (commands[i] == 0x7F) assert_int_equal(out[0], CTAP2_ERR_UNHANDLED_REQUEST);
    else assert_true(out[0] == 0 || out[0] == CTAP2_ERR_NOT_ALLOWED);
  }
  const uint8_t invalid_pcb[] = {0x0A, 0x06, 0x22, 0xAA};
  for (size_t i = 0; i < sizeof(invalid_pcb); ++i) {
    nfc_test_fixture(true);
    nfc_test_frame(invalid_pcb[i], body, 1);
    assert_true(cleanup_pending);
    assert_int_equal(nfc_test_tx_len, 0);
    assert_int_equal(nfc_test_releases, 0);
  }
  nfc_test_fixture(true);
  nfc_test_frame(R_ACK, body, 1); // R-blocks have no INF payload
  assert_true(cleanup_pending);
  assert_int_equal(nfc_test_tx_len, 0);
  set_nfc_state(0);
  device_applet_session_clear();
}
