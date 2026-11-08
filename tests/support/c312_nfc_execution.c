// SPDX-License-Identifier: Apache-2.0
// Included after unchanged pinned test_apdu.c; only FS/clock/reader IO seams.
int portable_execution_read_attr_real(const char *path, uint8_t attr, void *buf, lfs_size_t len);
static unsigned portable_execution_remaining, portable_execution_fired;
static uint32_t portable_execution_elapsed;
static uint8_t portable_execution_reply[32], portable_execution_reply_len;
static bool portable_execution_pending, portable_execution_before;

static void portable_execution_tx(void) {
  printf("RF ");
  for (unsigned i = 0; i < nfc_test_tx_len; ++i) printf("%02x", nfc_test_tx[i]);
  putchar('\n');
  if (portable_execution_pending) {
    portable_execution_pending = false;
    if (portable_execution_before) {
      const uint8_t echo[] = {S_WTX, 1, 0, 0}; // Matching WTX echo and chip-checked CRC.
      memcpy(nfc_test_rx, echo, sizeof(echo));
      nfc_test_rx_len = sizeof(echo);
    } else {
      memcpy(nfc_test_rx, portable_execution_reply, portable_execution_reply_len);
      nfc_test_rx_len = portable_execution_reply_len;
    }
    nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
    nfc_test_handler();
  }
  nfc_test_on_tx_enable = portable_execution_tx;
}

int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len) {
  if (portable_execution_remaining && apdu_processing && !cleanup_pending && nfc_test_timer) {
    void (*callback)(void) = nfc_test_timer;
    nfc_test_timer = NULL;
    --portable_execution_remaining;
    ++portable_execution_fired;
    if (portable_execution_before) {
      memcpy(nfc_test_rx, portable_execution_reply, portable_execution_reply_len);
      nfc_test_rx_len = portable_execution_reply_len;
      nfc_test_irq[0] = MAIN_IRQ_RX_DONE;
      nfc_test_handler();
    }
    set_test_tick(device_get_tick() + portable_execution_elapsed);
    portable_execution_pending = true;
    callback();
  }
  return portable_execution_read_attr_real(path, attr, buf, len);
}

static char *portable_execution_fgets(char *line, int size, FILE *stream) {
  while (fgets(line, size, stream)) {
    if (strcmp(line, "EXEC DISARM\n") == 0) {
      portable_execution_remaining = 0;
      printf("EXEC DISARMED\n");
    } else if (strcmp(line, "EXEC STATUS\n") == 0) {
      printf("EXEC %u %u %u\n", portable_execution_remaining, portable_execution_fired, nfc_test_timer == send_wtx);
    } else if (strncmp(line, "EXEC ARM ", 9) == 0 || strncmp(line, "EXEC BEFORE ", 12) == 0) {
      char frame[65];
      portable_execution_before = strncmp(line, "EXEC BEFORE ", 12) == 0;
      assert_int_equal(sscanf(line + (portable_execution_before ? 12 : 9), "%u %u %64s", &portable_execution_elapsed,
                             &portable_execution_remaining, frame), 3);
      assert_true(portable_execution_elapsed >= WTX_PERIOD);
      assert_true(portable_execution_remaining >= 1 && portable_execution_remaining <= 4);
      const size_t characters = strlen(frame);
      assert_true(characters % 2 == 0 && characters >= 6 && characters <= 64);
      portable_execution_reply_len = characters / 2;
      for (unsigned i = 0; i < portable_execution_reply_len; ++i) {
        unsigned byte;
        assert_int_equal(sscanf(frame + 2 * i, "%2x", &byte), 1);
        portable_execution_reply[i] = (uint8_t)byte;
      }
      portable_execution_fired = 0;
      portable_execution_pending = false;
      nfc_test_on_tx_enable = portable_execution_tx;
      printf("EXEC ARMED\n");
    } else {
      return line;
    }
  }
  return NULL;
}
#define fgets portable_execution_fgets
