// SPDX-License-Identifier: Apache-2.0
// Actual CCID assembly/source adapter, with a mock core and PKE register file.
#include "core.h"
#include <assert.h>
#include <ccid.h>
#include <pke.h>
#include <usb_device.h>
#include <usbd_ccid.h>

USBD_HandleTypeDef usb_device;
static uint8_t pke[1024], packet[64], reply[268], wire[310];
static uint32_t now;
static unsigned acquired, closed, executed, reply_length;
static uint8_t held, hid_busy, write_failure;
static int32_t begin_result = 291;
uint32_t device_get_tick(void) { return now; }
uint8_t ck_hid_busy(void) { return hid_busy; }
void USBD_CCID_ServiceReceive(void) {}
void ck_core_reset(void) { assert(!held); }
size_t pke_buffer_size(void) { return sizeof(pke); }
int pke_buffer_acquire(uint8_t owner) {
  assert(owner == PKE_BUFFER_OWNER_CTAP && !held && !hid_busy);
  held = 1;
  acquired++;
  return 0;
}
int pke_buffer_clear(void) {
  assert(held);
  memset(pke, 0, sizeof(pke));
  return 0;
}
int pke_buffer_release(uint8_t owner) {
  assert(owner == PKE_BUFFER_OWNER_CTAP && held);
  held = 0;
  closed++;
  return 0;
}
int pke_buffer_write(size_t at, const void *data, size_t n) {
  assert(held && at + n <= sizeof(pke));
  if (write_failure) return -1;
  memcpy(pke + at, data, n);
  return 0;
}
int pke_buffer_read(size_t at, void *data, size_t n) {
  assert(held && at + n <= sizeof(pke));
  memcpy(data, pke + at, n);
  return 0;
}
int32_t ck_core_extended_begin(const uint8_t prefix[7], size_t total) {
  assert(!held && total == 300);
  const uint8_t expected[] = {0x80, 0x10, 0, 0, 0, 1, 0x23};
  assert(memcmp(prefix, expected, 7) == 0);
  return begin_result;
}
int32_t ck_core_exchange_ccid_source(size_t total, uint8_t *out, size_t capacity) {
  assert(held && total == 300 && capacity == 258);
  // Read across prefix/body and body/Le boundaries, with monotonic offsets.
  uint8_t chunk[64];
  for (size_t at = 0; at < total;) {
    size_t n = MIN(sizeof(chunk), total - at);
    assert(ck_ccid_source_read(at, chunk, n) == 0);
    assert(memcmp(chunk, wire + 10 + at, n) == 0);
    at += n;
  }
  assert(ck_ccid_source_read(total, chunk, 1) == -1);
  ck_ccid_source_close();
  assert(!held); // applet execution must start after source release
  executed++;
  out[0] = 1;
  out[1] = 0x90;
  out[2] = 0;
  return 3;
}
int32_t ck_core_exchange(uint8_t owner, const uint8_t *in, size_t n, uint8_t *out, size_t capacity) {
  assert(owner == 1 && n == 5 && capacity == 258 && in[1] == 0xc0 && !held);
  out[0] = 0x69;
  out[1] = 0x86;
  return 2;
}
uint8_t CCID_Response_SendData(USBD_HandleTypeDef *d, const uint8_t *data, uint16_t n, uint8_t extension) {
  assert(d == &usb_device && !extension && n <= sizeof(reply));
  memcpy(reply, data, n);
  reply_length = n;
  CCID_InFinished(0);
  return USBD_OK;
}
static void feed(const uint8_t *data, size_t n) {
  assert(n <= sizeof(packet) && ck_ccid_rx_ready());
  memcpy(packet, data, n);
  CCID_OutEvent(packet, (uint8_t)n);
  assert(!ck_ccid_rx_ready());
  CCID_Loop();
}
static void rest(size_t at) {
  while (at < sizeof(wire)) {
    size_t n = MIN(sizeof(packet), sizeof(wire) - at);
    feed(wire + at, n);
    at += n;
  }
}
static void restart(void) {
  CCID_Init();
  uint8_t power[] = {0x62, 0, 0, 0, 0, 0, 0x34, 0, 0, 0};
  memcpy(packet, power, sizeof(power));
  CCID_OutEvent(packet, sizeof(power)); // new connection arrives before cleanup
  CCID_Loop();
  assert(!ck_ccid_rx_ready());
  CCID_Loop();
  assert(reply[0] == 0x80 && reply[6] == 0x34 && reply_length > 10);
}
int main(void) {
  // dwLength=300 is LE, extended Lc=291 and Le=0x0123 are BE.
  const uint8_t prefix[] = {0x6f, 0x2c, 1, 0, 0, 0, 0x56, 0, 0, 0, 0x80, 0x10, 0, 0, 0, 1, 0x23};
  memcpy(wire, prefix, sizeof(prefix));
  for (unsigned i = 0; i < 291; i++)
    wire[17 + i] = (uint8_t)(i * 37);
  wire[308] = 1;
  wire[309] = 0x23;
  restart();
  feed(wire, 3);
  feed(wire + 3, 8);
  feed(wire + 11, 6);
  assert(held && acquired == 1);
  rest(17);
  assert(executed == 1 && closed == 1);
  const uint8_t expected[] = {0x80, 3, 0, 0, 0, 0, 0x56, 0, 0, 0, 1, 0x90, 0};
  assert(reply_length == sizeof(expected) && memcmp(reply, expected, sizeof(expected)) == 0);

  feed(wire, 64);
  assert(held);
  now += 2000;
  CCID_Loop();
  assert(!held && closed == 2 && reply[8] == SLOTERROR_BAD_DWLENGTH);
  feed(wire, 64);
  assert(held);
  restart();
  assert(!held && closed == 3);
  write_failure = 1;
  rest(0);
  assert(!held && closed == 4 && executed == 1 && reply[8] == SLOTERROR_HW_ERROR);
  write_failure = 0;
  begin_result = -0x6700;
  rest(0);
  assert(acquired == 4 && reply[10] == 0x67 && reply[11] == 0);
  begin_result = 291;

  hid_busy = 1;
  feed(wire, 64); // queue while HID holds the shared scratch
  assert(!ck_ccid_rx_ready() && !held);
  hid_busy = 0;
  CCID_Loop();
  assert(held);
  rest(64);
  assert(closed == 5 && executed == 2);

  uint8_t short_apdu[] = {0x6f, 5, 0, 0, 0, 0, 0x78, 0, 0, 0, 0, 0xc0, 0, 0, 0};
  feed(short_apdu, sizeof(short_apdu));
  assert(reply[6] == 0x78 && reply[10] == 0x69 && reply[11] == 0x86);
  feed(wire, 64);
  now += 2000;
  feed(wire + 64, 64); // a late queued fragment must not revive the request
  assert(!held && closed == 6 && executed == 2 && reply[8] == SLOTERROR_BAD_DWLENGTH);
}
