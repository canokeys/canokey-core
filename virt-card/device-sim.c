// SPDX-License-Identifier: Apache-2.0
// implement software-simulated device funtions (LED, Touch, Timer, etc.)
#include "device.h"
#include "admin.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>

// constants for vendor
#include "git-rev.h"

#ifndef HW_VARIANT_NAME
#define HW_VARIANT_NAME "CanoKey Virt-Card"
#endif

static uint32_t initial_ticks = 0;
static char err_trigger_filename[64];

int admin_vendor_version(const CAPDU *capdu, RAPDU *rapdu) {
  LL = strlen(GIT_REV);
  memcpy(RDATA, GIT_REV, LL);
  if (LL > LE) LL = LE;

  return 0;
}

int admin_vendor_hw_variant(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);

  static const char *const hw_variant_str = HW_VARIANT_NAME;
  size_t len = strlen(hw_variant_str);
  memcpy(RDATA, hw_variant_str, len);
  LL = len;
  if (LL > LE) LL = LE;

  return 0;
}

int admin_vendor_hw_sn(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);

  static const char *const hw_sn = "\x00";
  memcpy(RDATA, hw_sn, 1);
  LL = 1;
  if (LL > LE) LL = LE;

  return 0;
}

void device_delay(int tick) {
  int ms = tick * 100; // 100ms per tick in software simulation
  struct timespec spec = {.tv_sec = ms / 1000, .tv_nsec = ms % 1000 * 1000000ll};
  nanosleep(&spec, NULL);
}
uint32_t device_get_tick(void) {
  uint64_t ms, s;
  struct timespec spec;

  clock_gettime(CLOCK_MONOTONIC, &spec);

  s = spec.tv_sec;
  ms = spec.tv_nsec / 1000000;
  return (uint32_t)(s * 1000 + ms) - initial_ticks;
}
void device_disable_irq(void) {}
void device_enable_irq(void) {}
void device_set_timeout(void (*callback)(void), uint16_t timeout) {}
fm_status_t fm_write_eeprom(uint16_t addr, const uint8_t *buf, uint8_t len) { return FM_STATUS_OK; }

int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update) {
  if (*var == expect) {
    *var = update;
    return 0;
  } else {
    return -1;
  }
}

int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking) {
  // Not really working, for test only
  while (*lock) {
    if (!blocking) return -1;
  }
  *lock = 1;
  return 0;
}
void device_spinlock_unlock(volatile uint32_t *lock) { *lock = 0; }

void led_on(void) {}
void led_off(void) {}

int testmode_emulate_user_presence(void) {
  if (!device_is_blinking()) return 0; // user only touches while blinking

#ifndef FUZZ // speed up fuzzing
  int counter = 0;
  FILE *f_cnt = fopen("/tmp/canokey-test-up", "r");
  if (f_cnt != NULL) {
    fscanf(f_cnt, "%d", &counter);
    fclose(f_cnt);
  } else {
    ERR_MSG("Failed to open canokey-test-up for reading\n");
  }
  counter++;
  DBG_MSG("counter=%d\n", counter);
  f_cnt = fopen("/tmp/canokey-test-up", "w");
  if (f_cnt != NULL) {
    fprintf(f_cnt, "%d", counter);
    fclose(f_cnt);
  } else {
    ERR_MSG("Failed to open canokey-test-up for writing\n");
  }
#endif

  set_touch_result(TOUCH_SHORT);
  return 0;
}

int testmode_get_is_nfc_mode(void) {
#ifndef FUZZ // speed up fuzzing
  uint32_t nfc_mode = 0;
  FILE *f_cfg = fopen("/tmp/canokey-test-nfc", "r");
  if (f_cfg == NULL) return -1;
  if (fscanf(f_cfg, "%u", &nfc_mode) < 1) return -1;
  fclose(f_cfg);
  set_nfc_state((uint8_t)nfc_mode);
#endif
  return 0;
}

void testmode_set_initial_ticks(uint32_t ticks) {
  initial_ticks = ticks;
}

void testmode_inject_error(uint8_t p1, uint8_t p2, uint16_t len, const uint8_t *data)
{
  DBG_MSG("%hhu %hhu ", p1, p2);
  PRINT_HEX(data, len);
  if (!p1 && !p2) {
    if (len < sizeof(err_trigger_filename)) {
      memcpy(err_trigger_filename, data, len);
      err_trigger_filename[len] = 0;
    }
  }
}

bool testmode_err_triggered(const char* filename, bool file_wr)
{
  bool ret = (strcmp(filename, err_trigger_filename) == 0);
  if (ret) err_trigger_filename[0] = 0;
  return ret;
}
