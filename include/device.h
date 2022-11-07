/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _DEVICE_H_
#define _DEVICE_H_

#include "common.h"

#define TOUCH_NO 0
#define TOUCH_SHORT 1
#define TOUCH_LONG 2

#define USER_PRESENCE_OK 0
#define USER_PRESENCE_CANCEL 1
#define USER_PRESENCE_TIMEOUT 2

#define WAIT_ENTRY_CCID 0
#define WAIT_ENTRY_CTAPHID 1

// functions should be implemented by device
/**
 * Delay processing for specific milliseconds
 *
 * @param ms Time to delay
 */
void device_delay(int ms);
uint32_t device_get_tick(void);

/**
 * Get a spinlock.
 *
 * @param lock      The lock handler, which should be pointed to a uint32_t variable.
 * @param blocking  If we should wait the lock to be released.
 *
 * @return 0 for locking successfully, -1 for failure.
 */
int device_spinlock_lock(volatile uint32_t *lock, uint32_t blocking);

/**
 * Unlock the specific handler.
 *
 * @param lock  The lock handler.
 */
void device_spinlock_unlock(volatile uint32_t *lock);

/**
 * Update the value of a variable atomically.
 *
 * @param var    The address of variable to update.
 * @param expect The current value of variable.
 * @param var    The new value of variable.
 */
int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update);

void led_on(void);
void led_off(void);
void device_set_timeout(void (*callback)(void), uint16_t timeout);
void fm_nss_low(void);
void fm_nss_high(void);
void fm_transmit(uint8_t *buf, uint8_t len);
void fm_receive(uint8_t *buf, uint8_t len);

// only for test
int testmode_emulate_user_presence(void);
int testmode_get_is_nfc_mode(void);

// platform independent functions
uint8_t wait_for_user_presence(uint8_t entry);
int strong_user_presence_test(void);
void device_loop(uint8_t has_touch);
uint8_t is_nfc(void);
void set_nfc_state(uint8_t state);
uint8_t get_touch_result(void);
void set_touch_result(uint8_t result);
void device_update_led(void);
/**
 * Blink for several time
 * @param sec duration, 0 for infinite
 * @param interval controls blinking frequency
 */
void start_blinking_interval(uint8_t sec, uint32_t interval);
static inline void start_blinking(uint8_t sec) {
  if (is_nfc()) start_blinking_interval(sec, 200);
}
void stop_blinking(void);
uint8_t device_is_blinking(void);
void fm_read_reg(uint8_t reg, uint8_t *buf, uint8_t len);
void fm_write_reg(uint8_t reg, uint8_t *buf, uint8_t len);
void fm_read_eeprom(uint16_t addr, uint8_t *buf, uint8_t len);
void fm_write_eeprom(uint16_t addr, uint8_t *buf, uint8_t len);
void fm_read_fifo(uint8_t *buf, uint8_t len);
void fm_write_fifo(uint8_t *buf, uint8_t len);

#endif // _DEVICE_H_
