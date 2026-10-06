/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdbool.h>

#include "common.h"
#include "nfc.h"

#define TOUCH_NO 0
#define TOUCH_SHORT 1
#define TOUCH_LONG 2

typedef enum {
  FM_STATUS_OK = 0,
  FM_STATUS_NACK = 1,
} fm_status_t;

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
 * @param expect The value required for the update to succeed.
 * @param update The new value of the variable.
 */
int device_atomic_compare_and_swap(volatile uint32_t *var, uint32_t expect, uint32_t update);

void led_on(void);
void led_off(void);
void device_set_timeout(void (*callback)(void), uint16_t timeout);

// NFC related
/**
 * Enable FM chip by pull down CSN
 */
void fm_csn_low(void);

/**
 * Disable FM chip by pull up CSN
 */
void fm_csn_high(void);
#if NFC_CHIP == NFC_CHIP_FM11NT
void i2c_start(void);
void i2c_stop(void);
void i2c_bus_recover(void);
void scl_delay(void);
fm_status_t i2c_read_ack(void);
void i2c_send_ack(void);
void i2c_send_nack(void);
fm_status_t i2c_write_byte(uint8_t data);
uint8_t i2c_read_byte(void);
#endif

// only for test
#define TESTMODE_ERR_WRITE 0
#define TESTMODE_ERR_READ 1

void testmode_inject_error(uint8_t p1, uint8_t p2, uint16_t len, const uint8_t *data);
bool testmode_err_triggered(const char *filename, bool file_wr);

// -----------------------------------------------------------------------------------

#if ENABLE_NFC
uint8_t is_nfc(void);
#else
static inline uint8_t is_nfc(void) { return 0; }
#endif

#endif // _DEVICE_H_
