/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _DEVICE_H_
#define _DEVICE_H_

#include "common.h"
#include "nfc.h"

#define TOUCH_NO 0
#define TOUCH_SHORT 1
#define TOUCH_LONG 2

#define USER_PRESENCE_OK 0
#define USER_PRESENCE_CANCEL 1
#define USER_PRESENCE_TIMEOUT 2

#define WAIT_ENTRY_CCID 0
#define WAIT_ENTRY_CTAPHID 1

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
 * @param expect The current value of variable.
 * @param var    The new value of variable.
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
#if NFC_CHIP == NFC_CHIP_FM11NC
void spi_transmit(const uint8_t *buf, uint8_t len);
void spi_receive(uint8_t *buf, uint8_t len);
#elif NFC_CHIP == NFC_CHIP_FM11NT
void i2c_start(void);
void i2c_stop(void);
void scl_delay(void);
fm_status_t i2c_read_ack(void);
void i2c_send_ack(void);
void i2c_send_nack(void);
fm_status_t i2c_write_byte(uint8_t data);
uint8_t i2c_read_byte(void);
#endif

// only for test
int testmode_emulate_user_presence(void);
int testmode_get_is_nfc_mode(void);
void testmode_set_initial_ticks(uint32_t ticks);
void testmode_inject_error(uint8_t p1, uint8_t p2, uint16_t len, const uint8_t *data);
bool testmode_err_triggered(const char* filename, bool file_wr);

// -----------------------------------------------------------------------------------

// platform independent functions
uint8_t wait_for_user_presence(uint8_t entry);
int strong_user_presence_test(void);
int send_keepalive_during_processing(uint8_t entry);
void device_loop(void);
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
  if (!is_nfc()) start_blinking_interval(sec, 200);
}
static inline void start_quick_blinking(uint8_t sec) {
  if (!is_nfc()) start_blinking_interval(sec, 25);
}
void device_init(void);
void stop_blinking(void);
uint8_t device_is_blinking(void);
bool device_allow_kbd_touch(void);
void fm11_init(void);
fm_status_t fm_read_regs(uint16_t reg, uint8_t *buf, uint8_t len);
fm_status_t fm_write_regs(uint16_t reg, const uint8_t *buf, uint8_t len);
fm_status_t fm_read_eeprom(uint16_t addr, uint8_t *buf, uint8_t len);
fm_status_t fm_write_eeprom(uint16_t addr, const uint8_t *buf, uint8_t len);
fm_status_t fm_read_fifo(uint8_t *buf, uint8_t len);
fm_status_t fm_write_fifo(uint8_t *buf, uint8_t len);
#if NFC_CHIP == NFC_CHIP_FM11NT
fm_status_t fm11nt_read(uint16_t addr, uint8_t *buf, uint8_t len);
fm_status_t fm11nt_write(uint16_t addr, const uint8_t *buf, uint8_t len);
uint8_t fm_crc8(const uint8_t *data, const uint8_t data_length);
#endif

#endif // _DEVICE_H_
