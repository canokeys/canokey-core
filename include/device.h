#ifndef _DEVICE_H_
#define _DEVICE_H_

#include "common.h"

#define TOUCH_NO 0
#define TOUCH_SHORT 1
#define TOUCH_LONG 2

#define USER_PRESENCE_OK 0
#define USER_PRESENCE_CANCEL 1
#define USER_PRESENCE_TIMEOUT 2

// functions should be implemented by device
void device_delay(int ms);
uint32_t device_get_tick(void);
/**
 * Blink for several time
 * @param sec 0 for infinite
 */
void device_start_blinking(uint8_t sec);
void device_stop_blinking(void);
uint8_t is_nfc(void);

// platform independent functions
uint8_t wait_for_user_presence(void);
void device_loop(void);
uint8_t get_touch_result(void);
void set_touch_result(uint8_t result);
/**
 * Blink for several time
 * @param sec 0 for infinite
 */
void start_blinking(uint8_t sec);
void stop_blinking(void);

#endif // _DEVICE_H_
