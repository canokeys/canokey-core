/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_DEVICE_CONFIG_H_
#define CANOKEY_CORE_INCLUDE_DEVICE_CONFIG_H_

#include <stdint.h>

/*
 * Runtime device-config readers used outside the admin applet. Writers and
 * platform persistence hooks stay in admin.h because they are admin commands.
 */
uint8_t device_config_is_led_normally_on(void);
uint8_t device_config_is_ndef_enabled(void);
uint8_t device_config_is_webusb_landing_enabled(void);

/*
 * Fill the 4-byte user-visible serial number. Missing platform serial storage
 * returns all zeros.
 */
void device_config_fill_serial(uint8_t *buf);

#endif // CANOKEY_CORE_INCLUDE_DEVICE_CONFIG_H_
