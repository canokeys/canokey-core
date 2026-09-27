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
uint8_t device_config_is_pass_enabled(void);
uint8_t device_config_is_openpgp_ccid_enabled(void);
uint8_t device_config_is_openpgp_nfc_enabled(void);
uint8_t device_config_is_piv_ccid_enabled(void);
uint8_t device_config_is_piv_nfc_enabled(void);
uint8_t device_config_is_webauthn_enabled(void);
uint8_t device_config_is_initialized(void);
int device_config_mark_initialized(void);
uint8_t device_config_is_nfc_enabled(void);
int device_config_set_nfc_enabled(uint8_t enabled);

/*
 * Fill the 4-byte user-visible serial number. Missing platform serial storage
 * returns all zeros.
 */
void device_config_fill_serial(uint8_t *buf);

#endif // CANOKEY_CORE_INCLUDE_DEVICE_CONFIG_H_
