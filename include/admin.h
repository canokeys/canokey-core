/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_ADMIN_ADMIN_H_
#define CANOKEY_CORE_ADMIN_ADMIN_H_

#include <apdu.h>

#define ADMIN_INS_WRITE_FIDO_PRIVATE_KEY 0x01
#define ADMIN_INS_WRITE_FIDO_CERT 0x02
#define ADMIN_INS_RESET_OPENPGP 0x03
#define ADMIN_INS_RESET_PIV 0x04
#define ADMIN_INS_RESET_OATH 0x05
#define ADMIN_INS_RESET_NDEF 0x07
#define ADMIN_INS_TOGGLE_NDEF_READ_ONLY 0x08
#define ADMIN_INS_RESET_CTAP 0x09
#define ADMIN_INS_READ_CTAP_SM2_CONFIG 0x11
#define ADMIN_INS_WRITE_CTAP_SM2_CONFIG 0x12
#define ADMIN_INS_RESET_PASS 0x13
#define ADMIN_INS_NFC_ENABLE 0x14
#define ADMIN_INS_VERIFY 0x20
#define ADMIN_INS_CHANGE_PIN 0x21
#define ADMIN_INS_WRITE_SN 0x30
#define ADMIN_INS_READ_VERSION 0x31
#define ADMIN_INS_READ_SN 0x32
#define ADMIN_INS_CONFIG 0x40
#define ADMIN_INS_FLASH_USAGE 0x41
#define ADMIN_INS_READ_CONFIG 0x42
#define ADMIN_INS_READ_PASS_CONFIG 0x43
#define ADMIN_INS_WRITE_PASS_CONFIG 0x44
#define ADMIN_INS_FACTORY_RESET 0x50
#define ADMIN_INS_SELECT 0xA4
#define ADMIN_INS_VENDOR_SPECIFIC 0xFF

#define ADMIN_P1_CFG_LED_ON 0x01
#define ADMIN_P1_CFG_NDEF 0x04
#define ADMIN_P1_CFG_WEBUSB_LANDING 0x05

typedef struct {
    uint32_t led_normally_on : 1;
    uint32_t ndef_en : 1;
    uint32_t webusb_landing_en : 1;
} __packed admin_device_config_t;

void admin_poweroff(void);
int admin_install(uint8_t reset);
int admin_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_specific(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_version(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_hw_variant(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_hw_sn(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_nfc_enable(const CAPDU *capdu, RAPDU *rapdu, bool pin_validated);

uint8_t cfg_is_led_normally_on(void);
uint8_t cfg_is_ndef_enable(void);
uint8_t cfg_is_webusb_landing_enable(void);

#endif // CANOKEY_CORE_ADMIN_ADMIN_H_
