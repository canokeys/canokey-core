/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_ADMIN_ADMIN_H_
#define CANOKEY_CORE_ADMIN_ADMIN_H_

#include <apdu.h>
#include <stdbool.h>
#include <stdint.h>

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

/*
 * ADMIN_INS_READ_VERSION:
 *   P1 = 0x00: platform/vendor firmware version
 *   P1 = 0x01: platform/vendor hardware variant
 *   P1 = ADMIN_P1_READ_CORE_COMMIT: canokey-core git commit id
 */
#define ADMIN_P1_READ_CORE_COMMIT 0x02

/**
 * ADMIN_INS_FLASH_USAGE:
 *   Read-only and intentionally available before admin PIN verification.
 *   P1 = ADMIN_FLASH_USAGE_TOTAL, P2 = 0, Le >= 2:
 *        returns {used_kib, total_kib}.
 *   P1 = ADMIN_FLASH_USAGE_APPLETS, P2 = 0, Le >= ADMIN_APPLET_USAGE_RESPONSE_LENGTH:
 *        returns ADMIN_APPLET_USAGE_COUNT records:
 *        {applet_id, flags, logical_bytes_be32}. logical_bytes is the sum of
 *        known LittleFS file payloads and user-attribute payloads owned by the
 *        applet. It excludes LittleFS metadata/copy-on-write block overhead,
 *        which is reported in ADMIN_APPLET_USAGE_ID_SYSTEM.
 *
 * flags bit 0 means one or more known paths/attrs were absent. Missing entries
 * are counted as zero because disabled or freshly-reset applets may not have all
 * optional files yet.
 */
#define ADMIN_FLASH_USAGE_TOTAL 0x00
#define ADMIN_FLASH_USAGE_APPLETS 0x01
#define ADMIN_APPLET_USAGE_RECORD_LENGTH 6
#define ADMIN_APPLET_USAGE_COUNT 8
#define ADMIN_APPLET_USAGE_RESPONSE_LENGTH (ADMIN_APPLET_USAGE_COUNT * ADMIN_APPLET_USAGE_RECORD_LENGTH)
#define ADMIN_APPLET_USAGE_FLAG_MISSING 0x01

#define ADMIN_APPLET_USAGE_ID_SYSTEM 0x00
#define ADMIN_APPLET_USAGE_ID_ADMIN 0x01
#define ADMIN_APPLET_USAGE_ID_OPENPGP 0x02
#define ADMIN_APPLET_USAGE_ID_PIV 0x03
#define ADMIN_APPLET_USAGE_ID_OATH 0x04
#define ADMIN_APPLET_USAGE_ID_CTAP 0x05
#define ADMIN_APPLET_USAGE_ID_NDEF 0x06
#define ADMIN_APPLET_USAGE_ID_PASS 0x07

/**
 * @brief KBD keymap admin APDUs.
 *
 * The keymap is a fixed 128-entry ASCII table. Entry N maps ASCII code N to
 * two bytes: {HID modifier, HID usage}. A stored table is authoritative for
 * KBDHID output; usage 0 means "skip this character" instead of falling back
 * to the built-in QWERTY map.
 *
 * ADMIN_INS_WRITE_KBD_KEYMAP:
 *   P1 = 0x00
 *   P2 = host-defined layout id
 *   Lc = ADMIN_KBD_KEYMAP_LENGTH
 *   Data = 128 consecutive {modifier, usage} entries
 *
 * ADMIN_INS_READ_KBD_KEYMAP:
 *   P1 = 0x00
 *   P2 = ADMIN_P2_KBD_READ_LAYOUT_ID: Le >= 1, returns one layout-id byte
 *   P2 = ADMIN_P2_KBD_READ_KEYMAP: Le >= ADMIN_KBD_KEYMAP_LENGTH, returns the
 *        128-entry {modifier, usage} table without the layout id
 *
 * ADMIN_INS_CLEAR_KBD_KEYMAP:
 *   P1 = 0x00, P2 = 0x00, Lc = 0
 */
#define ADMIN_INS_WRITE_KBD_KEYMAP 0x45
#define ADMIN_INS_READ_KBD_KEYMAP 0x46
#define ADMIN_INS_CLEAR_KBD_KEYMAP 0x47
#define ADMIN_INS_FACTORY_RESET 0x50
#define ADMIN_INS_SELECT 0xA4
#define ADMIN_INS_VENDOR_SPECIFIC 0xFF

#define ADMIN_KBD_ASCII_COUNT 128
#define ADMIN_KBD_KEYMAP_ENTRY_SIZE 2
#define ADMIN_KBD_KEYMAP_LENGTH (ADMIN_KBD_ASCII_COUNT * ADMIN_KBD_KEYMAP_ENTRY_SIZE)
#define ADMIN_P2_KBD_READ_LAYOUT_ID 0x00
#define ADMIN_P2_KBD_READ_KEYMAP 0x01

#define ADMIN_P1_CFG_LED_ON 0x01
#define ADMIN_P1_CFG_NDEF 0x04
#define ADMIN_P1_CFG_WEBUSB_LANDING 0x05
#define ADMIN_P1_CFG_FEATURE 0x06

#define ADMIN_FEATURE_PASS_BIT 0x00
#define ADMIN_FEATURE_OPENPGP_CCID_BIT 0x01
#define ADMIN_FEATURE_OPENPGP_NFC_BIT 0x02
#define ADMIN_FEATURE_PIV_CCID_BIT 0x03
#define ADMIN_FEATURE_PIV_NFC_BIT 0x04
#define ADMIN_FEATURE_WEBAUTHN_BIT 0x05
#define ADMIN_FEATURE_COUNT 0x06
#define ADMIN_FEATURE_PASS (1u << ADMIN_FEATURE_PASS_BIT)
#define ADMIN_FEATURE_OPENPGP_CCID (1u << ADMIN_FEATURE_OPENPGP_CCID_BIT)
#define ADMIN_FEATURE_OPENPGP_NFC (1u << ADMIN_FEATURE_OPENPGP_NFC_BIT)
#define ADMIN_FEATURE_PIV_CCID (1u << ADMIN_FEATURE_PIV_CCID_BIT)
#define ADMIN_FEATURE_PIV_NFC (1u << ADMIN_FEATURE_PIV_NFC_BIT)
#define ADMIN_FEATURE_WEBAUTHN (1u << ADMIN_FEATURE_WEBAUTHN_BIT)
#define ADMIN_FEATURE_MASK                                                                                           \
  (ADMIN_FEATURE_PASS | ADMIN_FEATURE_OPENPGP_CCID | ADMIN_FEATURE_OPENPGP_NFC | ADMIN_FEATURE_PIV_CCID |            \
   ADMIN_FEATURE_PIV_NFC | ADMIN_FEATURE_WEBAUTHN)

typedef struct {
  uint32_t led_normally_on : 1;
  uint32_t ndef_en : 1;
  uint32_t webusb_landing_en : 1;
  uint32_t pass_en : 1;
  uint32_t openpgp_ccid_en : 1;
  uint32_t openpgp_nfc_en : 1;
  uint32_t piv_ccid_en : 1;
  uint32_t piv_nfc_en : 1;
  uint32_t webauthn_en : 1;
} __packed admin_device_config_t;

void admin_poweroff(void);
int admin_install(uint8_t reset);
int admin_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_specific(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_version(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_hw_variant(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_hw_sn(const CAPDU *capdu, RAPDU *rapdu);
int admin_vendor_nfc_enable(const CAPDU *capdu, RAPDU *rapdu, bool pin_validated);

/*
 * Core config accessors backed by the platform config page.
 */
int admin_platform_device_config_read(admin_device_config_t *cfg);
int admin_platform_device_config_write(const admin_device_config_t *cfg);
int admin_platform_serial_read(uint8_t *buf);
int admin_platform_serial_write_once(const uint8_t *buf);
/*
 * KBD keymap admin commands use a 128-entry ASCII table. Each entry is
 * {modifier, HID usage}; a valid platform table is authoritative, and usage 0
 * means the character is intentionally skipped.
 */
int admin_platform_kbd_keymap_write(uint8_t layout_id, const uint8_t *keymap, uint16_t len);
int admin_platform_kbd_keymap_read(uint8_t *layout_id, uint8_t *keymap, uint16_t len);
int admin_platform_kbd_keymap_clear(void);

#endif // CANOKEY_CORE_ADMIN_ADMIN_H_
