// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <crypto-util.h>
#include <ctap.h>
#include <device-config.h>
#include <device.h>
#include <fs.h>
#if ENABLE_APPLET_NDEF
#include <ndef.h>
#endif
#include <oath.h>
#include <openpgp.h>
#include <pass.h>
#include <pin.h>
#include <piv.h>

#define PIN_RETRY_COUNTER 3

static pin_t pin = {.min_length = 6, .max_length = PIN_MAX_LENGTH, .is_validated = 0, .path = "admin-pin"};

static const admin_device_config_t default_cfg = {.led_normally_on = 1, .ndef_en = 1, .webusb_landing_en = 1};

static admin_device_config_t current_config;
static admin_device_config_t admin_get_current_config(void);

__attribute__((weak)) int admin_vendor_specific(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  UNUSED(rapdu);
  return 0;
}

__attribute__((weak)) int admin_vendor_version(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  UNUSED(rapdu);
  return 0;
}

__attribute__((weak)) int admin_vendor_hw_variant(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  UNUSED(rapdu);
  return 0;
}

__attribute__((weak)) int admin_vendor_hw_sn(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  UNUSED(rapdu);
  return 0;
}

__attribute__((weak)) int admin_vendor_nfc_enable(const CAPDU *capdu, RAPDU *rapdu, bool pin_validated) {
  UNUSED(capdu);
  UNUSED(rapdu);
  UNUSED(pin_validated);
  return 0;
}

// Query the platform hook on every read so a platform-backed config is not
// shadowed by core RAM after a vendor/admin APDU updates flash directly.
uint8_t device_config_is_led_normally_on(void) { return admin_get_current_config().led_normally_on; }

uint8_t device_config_is_ndef_enabled(void) { return admin_get_current_config().ndef_en; }

uint8_t device_config_is_webusb_landing_enabled(void) { return admin_get_current_config().webusb_landing_en; }

static admin_device_config_t admin_get_current_config(void) {
  admin_device_config_t cfg = default_cfg;
  if (admin_platform_device_config_read(&cfg) == 0) return cfg;
  return default_cfg;
}

void admin_poweroff(void) { pin.is_validated = 0; }

int admin_install(const uint8_t reset) {
  admin_poweroff();
  // Device config is platform-backed. Core keeps no LittleFS fallback, which
  // avoids two independent sources of truth for LED/NDEF/WebUSB flags.
  if (reset || admin_platform_device_config_read(&current_config) < 0) {
    current_config = default_cfg;
    if (admin_platform_device_config_write(&current_config) < 0) return -1;
  }
  if (reset || get_file_size(pin.path) < 0) {
    if (pin_create(&pin, "123456", 6, PIN_RETRY_COUNTER) < 0) return -1;
  }
  return 0;
}

static int admin_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC == 0) {
    if (pin.is_validated) return 0;
    const int retries = pin_get_retries(&pin);
    if (retries < 0) return -1;
    EXCEPT(pin_get_retry_sw((uint8_t)retries));
  }
  uint8_t ctr;
  const int err = pin_verify(&pin, DATA, LC, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(pin_get_retry_sw(ctr));
  return 0;
}

static int admin_change_pin(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  const int err = pin_update(&pin, DATA, LC);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static int admin_write_sn(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0x04) EXCEPT(SW_WRONG_LENGTH);
  if (admin_platform_serial_write_once(DATA) < 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  return 0;
}

static int admin_read_sn(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LE < 4) EXCEPT(SW_WRONG_LENGTH);

  device_config_fill_serial(RDATA);
  LL = 4;

  return 0;
}

static int admin_config(const CAPDU *capdu, RAPDU *rapdu) {
  current_config = admin_get_current_config();
  switch (P1) {
  case ADMIN_P1_CFG_LED_ON:
    current_config.led_normally_on = P2 & 1;
    break;
  case ADMIN_P1_CFG_NDEF:
    current_config.ndef_en = P2 & 1;
    break;
  case ADMIN_P1_CFG_WEBUSB_LANDING:
    current_config.webusb_landing_en = P2 & 1;
    break;
  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  const int ret = admin_platform_device_config_write(&current_config);
  stop_blinking();
  return ret;
}

static int admin_read_config(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LE < 6) EXCEPT(SW_WRONG_LENGTH);

  const admin_device_config_t cfg = admin_get_current_config();

  RDATA[0] = cfg.led_normally_on;
  RDATA[1] = 0; // reserved
#if ENABLE_APPLET_NDEF
  RDATA[2] = ndef_is_read_only();
#else
  RDATA[2] = 0;
#endif
  RDATA[3] = cfg.ndef_en;
  RDATA[4] = cfg.webusb_landing_en;
  RDATA[5] = 0; // reserved
  LL = 6;

  return 0;
}

static int admin_flash_usage(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LE < 2) EXCEPT(SW_WRONG_LENGTH);

  RDATA[0] = get_fs_usage();
  RDATA[1] = get_fs_size();
  LL = 2;

  return 0;
}

static int admin_write_kbd_keymap(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(rapdu);
  // Payload is 128 ASCII entries, each {modifier, HID usage}. P2 carries a
  // host-defined layout id so tooling can identify what was installed.
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != ADMIN_KBD_KEYMAP_LENGTH) EXCEPT(SW_WRONG_LENGTH);
  return admin_platform_kbd_keymap_write(P2, DATA, LC);
}

static int admin_read_kbd_keymap(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  switch (P2) {
  case ADMIN_P2_KBD_READ_LAYOUT_ID:
    if (LE < 1) EXCEPT(SW_WRONG_LENGTH);
    if (admin_platform_kbd_keymap_read(RDATA, NULL, 0) < 0) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    LL = 1;
    return 0;
  case ADMIN_P2_KBD_READ_KEYMAP: {
    uint8_t layout_id;
    if (LE < ADMIN_KBD_KEYMAP_LENGTH) EXCEPT(SW_WRONG_LENGTH);
    if (admin_platform_kbd_keymap_read(&layout_id, RDATA, ADMIN_KBD_KEYMAP_LENGTH) < 0)
      EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
    LL = ADMIN_KBD_KEYMAP_LENGTH;
    return 0;
  }
  default:
    EXCEPT(SW_WRONG_P1P2);
  }
}

static int admin_clear_kbd_keymap(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(rapdu);
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  return admin_platform_kbd_keymap_clear();
}

static int admin_factory_reset(const CAPDU *capdu, RAPDU *rapdu) {
  int ret;
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 5) EXCEPT(SW_WRONG_LENGTH);
  if (memcmp_s(DATA, "RESET", 5) != 0) EXCEPT(SW_WRONG_DATA);
#ifndef FUZZ
  ret = pin_get_retries(&pin);
  if (ret > 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);

  if (is_nfc()) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  if (strong_user_presence_test() < 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  DBG_MSG("factory reset begins\n");
  ret = openpgp_install(1);
  if (ret < 0) return ret;
  ret = piv_install(1);
  if (ret < 0) return ret;
  ret = oath_install(1);
  if (ret < 0) return ret;
  ret = ctap_install(1);
  if (ret < 0) return ret;
#if ENABLE_APPLET_NDEF
  ret = ndef_install(1);
  if (ret < 0) return ret;
#endif
  ret = pass_install(1);
  if (ret < 0) return ret;
  ret = admin_install(1);
  if (ret < 0) return ret;

  return 0;
}

void device_config_fill_serial(uint8_t *buf) {
  if (admin_platform_serial_read(buf) < 0) memset(buf, 0, 4);
}

int admin_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  int ret = 0;
  switch (INS) {
  case ADMIN_INS_SELECT:
    if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    return 0;

  case ADMIN_INS_READ_VERSION:
    if (P1 > 1 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    if (P1 == 0)
      ret = admin_vendor_version(capdu, rapdu);
    else if (P1 == 1)
      ret = admin_vendor_hw_variant(capdu, rapdu);
    goto done;

  case ADMIN_INS_READ_SN:
    if (P1 > 1 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    if (P1 == 0)
      ret = admin_read_sn(capdu, rapdu);
    else if (P1 == 1)
      ret = admin_vendor_hw_sn(capdu, rapdu);
    goto done;

  case ADMIN_INS_NFC_ENABLE:
    ret = admin_vendor_nfc_enable(capdu, rapdu, pin.is_validated);
    goto done;

  case ADMIN_INS_FACTORY_RESET:
    ret = admin_factory_reset(capdu, rapdu);
    goto done;

  case ADMIN_INS_VERIFY:
    ret = admin_verify(capdu, rapdu);
    goto done;

  default:
    break;
  }

#ifndef FUZZ
  if (!pin.is_validated) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif

  switch (INS) {
  case ADMIN_INS_WRITE_FIDO_PRIVATE_KEY:
    ret = ctap_install_private_key(capdu, rapdu);
    break;
  case ADMIN_INS_WRITE_FIDO_CERT:
    ret = ctap_install_cert(capdu, rapdu);
    break;
  case ADMIN_INS_RESET_OPENPGP:
    ret = openpgp_install(1);
    break;
  case ADMIN_INS_RESET_PIV:
    ret = piv_install(1);
    break;
  case ADMIN_INS_RESET_OATH:
    ret = oath_install(1);
    break;
  case ADMIN_INS_RESET_NDEF:
#if ENABLE_APPLET_NDEF
    ret = ndef_install(1);
#else
    EXCEPT(SW_INS_NOT_SUPPORTED);
#endif
    break;
  case ADMIN_INS_TOGGLE_NDEF_READ_ONLY:
#if ENABLE_APPLET_NDEF
    ret = ndef_toggle_read_only(capdu, rapdu);
#else
    EXCEPT(SW_INS_NOT_SUPPORTED);
#endif
    break;
  case ADMIN_INS_RESET_PASS:
#if ENABLE_PASS
    ret = pass_install(1);
#else
    EXCEPT(SW_INS_NOT_SUPPORTED);
#endif
    break;
  case ADMIN_INS_RESET_CTAP:
    ret = ctap_install(1);
    break;
  case ADMIN_INS_READ_CTAP_SM2_CONFIG:
    ret = ctap_read_sm2_config(capdu, rapdu);
    break;
  case ADMIN_INS_WRITE_CTAP_SM2_CONFIG:
    ret = ctap_write_sm2_config(capdu, rapdu);
    break;
  case ADMIN_INS_CHANGE_PIN:
    ret = admin_change_pin(capdu, rapdu);
    break;
  case ADMIN_INS_WRITE_SN:
    ret = admin_write_sn(capdu, rapdu);
    break;
  case ADMIN_INS_CONFIG:
    ret = admin_config(capdu, rapdu);
    break;
  case ADMIN_INS_FLASH_USAGE:
    ret = admin_flash_usage(capdu, rapdu);
    break;
  case ADMIN_INS_READ_CONFIG:
    ret = admin_read_config(capdu, rapdu);
    break;
  case ADMIN_INS_READ_PASS_CONFIG:
#if ENABLE_PASS
    ret = pass_read_config(capdu, rapdu);
#else
    EXCEPT(SW_INS_NOT_SUPPORTED);
#endif
    break;
  case ADMIN_INS_WRITE_PASS_CONFIG:
#if ENABLE_PASS
    ret = pass_write_config(capdu, rapdu);
#else
    EXCEPT(SW_INS_NOT_SUPPORTED);
#endif
    break;
  case ADMIN_INS_WRITE_KBD_KEYMAP:
    ret = admin_write_kbd_keymap(capdu, rapdu);
    break;
  case ADMIN_INS_READ_KBD_KEYMAP:
    ret = admin_read_kbd_keymap(capdu, rapdu);
    break;
  case ADMIN_INS_CLEAR_KBD_KEYMAP:
    ret = admin_clear_kbd_keymap(capdu, rapdu);
    break;
  case ADMIN_INS_VENDOR_SPECIFIC:
    ret = admin_vendor_specific(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }

done:
  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
