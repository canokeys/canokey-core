// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <crypto-util.h>
#include <ctap.h>
#include <device.h>
#include <fs.h>
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <pass.h>
#include <pin.h>
#include <piv.h>

#define PIN_RETRY_COUNTER 3
#define SN_FILE "sn"
#define CFG_FILE "admin_cfg"

static pin_t pin = {.min_length = 6, .max_length = PIN_MAX_LENGTH, .is_validated = 0, .path = "admin-pin"};

static const admin_device_config_t default_cfg = {.led_normally_on = 1, .ndef_en = 1, .webusb_landing_en = 1};

static admin_device_config_t current_config;

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

uint8_t cfg_is_led_normally_on(void) { return current_config.led_normally_on; }

uint8_t cfg_is_ndef_enable(void) { return current_config.ndef_en; }

uint8_t cfg_is_webusb_landing_enable(void) { return current_config.webusb_landing_en; }

void admin_poweroff(void) { pin.is_validated = 0; }

int admin_install(const uint8_t reset) {
  admin_poweroff();
  if (reset || get_file_size(CFG_FILE) != sizeof(admin_device_config_t)) {
    current_config = default_cfg;
    if (write_file(CFG_FILE, &current_config, 0, sizeof(current_config), 1) < 0) return -1;
  } else {
    if (read_file(CFG_FILE, &current_config, 0, sizeof(current_config)) < 0) return -1;
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
    EXCEPT(SW_PIN_RETRIES + retries);
  }
  uint8_t ctr;
  const int err = pin_verify(&pin, DATA, LC, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_PIN_RETRIES + ctr);
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
  if (get_file_size(SN_FILE) >= 0) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  return write_file(SN_FILE, DATA, 0, LC, 1);
}

static int admin_read_sn(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LE < 4) EXCEPT(SW_WRONG_LENGTH);

  fill_sn(RDATA);
  LL = 4;

  return 0;
}

static int admin_config(const CAPDU *capdu, RAPDU *rapdu) {
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
  const int ret = write_file(CFG_FILE, &current_config, 0, sizeof(current_config), 1);
  stop_blinking();
  return ret;
}

static int admin_read_config(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LE < 5) EXCEPT(SW_WRONG_LENGTH);

  RDATA[0] = current_config.led_normally_on;
  RDATA[1] = 0; // reserved
  RDATA[2] = ndef_get_read_only();
  RDATA[3] = current_config.ndef_en;
  RDATA[4] = current_config.webusb_landing_en;
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
  ret = ndef_install(1);
  if (ret < 0) return ret;
  ret = pass_install(1);
  if (ret < 0) return ret;
  ret = admin_install(1);
  if (ret < 0) return ret;

  return 0;
}

void fill_sn(uint8_t *buf) {
  const int err = read_file(SN_FILE, buf, 0, 4);
  if (err != 4) memset(buf, 0, 4);
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
    ret = ndef_install(1);
    break;
  case ADMIN_INS_TOGGLE_NDEF_READ_ONLY:
    ret = ndef_toggle_read_only(capdu, rapdu);
    break;
  case ADMIN_INS_RESET_PASS:
    ret = pass_install(1);
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
    ret = pass_read_config(capdu, rapdu);
    break;
  case ADMIN_INS_WRITE_PASS_CONFIG:
    ret = pass_write_config(capdu, rapdu);
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
