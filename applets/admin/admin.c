// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <canokey-core-git-rev.h>
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

#define ADMIN_PIN_FILE "admin-pin"

typedef struct {
  uint8_t first_source;
  uint8_t source_count;
  uint8_t id;
} admin_applet_usage_def_t;

enum {
  ADMIN_ATTR_NONE,
  ADMIN_ATTR_KEY,
  ADMIN_ATTR_OPENPGP_DATA,
  ADMIN_ATTR_PIV_PIN,
  ADMIN_ATTR_PIV_ADMIN_KEY,
  ADMIN_ATTR_PIV_DO_META,
  ADMIN_ATTR_OATH,
  ADMIN_ATTR_CTAP_CERT,
  ADMIN_ATTR_CTAP_DC,
};

static pin_t pin = {.min_length = 6, .max_length = PIN_MAX_LENGTH, .is_validated = 0, .path = ADMIN_PIN_FILE};

// Logical usage manifests for ADMIN_FLASH_USAGE_APPLETS. Keep these in sync
// with applet-owned LittleFS paths and user attributes. The SYSTEM record
// reports LittleFS physical usage that cannot be attributed to these payloads.
static const uint8_t key_attrs[] = {0x00, 0x01};
static const uint8_t openpgp_data_attrs[] = {0x5E, 0x5B, 0x2D, 0x35, 0xC4, 0x93, 0xD6, 0xD7, 0xD8, 0xC1, 0xC2,
                                             0xC3, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB};

static const uint8_t piv_pin_attrs[] = {0x00, 0x01, 0x81};
static const uint8_t piv_admin_key_attrs[] = {0x81};
static const uint8_t piv_do_meta_attrs[] = {0x90, 0x91, 0x92, 0x93};

static const uint8_t oath_attrs[] = {0x02, 0x03};

static const uint8_t ctap_cert_attrs[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static const uint8_t ctap_dc_attrs[] = {0x00};

static const char *const usage_sources[] = {
    ADMIN_PIN_FILE,
    "pgp-data", "pgp-sigk", "pgp-deck", "pgp-autk", "pgp-sigc", "pgp-decc", "pgp-autc", "pgp-pw1",
    "pgp-pw3", "pgp-rc",
    "oath",
    "ctap_cert", "ctap_dc", "ctap_dm", "ctap_lb", "ctap_lbt", "ctap_mpr",
    "E103", "NDEF",
    "pass",
};

static const char *const piv_usage_fixed_sources[] = {
    "piv-chu", "piv-ccc", "piv-pi",  "piv-fig", "piv-face", "piv-sec",
    "piv-kh",  "piv-iris", "piv-do", "piv-pin", "piv-puk",
};

#define ADMIN_ATTR_PAIR(low, high) ((low) | ((high) << 4u))
static const uint8_t usage_attr_kinds[] = {
    ADMIN_ATTR_PAIR(ADMIN_ATTR_KEY, ADMIN_ATTR_OPENPGP_DATA),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_KEY, ADMIN_ATTR_KEY),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_KEY, ADMIN_ATTR_NONE),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_NONE),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_NONE),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_OATH),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_CTAP_CERT, ADMIN_ATTR_CTAP_DC),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_NONE),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_NONE),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_NONE),
    ADMIN_ATTR_PAIR(ADMIN_ATTR_NONE, ADMIN_ATTR_NONE),
};
_Static_assert(sizeof(usage_attr_kinds) * 2u >= sizeof(usage_sources) / sizeof(usage_sources[0]),
               "Every flash-usage source needs an attribute kind");

static const admin_applet_usage_def_t applet_usage_defs[] = {
    {0, 1, ADMIN_APPLET_USAGE_ID_ADMIN},       {1, 10, ADMIN_APPLET_USAGE_ID_OPENPGP},
    {0, 0, ADMIN_APPLET_USAGE_ID_PIV},         {11, 1, ADMIN_APPLET_USAGE_ID_OATH},
    {12, 6, ADMIN_APPLET_USAGE_ID_CTAP},       {18, 2, ADMIN_APPLET_USAGE_ID_NDEF},
    {20, 1, ADMIN_APPLET_USAGE_ID_PASS},
};

static const admin_device_config_t default_cfg = {
    .led_normally_on = 1,
    .ndef_en = 1,
    .webusb_landing_en = 1,
    .pass_en = 1,
    .openpgp_ccid_en = 1,
    .openpgp_nfc_en = 1,
    .piv_ccid_en = 1,
    .piv_nfc_en = 1,
    .webauthn_en = 1,
};

static admin_device_config_t current_config;
static uint8_t current_config_valid;

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

static admin_device_config_t admin_get_current_config(void) {
  if (current_config_valid) return current_config;
  return default_cfg;
}

uint8_t device_config_is_led_normally_on(void) { return admin_get_current_config().led_normally_on; }

uint8_t device_config_is_ndef_enabled(void) { return admin_get_current_config().ndef_en; }

uint8_t device_config_is_webusb_landing_enabled(void) { return admin_get_current_config().webusb_landing_en; }

uint8_t device_config_is_pass_enabled(void) { return admin_get_current_config().pass_en; }

uint8_t device_config_is_openpgp_ccid_enabled(void) { return admin_get_current_config().openpgp_ccid_en; }

uint8_t device_config_is_openpgp_nfc_enabled(void) { return admin_get_current_config().openpgp_nfc_en; }

uint8_t device_config_is_piv_ccid_enabled(void) { return admin_get_current_config().piv_ccid_en; }

uint8_t device_config_is_piv_nfc_enabled(void) { return admin_get_current_config().piv_nfc_en; }

uint8_t device_config_is_webauthn_enabled(void) { return admin_get_current_config().webauthn_en; }

void admin_poweroff(void) { pin.is_validated = 0; }

int admin_install(const uint8_t reset) {
  admin_poweroff();
  if (reset || admin_platform_device_config_read(&current_config) < 0) {
    current_config = default_cfg;
    if (admin_platform_device_config_write(&current_config) < 0) return -1;
  }
  current_config_valid = 1;
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

static int admin_read_core_commit(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  size_t len = sizeof(CANOKEY_CORE_GIT_REV) - 1;
  if (len > APDU_BUFFER_SIZE) len = APDU_BUFFER_SIZE;
  if (len > LE) len = LE;
  memcpy(RDATA, CANOKEY_CORE_GIT_REV, len);
  LL = len;
  return 0;
}

static int admin_config(const CAPDU *capdu, RAPDU *rapdu) {
  admin_device_config_t next_config = admin_get_current_config();
  switch (P1) {
  case ADMIN_P1_CFG_LED_ON:
    next_config.led_normally_on = P2 & 1;
    break;
  case ADMIN_P1_CFG_NDEF:
    next_config.ndef_en = P2 & 1;
    break;
  case ADMIN_P1_CFG_WEBUSB_LANDING:
    next_config.webusb_landing_en = P2 & 1;
    break;
  case ADMIN_P1_CFG_FEATURE:
    if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
    if ((P2 & ~ADMIN_FEATURE_MASK) != 0) EXCEPT(SW_WRONG_P1P2);
    next_config.pass_en = (P2 & ADMIN_FEATURE_PASS) != 0;
    next_config.openpgp_ccid_en = (P2 & ADMIN_FEATURE_OPENPGP_CCID) != 0;
    next_config.openpgp_nfc_en = (P2 & ADMIN_FEATURE_OPENPGP_NFC) != 0;
    next_config.piv_ccid_en = (P2 & ADMIN_FEATURE_PIV_CCID) != 0;
    next_config.piv_nfc_en = (P2 & ADMIN_FEATURE_PIV_NFC) != 0;
    next_config.webauthn_en = (P2 & ADMIN_FEATURE_WEBAUTHN) != 0;
    break;
  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  const int ret = admin_platform_device_config_write(&next_config);
  if (ret == 0) {
    current_config = next_config;
    current_config_valid = 1;
  }
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
  RDATA[5] = (cfg.pass_en ? ADMIN_FEATURE_PASS : 0) | (cfg.openpgp_ccid_en ? ADMIN_FEATURE_OPENPGP_CCID : 0) |
             (cfg.openpgp_nfc_en ? ADMIN_FEATURE_OPENPGP_NFC : 0) | (cfg.piv_ccid_en ? ADMIN_FEATURE_PIV_CCID : 0) |
             (cfg.piv_nfc_en ? ADMIN_FEATURE_PIV_NFC : 0) | (cfg.webauthn_en ? ADMIN_FEATURE_WEBAUTHN : 0);
  LL = 6;

  return 0;
}

static void admin_put_u32_be(uint8_t *buf, uint32_t value) {
  buf[0] = (uint8_t)(value >> 24);
  buf[1] = (uint8_t)(value >> 16);
  buf[2] = (uint8_t)(value >> 8);
  buf[3] = (uint8_t)value;
}

static const uint8_t *admin_fs_usage_attrs(uint8_t kind, uint8_t *count) {
  switch (kind) {
  case ADMIN_ATTR_KEY:
    *count = sizeof(key_attrs);
    return key_attrs;
  case ADMIN_ATTR_OPENPGP_DATA:
    *count = sizeof(openpgp_data_attrs);
    return openpgp_data_attrs;
  case ADMIN_ATTR_PIV_PIN:
    *count = sizeof(piv_pin_attrs);
    return piv_pin_attrs;
  case ADMIN_ATTR_PIV_ADMIN_KEY:
    *count = sizeof(piv_admin_key_attrs);
    return piv_admin_key_attrs;
  case ADMIN_ATTR_PIV_DO_META:
    *count = sizeof(piv_do_meta_attrs);
    return piv_do_meta_attrs;
  case ADMIN_ATTR_OATH:
    *count = sizeof(oath_attrs);
    return oath_attrs;
  case ADMIN_ATTR_CTAP_CERT:
    *count = sizeof(ctap_cert_attrs);
    return ctap_cert_attrs;
  case ADMIN_ATTR_CTAP_DC:
    *count = sizeof(ctap_dc_attrs);
    return ctap_dc_attrs;
  default:
    *count = 0;
    return NULL;
  }
}

static uint8_t admin_fs_usage_attr_kind(uint8_t source_index) {
  const uint8_t packed = usage_attr_kinds[source_index >> 1u];
  return (source_index & 1u) != 0 ? packed >> 4u : packed & 0x0Fu;
}

static int admin_sum_fs_usage(const char *path, uint8_t attr_kind, uint32_t *bytes, uint8_t *flags) {
  int size = get_file_size(path);
  if (size == LFS_ERR_NOENT) {
    *flags |= ADMIN_APPLET_USAGE_FLAG_MISSING;
  } else if (size < 0) {
    return size;
  } else {
    *bytes += (uint32_t)size;
  }

  uint8_t attr_count;
  const uint8_t *attrs = admin_fs_usage_attrs(attr_kind, &attr_count);
  for (uint8_t i = 0; i < attr_count; ++i) {
    size = get_attr_size(path, attrs[i]);
    if (size == LFS_ERR_NOENT || size == LFS_ERR_NOATTR) {
      *flags |= ADMIN_APPLET_USAGE_FLAG_MISSING;
      continue;
    }
    if (size < 0) return size;
    *bytes += (uint32_t)size;
  }

  return 0;
}

static char admin_hex_digit(uint8_t nibble) { return (char)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10); }

static int admin_sum_piv_slot_usage(char kind, uint8_t slot, uint8_t attr_kind, uint32_t *bytes, uint8_t *flags) {
  char path[] = "piv-k00";
  path[4] = kind;
  path[5] = admin_hex_digit(slot >> 4u);
  path[6] = admin_hex_digit(slot & 0x0Fu);
  return admin_sum_fs_usage(path, attr_kind, bytes, flags);
}

static int admin_sum_piv_usage(uint32_t *bytes, uint8_t *flags) {
  for (uint8_t i = 0; i < sizeof(piv_usage_fixed_sources) / sizeof(piv_usage_fixed_sources[0]); ++i) {
    uint8_t attr_kind = ADMIN_ATTR_NONE;
    if (i == 8)
      attr_kind = ADMIN_ATTR_PIV_DO_META;
    else if (i >= 9)
      attr_kind = ADMIN_ATTR_PIV_PIN;
    if (admin_sum_fs_usage(piv_usage_fixed_sources[i], attr_kind, bytes, flags) < 0) return -1;
  }

  static const uint8_t special_slots[] = {0x9A, 0x9C, 0x9D, 0x9E, 0xF9};
  for (uint8_t i = 0; i < sizeof(special_slots); ++i) {
    if (admin_sum_piv_slot_usage('c', special_slots[i], ADMIN_ATTR_NONE, bytes, flags) < 0 ||
        admin_sum_piv_slot_usage('k', special_slots[i], ADMIN_ATTR_NONE, bytes, flags) < 0)
      return -1;
  }
  for (uint8_t slot = 0x82; slot <= 0x95; ++slot) {
    if (admin_sum_piv_slot_usage('c', slot, ADMIN_ATTR_NONE, bytes, flags) < 0 ||
        admin_sum_piv_slot_usage('k', slot, ADMIN_ATTR_NONE, bytes, flags) < 0)
      return -1;
  }
  return admin_sum_piv_slot_usage('k', 0x9B, ADMIN_ATTR_PIV_ADMIN_KEY, bytes, flags);
}

static int admin_flash_usage_applets(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  if (LE < ADMIN_APPLET_USAGE_RESPONSE_LENGTH) EXCEPT(SW_WRONG_LENGTH);

  size_t off = 0;
  uint32_t attributed_bytes = 0;
  for (size_t i = 0; i < sizeof(applet_usage_defs) / sizeof(applet_usage_defs[0]); ++i) {
    uint32_t bytes = 0;
    uint8_t flags = 0;
    if (applet_usage_defs[i].id == ADMIN_APPLET_USAGE_ID_PIV) {
      if (admin_sum_piv_usage(&bytes, &flags) < 0) return -1;
    } else {
      for (uint8_t j = 0; j < applet_usage_defs[i].source_count; ++j) {
        const uint8_t source_index = applet_usage_defs[i].first_source + j;
        const uint8_t attr_kind = admin_fs_usage_attr_kind(source_index);
        if (admin_sum_fs_usage(usage_sources[source_index], attr_kind, &bytes, &flags) < 0) return -1;
      }
    }
    if (UINT32_MAX - attributed_bytes < bytes) {
      attributed_bytes = UINT32_MAX;
    } else {
      attributed_bytes += bytes;
    }

    RDATA[off++] = applet_usage_defs[i].id;
    RDATA[off++] = flags;
    admin_put_u32_be(RDATA + off, bytes);
    off += 4;
  }

  int fs_usage_bytes = get_fs_usage_bytes();
  if (fs_usage_bytes < 0) return -1;
  const uint32_t unattributed_bytes =
      (uint32_t)fs_usage_bytes > attributed_bytes ? (uint32_t)fs_usage_bytes - attributed_bytes : 0;
  RDATA[off++] = ADMIN_APPLET_USAGE_ID_SYSTEM;
  RDATA[off++] = 0;
  admin_put_u32_be(RDATA + off, unattributed_bytes);
  off += 4;

  LL = off;
  return 0;
}

static int admin_flash_usage(const CAPDU *capdu, RAPDU *rapdu) {
  if (P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (P1 == ADMIN_FLASH_USAGE_APPLETS) return admin_flash_usage_applets(capdu, rapdu);
  if (P1 != ADMIN_FLASH_USAGE_TOTAL) EXCEPT(SW_WRONG_P1P2);
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

int __attribute__((noinline)) admin_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;

  int ret = 0;
  switch (INS) {
  case ADMIN_INS_SELECT:
    if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    return 0;

  case ADMIN_INS_READ_VERSION:
    if (P1 > ADMIN_P1_READ_CORE_COMMIT || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    if (P1 == 0)
      ret = admin_vendor_version(capdu, rapdu);
    else if (P1 == 1)
      ret = admin_vendor_hw_variant(capdu, rapdu);
    else if (P1 == ADMIN_P1_READ_CORE_COMMIT)
      ret = admin_read_core_commit(capdu, rapdu);
    goto done;

  case ADMIN_INS_READ_SN:
    if (P1 > 1 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
    if (P1 == 0)
      ret = admin_read_sn(capdu, rapdu);
    else if (P1 == 1)
      ret = admin_vendor_hw_sn(capdu, rapdu);
    goto done;

  case ADMIN_INS_FLASH_USAGE:
    ret = admin_flash_usage(capdu, rapdu);
    goto done;

  case ADMIN_INS_READ_CONFIG:
    ret = admin_read_config(capdu, rapdu);
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
