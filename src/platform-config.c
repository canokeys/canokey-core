// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <common.h>
#include <crc.h>
#include <ctap.h>
#include <kbdhid.h>
#include <piv.h>
#include <platform-config.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#define CONFIG_MAGIC 0x434B4346u // "CKCF"
#define CONFIG_VERSION 1u
#define CONFIG_HEADER_LEN 0x20u
#define CONFIG_KBD_ENTRY_SIZE 2u
#define CONFIG_KBD_ASCII_COUNT 128u
#define CONFIG_TLV_SIZE 220u
#define CONFIG_TLV_EMPTY 0xFFu

#define CONFIG_TLV_CTAP_SM2_CONFIG 0x01u
#define CONFIG_TLV_PIV_ALG_EXT_CONFIG 0x02u
#define CONFIG_TLV_CTAP_PERSISTENT_CONFIG 0x03u

#define CONFIG_FLAG_INITIALIZED (1u << 0)
#define CONFIG_FLAG_NFC_ENABLED (1u << 1)
#define CONFIG_FLAG_LED_NORMALLY_ON (1u << 2)
#define CONFIG_FLAG_NDEF_ENABLED (1u << 3)
#define CONFIG_FLAG_WEBUSB_LANDING_ENABLED (1u << 4)
#define CONFIG_FLAG_SN_VALID (1u << 5)
#define CONFIG_FLAG_KBD_KEYMAP_VALID (1u << 6)
#define CONFIG_FLAG_PASS_ENABLED (1u << 7)
#define CONFIG_FLAG_OPENPGP_CCID_ENABLED (1u << 8)
#define CONFIG_FLAG_OPENPGP_NFC_ENABLED (1u << 9)
#define CONFIG_FLAG_PIV_CCID_ENABLED (1u << 10)
#define CONFIG_FLAG_PIV_NFC_ENABLED (1u << 11)
#define CONFIG_FLAG_WEBAUTHN_ENABLED (1u << 12)
#define CONFIG_FLAGS_FEATURES                                                                                         \
  (CONFIG_FLAG_PASS_ENABLED | CONFIG_FLAG_OPENPGP_CCID_ENABLED | CONFIG_FLAG_OPENPGP_NFC_ENABLED |                    \
   CONFIG_FLAG_PIV_CCID_ENABLED | CONFIG_FLAG_PIV_NFC_ENABLED | CONFIG_FLAG_WEBAUTHN_ENABLED)

// The first word is platform-owned loader handoff state and is excluded from
// the core config CRC. The rest of the page is owned by this module.
typedef struct {
  uint8_t modifier;
  uint8_t usage;
} __packed config_kbd_entry_t;

typedef struct {
  uint32_t platform_word;
  uint32_t magic;
  uint8_t version;
  uint8_t header_len;
  uint16_t page_len;
  uint32_t flags;
  uint8_t serial[4];
  uint8_t kbd_layout_id;
  uint8_t kbd_entry_size;
  uint8_t kbd_first;
  uint8_t kbd_count;
  uint8_t reserved[8];
  config_kbd_entry_t keymap[CONFIG_KBD_ASCII_COUNT];
  uint8_t tlv[CONFIG_TLV_SIZE];
  uint32_t crc;
} __packed config_page_t;

_Static_assert(sizeof(config_page_t) == PLATFORM_CONFIG_PAGE_SIZE,
               "platform config page must be exactly one flash page");
_Static_assert(offsetof(config_page_t, keymap) == CONFIG_HEADER_LEN,
               "platform config keymap must start after the fixed header");
_Static_assert(offsetof(config_page_t, crc) == PLATFORM_CONFIG_PAGE_SIZE - sizeof(uint32_t),
               "platform config CRC must be the last word");
_Static_assert(sizeof(((config_page_t *)0)->keymap) == ADMIN_KBD_KEYMAP_LENGTH,
               "admin keymap APDU length must match platform config keymap storage");

__weak int platform_config_page_read(size_t off, void *buf, size_t len) {
  UNUSED(off);
  UNUSED(buf);
  UNUSED(len);
  return -1;
}

__weak int platform_config_page_write(const void *page, size_t len) {
  UNUSED(page);
  UNUSED(len);
  return -1;
}

static int config_read_page(config_page_t *page) {
  return platform_config_page_read(0, page, sizeof(*page));
}

static uint32_t config_crc_value(const config_page_t *page) {
  // The platform word may be rewritten without touching config metadata, so
  // the CRC covers only bytes owned by core.
  const uint8_t *start = (const uint8_t *)page + offsetof(config_page_t, magic);
  return crc32_update(CRC32_INIT, start, PLATFORM_CONFIG_PAGE_SIZE - offsetof(config_page_t, magic) - sizeof(page->crc));
}

static bool config_page_valid(const config_page_t *page) {
  return page->magic == CONFIG_MAGIC && page->version == CONFIG_VERSION && page->header_len == CONFIG_HEADER_LEN &&
         page->page_len == PLATFORM_CONFIG_PAGE_SIZE && page->crc == config_crc_value(page);
}

static bool config_valid(void) {
  alignas(4) config_page_t page;
  return config_read_page(&page) == 0 && config_page_valid(&page);
}

static void config_set_defaults(config_page_t *page, uint32_t platform_word) {
  memset(page, 0xFF, sizeof(*page));
  page->platform_word = platform_word;
  page->magic = CONFIG_MAGIC;
  page->version = CONFIG_VERSION;
  page->header_len = CONFIG_HEADER_LEN;
  page->page_len = PLATFORM_CONFIG_PAGE_SIZE;
  page->flags = CONFIG_FLAG_NFC_ENABLED | CONFIG_FLAG_LED_NORMALLY_ON | CONFIG_FLAG_NDEF_ENABLED |
                CONFIG_FLAG_WEBUSB_LANDING_ENABLED | CONFIG_FLAGS_FEATURES;
  memset(page->serial, 0, sizeof(page->serial));
  page->kbd_layout_id = 0;
  page->kbd_entry_size = CONFIG_KBD_ENTRY_SIZE;
  page->kbd_first = 0;
  page->kbd_count = CONFIG_KBD_ASCII_COUNT;
  memset(page->keymap, 0, sizeof(page->keymap));
  memset(page->tlv, CONFIG_TLV_EMPTY, sizeof(page->tlv));
  page->crc = config_crc_value(page);
}

// The fixed keymap consumes most of the page. Small optional configs use this
// compact TLV tail so adding one does not force a layout bump.
static bool config_tlv_find(const config_page_t *page, uint8_t type, const uint8_t **value, uint8_t *len) {
  size_t off = 0;
  while (off < sizeof(page->tlv)) {
    const uint8_t item_type = page->tlv[off];
    if (item_type == CONFIG_TLV_EMPTY) return false;
    if (off + 2 > sizeof(page->tlv)) return false;

    const uint8_t item_len = page->tlv[off + 1];
    if (item_len > sizeof(page->tlv) - off - 2) return false;

    if (item_type == type) {
      if (value != NULL) *value = &page->tlv[off + 2];
      if (len != NULL) *len = item_len;
      return true;
    }
    off += 2 + item_len;
  }
  return false;
}

static int config_tlv_append(uint8_t *tlv, size_t *off, uint8_t type, const uint8_t *value, uint8_t len) {
  if (*off > CONFIG_TLV_SIZE || CONFIG_TLV_SIZE - *off < 2 || len > CONFIG_TLV_SIZE - *off - 2) return -1;
  tlv[(*off)++] = type;
  tlv[(*off)++] = len;
  memcpy(&tlv[*off], value, len);
  *off += len;
  return 0;
}

typedef int (*config_update_fn)(config_page_t *page, void *ctx);

static int config_update(config_update_fn update, void *ctx) {
  alignas(4) config_page_t page;

  // Flash-backed platforms can only rewrite the page as an erase block. Always
  // copy the full page, repair invalid metadata in RAM, then write one full page.
  if (config_read_page(&page) < 0) return -1;
  if (!config_page_valid(&page)) config_set_defaults(&page, page.platform_word);

  if (update(&page, ctx) < 0) return -1;

  uint32_t platform_word = page.platform_word;
  (void)platform_config_page_read(offsetof(config_page_t, platform_word), &platform_word, sizeof(platform_word));
  page.platform_word = platform_word;
  page.crc = config_crc_value(&page);
  return platform_config_page_write(&page, sizeof(page));
}

static int set_initialized_update(config_page_t *page, void *ctx) {
  UNUSED(ctx);
  page->flags |= CONFIG_FLAG_INITIALIZED;
  return 0;
}

static int set_nfc_update(config_page_t *page, void *ctx) {
  const uint8_t enabled = *(const uint8_t *)ctx;
  if (enabled)
    page->flags |= CONFIG_FLAG_NFC_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_NFC_ENABLED;
  return 0;
}

static int set_admin_cfg_update(config_page_t *page, void *ctx) {
  const admin_device_config_t *cfg = (const admin_device_config_t *)ctx;
  if (cfg->led_normally_on)
    page->flags |= CONFIG_FLAG_LED_NORMALLY_ON;
  else
    page->flags &= ~CONFIG_FLAG_LED_NORMALLY_ON;
  if (cfg->ndef_en)
    page->flags |= CONFIG_FLAG_NDEF_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_NDEF_ENABLED;
  if (cfg->webusb_landing_en)
    page->flags |= CONFIG_FLAG_WEBUSB_LANDING_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_WEBUSB_LANDING_ENABLED;
  if (cfg->pass_en)
    page->flags |= CONFIG_FLAG_PASS_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_PASS_ENABLED;
  if (cfg->openpgp_ccid_en)
    page->flags |= CONFIG_FLAG_OPENPGP_CCID_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_OPENPGP_CCID_ENABLED;
  if (cfg->openpgp_nfc_en)
    page->flags |= CONFIG_FLAG_OPENPGP_NFC_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_OPENPGP_NFC_ENABLED;
  if (cfg->piv_ccid_en)
    page->flags |= CONFIG_FLAG_PIV_CCID_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_PIV_CCID_ENABLED;
  if (cfg->piv_nfc_en)
    page->flags |= CONFIG_FLAG_PIV_NFC_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_PIV_NFC_ENABLED;
  if (cfg->webauthn_en)
    page->flags |= CONFIG_FLAG_WEBAUTHN_ENABLED;
  else
    page->flags &= ~CONFIG_FLAG_WEBAUTHN_ENABLED;
  return 0;
}

static int set_sn_update(config_page_t *page, void *ctx) {
  const uint8_t *sn = (const uint8_t *)ctx;
  memcpy(page->serial, sn, sizeof(page->serial));
  page->flags |= CONFIG_FLAG_SN_VALID;
  return 0;
}

typedef struct {
  uint8_t layout_id;
  const uint8_t *keymap;
} keymap_update_t;

static int set_keymap_update(config_page_t *page, void *ctx) {
  const keymap_update_t *keymap = (const keymap_update_t *)ctx;
  page->kbd_layout_id = keymap->layout_id;
  page->kbd_entry_size = CONFIG_KBD_ENTRY_SIZE;
  page->kbd_first = 0;
  page->kbd_count = CONFIG_KBD_ASCII_COUNT;
  memcpy(page->keymap, keymap->keymap, sizeof(page->keymap));
  page->flags |= CONFIG_FLAG_KBD_KEYMAP_VALID;
  return 0;
}

static int clear_keymap_update(config_page_t *page, void *ctx) {
  UNUSED(ctx);
  page->kbd_layout_id = 0;
  page->kbd_entry_size = CONFIG_KBD_ENTRY_SIZE;
  page->kbd_first = 0;
  page->kbd_count = CONFIG_KBD_ASCII_COUNT;
  memset(page->keymap, 0, sizeof(page->keymap));
  page->flags &= ~CONFIG_FLAG_KBD_KEYMAP_VALID;
  return 0;
}

typedef struct {
  uint8_t type;
  const uint8_t *value;
  uint8_t len;
} tlv_update_t;

static int set_tlv_update(config_page_t *page, void *ctx) {
  const tlv_update_t *update = (const tlv_update_t *)ctx;
  uint8_t tlv[CONFIG_TLV_SIZE];
  size_t src = 0;
  size_t dst = 0;

  // Rebuild the TLV tail instead of patching in place. Flash writes still go
  // through config_update(), and rebuilding keeps replaced values compact.
  memset(tlv, CONFIG_TLV_EMPTY, sizeof(tlv));
  while (src < sizeof(page->tlv)) {
    const uint8_t item_type = page->tlv[src];
    if (item_type == CONFIG_TLV_EMPTY) break;
    if (src + 2 > sizeof(page->tlv)) break;

    const uint8_t item_len = page->tlv[src + 1];
    if (item_len > sizeof(page->tlv) - src - 2) break;
    if (item_type != update->type && config_tlv_append(tlv, &dst, item_type, &page->tlv[src + 2], item_len) < 0)
      return -1;
    src += 2 + item_len;
  }

  if (config_tlv_append(tlv, &dst, update->type, update->value, update->len) < 0) return -1;
  memcpy(page->tlv, tlv, sizeof(page->tlv));
  return 0;
}

static int config_tlv_read(uint8_t type, uint8_t *value, uint8_t len) {
  alignas(4) config_page_t page;
  const uint8_t *stored;
  uint8_t stored_len;

  if (config_read_page(&page) < 0 || !config_page_valid(&page) || !config_tlv_find(&page, type, &stored, &stored_len) ||
      stored_len != len)
    return -1;
  memcpy(value, stored, len);
  return 0;
}

static int config_tlv_write(uint8_t type, const uint8_t *value, uint8_t len) {
  tlv_update_t update = {.type = type, .value = value, .len = len};
  return config_update(set_tlv_update, &update);
}

int admin_platform_device_config_read(admin_device_config_t *cfg) {
  alignas(4) config_page_t page;
  if (config_read_page(&page) < 0 || !config_page_valid(&page)) return -1;
  cfg->led_normally_on = (page.flags & CONFIG_FLAG_LED_NORMALLY_ON) != 0;
  cfg->ndef_en = (page.flags & CONFIG_FLAG_NDEF_ENABLED) != 0;
  cfg->webusb_landing_en = (page.flags & CONFIG_FLAG_WEBUSB_LANDING_ENABLED) != 0;
  cfg->pass_en = (page.flags & CONFIG_FLAG_PASS_ENABLED) != 0;
  cfg->openpgp_ccid_en = (page.flags & CONFIG_FLAG_OPENPGP_CCID_ENABLED) != 0;
  cfg->openpgp_nfc_en = (page.flags & CONFIG_FLAG_OPENPGP_NFC_ENABLED) != 0;
  cfg->piv_ccid_en = (page.flags & CONFIG_FLAG_PIV_CCID_ENABLED) != 0;
  cfg->piv_nfc_en = (page.flags & CONFIG_FLAG_PIV_NFC_ENABLED) != 0;
  cfg->webauthn_en = (page.flags & CONFIG_FLAG_WEBAUTHN_ENABLED) != 0;
  return 0;
}

int admin_platform_device_config_write(const admin_device_config_t *cfg) {
  return config_update(set_admin_cfg_update, (void *)cfg);
}

int admin_platform_serial_read(uint8_t *buf) {
  alignas(4) config_page_t page;
  if (config_read_page(&page) < 0 || !config_page_valid(&page) || (page.flags & CONFIG_FLAG_SN_VALID) == 0) return -1;
  memcpy(buf, page.serial, sizeof(page.serial));
  return 0;
}

int admin_platform_serial_write_once(const uint8_t *buf) {
  if (config_valid()) {
    alignas(4) config_page_t page;
    if (config_read_page(&page) == 0 && config_page_valid(&page) && (page.flags & CONFIG_FLAG_SN_VALID) != 0)
      return -1;
  }
  return config_update(set_sn_update, (void *)buf);
}

int admin_platform_kbd_keymap_write(uint8_t layout_id, const uint8_t *keymap, uint16_t len) {
  if (keymap == NULL || len != sizeof(((config_page_t *)0)->keymap)) return -1;
  keymap_update_t update = {.layout_id = layout_id, .keymap = keymap};
  return config_update(set_keymap_update, &update);
}

int admin_platform_kbd_keymap_read(uint8_t *layout_id, uint8_t *keymap, uint16_t len) {
  alignas(4) config_page_t page;
  if (layout_id == NULL) return -1;
  if ((keymap == NULL && len != 0) || (keymap != NULL && len != sizeof(page.keymap))) return -1;
  if (config_read_page(&page) < 0 || !config_page_valid(&page) || (page.flags & CONFIG_FLAG_KBD_KEYMAP_VALID) == 0)
    return -1;
  if (page.kbd_entry_size != CONFIG_KBD_ENTRY_SIZE || page.kbd_first != 0 || page.kbd_count != CONFIG_KBD_ASCII_COUNT)
    return -1;
  *layout_id = page.kbd_layout_id;
  if (keymap != NULL) memcpy(keymap, page.keymap, sizeof(page.keymap));
  return 0;
}

int admin_platform_kbd_keymap_clear(void) { return config_update(clear_keymap_update, NULL); }

int ctap_platform_sm2_config_read(void *cfg, size_t len) {
  // The TLV length field is one byte; reject unexpected larger core structs
  // instead of silently truncating a future config.
  if (len > UINT8_MAX) return -1;
  return config_tlv_read(CONFIG_TLV_CTAP_SM2_CONFIG, cfg, (uint8_t)len);
}

int ctap_platform_sm2_config_write(const void *cfg, size_t len) {
  if (len > UINT8_MAX) return -1;
  return config_tlv_write(CONFIG_TLV_CTAP_SM2_CONFIG, cfg, (uint8_t)len);
}

int ctap_platform_persistent_config_read(void *cfg, size_t len) {
  if (len > UINT8_MAX) return -1;
  return config_tlv_read(CONFIG_TLV_CTAP_PERSISTENT_CONFIG, cfg, (uint8_t)len);
}

int ctap_platform_persistent_config_write(const void *cfg, size_t len) {
  if (len > UINT8_MAX) return -1;
  return config_tlv_write(CONFIG_TLV_CTAP_PERSISTENT_CONFIG, cfg, (uint8_t)len);
}

int piv_platform_algorithm_extension_config_read(piv_algorithm_extension_config_t *cfg) {
  return config_tlv_read(CONFIG_TLV_PIV_ALG_EXT_CONFIG, (uint8_t *)cfg, sizeof(*cfg));
}

int piv_platform_algorithm_extension_config_write(const piv_algorithm_extension_config_t *cfg) {
  return config_tlv_write(CONFIG_TLV_PIV_ALG_EXT_CONFIG, (const uint8_t *)cfg, sizeof(*cfg));
}

bool kbdhid_platform_translate_ascii(uint8_t ch, uint8_t *modifier, uint8_t *usage) {
  alignas(4) config_page_t page;
  if (config_read_page(&page) < 0 || !config_page_valid(&page) || (page.flags & CONFIG_FLAG_KBD_KEYMAP_VALID) == 0)
    return false;
  if (page.kbd_entry_size != CONFIG_KBD_ENTRY_SIZE || page.kbd_first != 0 || page.kbd_count != CONFIG_KBD_ASCII_COUNT ||
      ch >= CONFIG_KBD_ASCII_COUNT)
    return false;

  // A valid platform keymap is authoritative. usage == 0 means "skip this
  // character", not "fall back to the built-in QWERTY map".
  const config_kbd_entry_t *entry = &page.keymap[ch];
  *modifier = entry->modifier;
  *usage = entry->usage;
  return true;
}

uint8_t device_config_is_initialized(void) {
  alignas(4) config_page_t page;
  if (config_read_page(&page) < 0 || !config_page_valid(&page)) return 0;
  return (page.flags & CONFIG_FLAG_INITIALIZED) != 0;
}

int device_config_mark_initialized(void) {
  if (device_config_is_initialized()) return 0;
  return config_update(set_initialized_update, NULL);
}

uint8_t device_config_is_nfc_enabled(void) {
  alignas(4) config_page_t page;
  if (config_read_page(&page) < 0 || !config_page_valid(&page)) return 1;
  return (page.flags & CONFIG_FLAG_NFC_ENABLED) != 0;
}

int device_config_set_nfc_enabled(uint8_t enabled) { return config_update(set_nfc_update, &enabled); }
