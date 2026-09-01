// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-internal.h"
#include "ctap-parser.h"
#include "secret.h"
#include "u2f.h"
#include <apdu.h>
#include <applet-scratch.h>
#include <block-cipher.h>
#include <cbor.h>
#include <common.h>
#include <crypto-util.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <fs.h>
#include <hmac.h>
#include <ml-dsa-65.h>
#include <memzero.h>
#include <pke.h>
#include <rand.h>
#include <string.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if ((ret) != 0) ERR_MSG("CHECK_PARSER_RET %#x\n", ret);                                                            \
    if ((ret) > 0) return ret;                                                                                         \
  } while (0)

#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if ((ret) != 0) ERR_MSG("CHECK_CBOR_RET %#x\n", ret);                                                              \
    if ((ret) != 0) return CTAP2_ERR_INVALID_CBOR;                                                                     \
  } while (0)

#define SET_RESP()                                                                                                     \
  do {                                                                                                                 \
    if (*resp == 0)                                                                                                    \
      *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, encode_buf);                                              \
    else                                                                                                               \
      *resp_len = 1;                                                                                                   \
  } while (0)

static int ctap_large_response_read_at(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  const uint8_t *src = (const uint8_t *)ctx;
  memcpy(buf, src + offset, len);
  return (int)len;
}

#if ENABLE_NFC
#define WAIT(timeout_response)                                                                                         \
  do {                                                                                                                 \
    if (is_nfc()) {                                                                                                    \
      int __nfc_wait = ctap_nfc_wait_for_user_presence(timeout_response);                                              \
      if (__nfc_wait < 0) break;                                                                                       \
      return (uint8_t)__nfc_wait;                                                                                      \
    }                                                                                                                  \
    switch (wait_for_user_presence(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID)) {          \
    case USER_PRESENCE_CANCEL:                                                                                         \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      return timeout_response;                                                                                         \
    }                                                                                                                  \
  } while (0)
#else
#define WAIT(timeout_response)                                                                                         \
  do {                                                                                                                 \
    switch (wait_for_user_presence(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID)) {          \
    case USER_PRESENCE_CANCEL:                                                                                         \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      return timeout_response;                                                                                         \
    }                                                                                                                  \
  } while (0)
#endif

#define KEEPALIVE()                                                                                                    \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    send_keepalive_during_processing(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID);          \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};

typedef struct {
  uint8_t last_subcommand;
  uint32_t next_idx;
  uint32_t total;
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  bool has_rp_filter;
} CTAP_credential_management_state;

// pin & command states
static uint8_t consecutive_pin_counter, last_cmd;
static bool runtime_reset_pending = true;
// source of APDU in process
static ctap_src_t current_cmd_src;
// SM2 attr
CTAP_sm2_attr ctap_sm2_attr;

static void ctap_sm2_config_set_default(void) {
  ctap_sm2_attr.curve_id = 9;  // An unused one. See https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
  ctap_sm2_attr.algo_id = -54; // An unused one. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
}

static bool ctap_sm2_algo_id_valid(int32_t algo_id) {
  return algo_id != COSE_ALG_ES256 && algo_id != COSE_ALG_EDDSA && algo_id != COSE_ALG_ML_DSA_65;
}

static int ctap_sm2_config_read_platform(CTAP_sm2_attr *attr) {
  if (ctap_platform_sm2_config_read(attr, sizeof(*attr)) < 0) return -1;
  return ctap_sm2_algo_id_valid(attr->algo_id) ? 0 : -1;
}

static bool ctap_littlefs_state_present(void) {
  uint8_t buf[KH_KEY_SIZE];
  uint8_t pin_ctr;
  CTAP_dc_general_attr attr;
  const int pin_attr_len = read_attr(CTAP_CERT_FILE, PIN_ATTR, buf, sizeof(buf));
  if (pin_attr_len != 0 && pin_attr_len != PIN_HASH_SIZE_P1) return false;

  return get_file_size(DC_FILE) >= 0 && get_file_size(DC_META_FILE) >= 0 && get_file_size(CTAP_CERT_FILE) >= 0 &&
         get_file_size(LB_FILE) >= 0 && read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) == sizeof(attr) &&
         read_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, buf, 4) == 4 &&
         (pin_attr_len == 0 || read_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &pin_ctr, sizeof(pin_ctr)) == sizeof(pin_ctr)) &&
         read_attr(CTAP_CERT_FILE, KH_KEY_ATTR, buf, KH_KEY_SIZE) == KH_KEY_SIZE &&
         read_attr(CTAP_CERT_FILE, HE_KEY_ATTR, buf, HE_KEY_SIZE) == HE_KEY_SIZE;
}

typedef struct {
  uint8_t *buf;
  size_t len;
  size_t emitted;
} CTAP_mem_stream_state;

typedef struct {
  const uint8_t *buf;
  size_t len;
} CTAP_const_stream_segment;

#define CTAP_CONST_STREAM_MAX_SEGMENTS 24
#define CTAP_CONST_STREAM_INLINE_BYTES 48

typedef struct {
  CTAP_const_stream_segment segments[CTAP_CONST_STREAM_MAX_SEGMENTS];
  size_t segment_count;
  size_t current_segment;
  size_t segment_off;
  size_t total_len;
  size_t inline_len;
  uint8_t inline_bytes[CTAP_CONST_STREAM_INLINE_BYTES];
} CTAP_const_stream_state;

_Static_assert(sizeof(CTAP_const_stream_state) <= APPLET_SHARED_BUFFER_LENGTH,
               "GetInfo const stream state should stay smaller than one shared scratch buffer");

#define CTAP_MC_STREAM_MAX_SEGMENTS 5

typedef enum {
  CTAP_MC_STREAM_SEG_MEM,
  CTAP_MC_STREAM_SEG_FILE,
  CTAP_MC_STREAM_SEG_MLDSA,
} CTAP_make_credential_stream_segment_kind;

typedef struct {
  CTAP_make_credential_stream_segment_kind kind;
  const uint8_t *buf;
  const char *path;
  CTAP_mldsa_stream_state *mldsa;
  size_t file_off;
  size_t len;
  size_t off;
} CTAP_make_credential_stream_segment;

typedef struct {
  CTAP_make_credential_stream_segment segments[CTAP_MC_STREAM_MAX_SEGMENTS];
  size_t segment_count;
  size_t current_segment;
  size_t total_len;
  size_t emitted;
  bool prepared;
} CTAP_make_credential_stream_state;

#if ENABLE_NFC
#define CTAP_NFC_KEEPALIVE_PENDING 0xFE
#define CTAP_NFC_GET_RESPONSE 0x11
#define CTAP_NFC_PENDING_FILE "ctap_np"

typedef struct {
  uint8_t active;
  uint8_t allow_poll;
  uint8_t touch_granted;
  uint8_t keepalive_status;
  uint32_t wait_start;
  uint16_t request_len;
  uint8_t request[APDU_INCOMING_DATA_SIZE];
  uint8_t request_in_file;
} CTAP_nfc_pending_state;
#endif

typedef struct {
  uint32_t parsed_params;
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  uint8_t client_data_hash[CLIENT_DATA_HASH_SIZE];
  size_t allow_list_size;
  uint32_t next_dc_idx;
  uint32_t number_of_credentials;
  uint32_t credential_counter;
  CTAP_options options;
  CTAP_hmac_secret_ext ext_hmac_secret_data;
  bool ext_cred_blob;
  bool ext_third_party_payment;
} CTAP_get_assertion_state;

static CTAP_make_credential_stream_state mc_stream_state;
static CTAP_mem_stream_state mem_stream_state;
#if ENABLE_NFC
static CTAP_nfc_pending_state nfc_pending_state;
#endif
static CTAP_credential_management_state cred_mgmt_state;
static CTAP_get_assertion_state ga_state;
static bool uv, up, user_details;
static uint32_t timer;
#define mldsa_stream_state applet_session_scratch.ctap_mldsa
#define ga applet_session_scratch.ctap_ga
static uint8_t *stream_resp_base;
static bool stream_make_credential_response;
static bool hid_cbor_stream_response_active;
static bool cert_write_active;
static uint16_t cert_write_len;
// Current request bytes may be either a stable memory buffer or a transport
// source such as HID/APDU PKE staging. Source-backed bytes are valid only until
// parsing and any required raw-byte consumption completes.
static ctap_req_src_t current_req_src;
static const uint8_t *current_req_mem;
static size_t current_req_mem_len;

// Leave slack for LittleFS metadata and copy-on-write block allocation. This is
// an admission-control guard only; actual writes still map LFS_ERR_NOSPC to the
// CTAP storage-full status.
#define CTAP_FS_RESERVE_BYTES (128 * LFS_CACHE_SIZE)

static uint8_t ctap_dc_record_count(uint32_t *count) {
  int size = get_file_size(DC_FILE);
  if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  *count = (uint32_t)(size / (int)sizeof(CTAP_discoverable_credential));
  return 0;
}

static uint8_t ctap_meta_record_count(uint32_t *count) {
  int size = get_file_size(DC_META_FILE);
  if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  *count = (uint32_t)(size / (int)sizeof(CTAP_rp_meta));
  return 0;
}

static uint8_t ctap_storage_write_result(int err) {
  if (err == 0) return 0;
  if (err == LFS_ERR_NOSPC) return CTAP2_ERR_KEY_STORE_FULL;
  return CTAP2_ERR_UNHANDLED_REQUEST;
}

static uint8_t ctap_find_rp_meta(const uint8_t rp_id_hash[SHA256_DIGEST_LENGTH], CTAP_rp_meta *meta,
                                 uint32_t *out_idx, uint32_t *first_deleted, uint32_t *count) {
  uint32_t n_meta;
  uint8_t err = ctap_meta_record_count(&n_meta);
  if (err) return err;
  if (first_deleted) *first_deleted = UINT32_MAX;
  for (uint32_t i = 0; i < n_meta; ++i) {
    int size = read_file(DC_META_FILE, meta, (lfs_soff_t)(i * sizeof(CTAP_rp_meta)), sizeof(CTAP_rp_meta));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (meta->deleted || meta->live_count == 0) {
      if (first_deleted && *first_deleted == UINT32_MAX) *first_deleted = i;
      continue;
    }
    if (memcmp_s(meta->rp_id_hash, rp_id_hash, SHA256_DIGEST_LENGTH) == 0) {
      if (out_idx) *out_idx = i;
      if (count) *count = n_meta;
      return 0;
    }
  }
  if (count) *count = n_meta;
  return CTAP2_ERR_NO_CREDENTIALS;
}

static uint32_t ctap_count_deleted_credentials(void) {
  uint32_t n_dc;
  if (ctap_dc_record_count(&n_dc) != 0) return 0;
  uint32_t deleted = 0;
  CTAP_discoverable_credential dc;
  for (uint32_t i = 0; i < n_dc; ++i) {
    if (read_file(DC_FILE, &dc, (lfs_soff_t)(i * sizeof(CTAP_discoverable_credential)),
                  sizeof(CTAP_discoverable_credential)) < 0)
      return deleted;
    if (dc.deleted) ++deleted;
  }
  return deleted;
}

static size_t ctap_dc_write_cost(void) {
  // Worst-case cost for admitting one brand-new resident credential: one DC
  // record, one RP metadata record, and the general attribute update.
  return sizeof(CTAP_discoverable_credential) + sizeof(CTAP_rp_meta) + sizeof(CTAP_dc_general_attr);
}

static uint32_t ctap_capacity_remaining_new_credentials(void) {
  // Report reusable tombstones plus a conservative estimate for new records
  // that can fit in the remaining flash. This mirrors admission control but is
  // not a promise that every later write will succeed.
  uint32_t reusable = ctap_count_deleted_credentials();
  int free_bytes = get_fs_free_bytes();
  if (free_bytes <= CTAP_FS_RESERVE_BYTES) return reusable;
  size_t writable_records = ((size_t)free_bytes - CTAP_FS_RESERVE_BYTES) / ctap_dc_write_cost();
  if (writable_records > UINT32_MAX - reusable) return UINT32_MAX;
  return reusable + (uint32_t)writable_records;
}

static uint8_t ctap_rebuild_rp_meta_counts(void) {
  // Rebuild denormalized RP live counts from DC_FILE after an interrupted
  // add/delete. The DC tombstone flag is the source of truth.
  uint32_t n_meta;
  uint8_t err = ctap_meta_record_count(&n_meta);
  if (err) return err;
  uint32_t n_dc;
  err = ctap_dc_record_count(&n_dc);
  if (err) return err;

  CTAP_rp_meta meta;
  CTAP_discoverable_credential dc;
  uint32_t keepalive_counter = 0;
  for (uint32_t i = 0; i < n_meta; ++i) {
    int size = read_file(DC_META_FILE, &meta, (lfs_soff_t)(i * sizeof(CTAP_rp_meta)), sizeof(CTAP_rp_meta));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (meta.deleted && meta.live_count == 0) continue;
    uint32_t live_count = 0;
    for (uint32_t j = 0; j < n_dc; ++j) {
      size = read_file(DC_FILE, &dc, (lfs_soff_t)(j * sizeof(CTAP_discoverable_credential)),
                       sizeof(CTAP_discoverable_credential));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if ((++keepalive_counter & 0x0f) == 0) KEEPALIVE();
      if (dc.deleted) continue;
      if (memcmp_s(dc.credential_id.rp_id_hash, meta.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) ++live_count;
    }
    meta.live_count = live_count;
    meta.deleted = live_count == 0;
    size = write_file(DC_META_FILE, &meta, (lfs_soff_t)(i * sizeof(CTAP_rp_meta)), sizeof(CTAP_rp_meta), 0);
    if (size < 0) return ctap_storage_write_result(size);
    if ((++keepalive_counter & 0x0f) == 0) KEEPALIVE();
  }
  return 0;
}

static uint8_t ctap_find_next_assertion_dc(uint32_t start_exclusive, bool count_all, bool uv,
                                           CTAP_discoverable_credential *out, uint32_t *out_idx, uint32_t *total) {
  uint32_t n_dc;
  uint8_t err = ctap_dc_record_count(&n_dc);
  if (err) return err;
  if (start_exclusive > n_dc) start_exclusive = n_dc;
  uint32_t count = 0;
  bool found = false;
  CTAP_discoverable_credential dc;
  for (uint32_t idx = start_exclusive; idx > 0; --idx) {
    uint32_t i = idx - 1;
    if (read_file(DC_FILE, &dc, (lfs_soff_t)(i * sizeof(CTAP_discoverable_credential)),
                  sizeof(CTAP_discoverable_credential)) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (dc.deleted) continue;
    if (memcmp_s(ga_state.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) != 0) continue;
    if (!check_credential_protect_requirements(&dc.credential_id, false, uv)) continue;
    if (count_all) ++count;
    if (!found) {
      memcpy(out, &dc, sizeof(*out));
      *out_idx = i;
      found = true;
      if (!count_all) break;
    }
  }
  if (total) *total = count;
  return found ? 0 : CTAP2_ERR_NO_CREDENTIALS;
}

static int ctap_mem_req_read(void *ctx, size_t offset, uint8_t *buf, size_t len) {
  const uint8_t *src = (const uint8_t *)ctx;
  memcpy(buf, src + offset, len);
  return 0;
}

static int ctap_pke_req_read(void *ctx, size_t offset, uint8_t *buf, size_t len) {
  UNUSED(ctx);
  return pke_buffer_read(offset, buf, len);
}

static int ctap_req_read_payload_bytes(size_t offset, uint8_t *buf, size_t len) {
  if (current_req_src.read) {
    if (current_req_src.cancelled && current_req_src.cancelled(current_req_src.ctx)) return -1;
    if (offset > current_req_src.len || len > current_req_src.len - offset) return -1;
    return current_req_src.read(current_req_src.ctx, current_req_src.base_offset + offset, buf, len);
  }
  if (!current_req_mem) return -1;
  if (offset > current_req_mem_len || len > current_req_mem_len - offset) return -1;
  memcpy(buf, current_req_mem + offset, len);
  return 0;
}

static void ctap_req_src_clear(void) {
  current_req_src.read = NULL;
  current_req_src.cancelled = NULL;
  current_req_src.ctx = NULL;
  current_req_src.base_offset = 0;
  current_req_src.len = 0;
}

static void ctap_req_lifetime_end(void) {
  // Cross the request lifetime boundary before keepalive, WAIT(), crypto, or
  // response streaming can reuse PKE or re-enter transport handling.
  ctap_req_src_clear();
  current_req_mem = NULL;
  current_req_mem_len = 0;
}

static void ctap_begin_hid_cbor_stream_response(void) { hid_cbor_stream_response_active = true; }

static void ctap_end_hid_cbor_stream_response(void) { hid_cbor_stream_response_active = false; }

static int ctap_req_read_param_bytes(size_t offset, uint8_t *buf, size_t len) {
  return ctap_req_read_payload_bytes(offset + 1, buf, len);
}

static ctap_req_src_t ctap_param_req_src(void) {
  // CTAP CBOR payloads include a one-byte command prefix; parsers consume only
  // the CBOR parameter map that follows it.
  ctap_req_src_t src = current_req_src;
  if (src.len > 0) --src.len;
  src.base_offset += 1;
  return src;
}

typedef struct {
  uint8_t min_pin_length;
  uint8_t max_pin_length;
  uint8_t force_pin_change;
  uint8_t always_uv;
  uint8_t long_touch_for_reset;
  uint8_t pin_code_point_length;
} __packed CTAP_persistent_config;

static void ctap_config_default(CTAP_persistent_config *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->min_pin_length = CTAP_DEFAULT_MIN_PIN_LENGTH;
  cfg->max_pin_length = CTAP_MAX_PIN_LENGTH;
}

static int ctap_config_store(const CTAP_persistent_config *cfg) {
  return ctap_platform_persistent_config_write(cfg, sizeof(*cfg));
}

static bool ctap_config_valid(const CTAP_persistent_config *cfg) {
  return cfg->min_pin_length >= CTAP_DEFAULT_MIN_PIN_LENGTH && cfg->max_pin_length >= 8 &&
         cfg->max_pin_length <= CTAP_MAX_PIN_LENGTH && cfg->min_pin_length <= cfg->max_pin_length &&
         cfg->force_pin_change <= 1 && cfg->always_uv <= 1 && cfg->long_touch_for_reset <= 1;
}

static int ctap_config_read_platform(CTAP_persistent_config *cfg) {
  if (ctap_platform_persistent_config_read(cfg, sizeof(*cfg)) < 0) return -1;
  return ctap_config_valid(cfg) ? 0 : -1;
}

static int ctap_config_load(CTAP_persistent_config *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  if (ctap_config_read_platform(cfg) == 0) return 0;

  ctap_config_default(cfg);
  return 0;
}

static bool ctap_parse_pin_code_points(const uint8_t *pin, size_t len, uint8_t *out) {
  size_t i = 0;
  uint16_t count = 0;

  while (i < len) {
    uint8_t c = pin[i];
    size_t seq_len;
    uint32_t codepoint;

    if (c < 0x80) {
      seq_len = 1;
      codepoint = c;
    } else if ((c & 0xE0) == 0xC0) {
      seq_len = 2;
      codepoint = c & 0x1F;
      if (codepoint == 0) return false;
    } else if ((c & 0xF0) == 0xE0) {
      seq_len = 3;
      codepoint = c & 0x0F;
    } else if ((c & 0xF8) == 0xF0) {
      seq_len = 4;
      codepoint = c & 0x07;
    } else {
      return false;
    }

    if (seq_len > len - i) return false;
    for (size_t j = 1; j < seq_len; ++j) {
      uint8_t cc = pin[i + j];
      if ((cc & 0xC0) != 0x80) return false;
      codepoint = (codepoint << 6) | (cc & 0x3F);
    }

    if ((seq_len == 2 && codepoint < 0x80) || (seq_len == 3 && codepoint < 0x800) ||
        (seq_len == 4 && codepoint < 0x10000) || (codepoint >= 0xD800 && codepoint <= 0xDFFF) || codepoint > 0x10FFFF)
      return false;

    ++count;
    if (count > UINT8_MAX) return false;
    i += seq_len;
  }

  *out = (uint8_t)count;
  return true;
}

static uint8_t ctap_config_get_min_pin_length(void) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return CTAP_DEFAULT_MIN_PIN_LENGTH;
  return cfg.min_pin_length;
}

static bool ctap_config_always_uv_enabled(void) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return false;
  return cfg.always_uv != 0;
}

static bool ctap_config_long_touch_reset_enabled(void) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return false;
  return cfg.long_touch_for_reset != 0;
}

static bool ctap_config_force_pin_change_required(void) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return false;
  return cfg.force_pin_change != 0;
}

static int ctap_min_pin_rpids_store(const CTAP_config *cfg) {
  if (cfg->min_pin_rpid_count == 0) return write_file(MIN_PIN_RPIDS_FILE, NULL, 0, 0, 1);

  for (uint8_t i = 0; i < cfg->min_pin_rpid_count; ++i) {
    if (write_file(MIN_PIN_RPIDS_FILE, &cfg->min_pin_rpids[i], i * (int)sizeof(CTAP_min_pin_rp_id),
                   sizeof(CTAP_min_pin_rp_id), i == 0) < 0)
      return -1;
  }
  return 0;
}

static bool ctap_min_pin_rpid_authorized(const uint8_t *rp_id, size_t rp_id_len) {
  if (!rp_id || rp_id_len == 0 || rp_id_len > DOMAIN_NAME_MAX_SIZE) return false;

  int size = get_file_size(MIN_PIN_RPIDS_FILE);
  if (size <= 0) return false;
  int count = MIN(size / (int)sizeof(CTAP_min_pin_rp_id), CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH);
  for (int i = 0; i < count; ++i) {
    CTAP_min_pin_rp_id item;
    if (read_file(MIN_PIN_RPIDS_FILE, &item, i * (int)sizeof(item), sizeof(item)) < 0) return false;
    if (item.len == rp_id_len && memcmp_s(item.id, rp_id, rp_id_len) == 0) return true;
  }
  return false;
}

static uint8_t ctap_validate_new_pin(const uint8_t *pin, size_t len, uint8_t *code_points) {
  CTAP_persistent_config cfg;
  if (len == 0 || len > CTAP_MAX_PIN_LENGTH) return CTAP2_ERR_PIN_POLICY_VIOLATION;
  if (ctap_config_load(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (!ctap_parse_pin_code_points(pin, len, code_points)) return CTAP2_ERR_PIN_POLICY_VIOLATION;
  if (*code_points < cfg.min_pin_length || *code_points > cfg.max_pin_length) return CTAP2_ERR_PIN_POLICY_VIOLATION;
  return 0;
}

static int ctap_note_pin_changed(uint8_t code_points) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return -1;
  cfg.pin_code_point_length = code_points;
  cfg.force_pin_change = 0;
  return ctap_config_store(&cfg);
}

#if ENABLE_NFC
static int ctap_nfc_pending_req_read(void *ctx, size_t offset, uint8_t *buf, size_t len) {
  const CTAP_nfc_pending_state *pending = (const CTAP_nfc_pending_state *)ctx;
  if (!pending) return -1;
  if (pending->request_in_file)
    return read_file(CTAP_NFC_PENDING_FILE, buf, (lfs_soff_t)offset, (lfs_size_t)len) < 0 ? -1 : 0;
  memcpy(buf, pending->request + offset, len);
  return 0;
}
#endif

static int ctap_mem_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_mem_stream_state *state = (CTAP_mem_stream_state *)ctx;
  size_t copied = MIN(state->len - state->emitted, max_len);
  if (copied != 0) memcpy(out, state->buf + state->emitted, copied);
  state->emitted += copied;
  *written = copied;
  return 0;
}

static int ctap_prepare_hid_cbor_stream_source(uint8_t status, size_t resp_len, CTAPHID_TxSource *source) {
  if (!source || status != 0 || resp_len <= APDU_BUFFER_SIZE) return 0;

  mem_stream_state.buf = applet_session_scratch.buffer;
  mem_stream_state.len = resp_len;
  mem_stream_state.emitted = 0;
  source->total_len = mem_stream_state.len;
  source->read = ctap_mem_stream_read;
  source->close = CTAPHID_CloseSharedBufferSource;
  source->ctx = &mem_stream_state;
  return 1;
}

static void ctap_const_stream_reset(CTAP_const_stream_state *state) { memset(state, 0, sizeof(*state)); }

static int ctap_const_stream_add_mem(CTAP_const_stream_state *state, const uint8_t *buf, size_t len) {
  if (len == 0) return 0;
  if (!buf || state->segment_count >= CTAP_CONST_STREAM_MAX_SEGMENTS) return -1;
  state->segments[state->segment_count++] = (CTAP_const_stream_segment){.buf = buf, .len = len};
  state->total_len += len;
  return 0;
}

static int ctap_const_stream_add_inline(CTAP_const_stream_state *state, const uint8_t *buf, size_t len) {
  if (len == 0) return 0;
  if (!buf || len > sizeof(state->inline_bytes) - state->inline_len) return -1;
  uint8_t *dst = state->inline_bytes + state->inline_len;
  memcpy(dst, buf, len);
  state->inline_len += len;
  return ctap_const_stream_add_mem(state, dst, len);
}

static int ctap_const_stream_add_byte(CTAP_const_stream_state *state, uint8_t value) {
  return ctap_const_stream_add_inline(state, &value, 1);
}

static int ctap_const_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_const_stream_state *state = (CTAP_const_stream_state *)ctx;
  size_t copied = 0;

  while (copied < max_len && state->current_segment < state->segment_count) {
    CTAP_const_stream_segment *segment = &state->segments[state->current_segment];
    if (state->segment_off == segment->len) {
      ++state->current_segment;
      state->segment_off = 0;
      continue;
    }

    size_t n = MIN(segment->len - state->segment_off, max_len - copied);
    memcpy(out + copied, segment->buf + state->segment_off, n);
    state->segment_off += n;
    copied += n;
  }

  *written = copied;
  return 0;
}

static int ctap_const_stream_read_at(void *ctx, uint32_t offset, uint8_t *out, uint16_t max_len) {
  CTAP_const_stream_state *state = (CTAP_const_stream_state *)ctx;
  size_t copied = 0;
  size_t off = offset;

  if (off >= state->total_len) return 0;

  for (size_t i = 0; i < state->segment_count && copied < max_len; ++i) {
    const CTAP_const_stream_segment *segment = &state->segments[i];
    if (off >= segment->len) {
      off -= segment->len;
      continue;
    }

    size_t n = MIN(segment->len - off, (size_t)max_len - copied);
    memcpy(out + copied, segment->buf + off, n);
    copied += n;
    off = 0;
  }

  return (int)copied;
}

static int cbor_put_uint(uint8_t **p, uint64_t v, uint8_t major) {
  if (v < 24) {
    *(*p)++ = major | (uint8_t)v;
  } else if (v <= UINT8_MAX) {
    *(*p)++ = major | 24;
    *(*p)++ = (uint8_t)v;
  } else if (v <= UINT16_MAX) {
    *(*p)++ = major | 25;
    *(*p)++ = (uint8_t)(v >> 8);
    *(*p)++ = (uint8_t)v;
  } else {
    return -1;
  }
  return 0;
}

static int cbor_put_uint_inline(CTAP_const_stream_state *state, uint64_t value) {
  uint8_t encoded[9];
  uint8_t *p = encoded;
  if (cbor_put_uint(&p, value, 0x00) < 0) return -1;
  return ctap_const_stream_add_inline(state, encoded, (size_t)(p - encoded));
}

static int cbor_put_int(uint8_t **p, int64_t v) {
  if (v >= 0) return cbor_put_uint(p, (uint64_t)v, 0x00);
  return cbor_put_uint(p, (uint64_t)(-1 - v), 0x20);
}

static int cbor_put_int_inline(CTAP_const_stream_state *state, int64_t value) {
  uint8_t encoded[9];
  uint8_t *p = encoded;
  if (cbor_put_int(&p, value) < 0) return -1;
  return ctap_const_stream_add_inline(state, encoded, (size_t)(p - encoded));
}

static int cbor_put_bool_inline(CTAP_const_stream_state *state, bool value) {
  return ctap_const_stream_add_byte(state, value ? 0xF5 : 0xF4);
}

static int cbor_put_bytes_header(uint8_t **p, size_t len) { return cbor_put_uint(p, len, 0x40); }

static int cbor_put_text(uint8_t **p, const char *s) {
  size_t len = strlen(s);
  if (cbor_put_uint(p, len, 0x60) < 0) return -1;
  memcpy(*p, s, len);
  *p += len;
  return 0;
}

static int cbor_put_mldsa65_cose_prefix(uint8_t **p) {
  if (cbor_put_uint(p, 3, 0xA0) < 0) return -1;
  if (cbor_put_int(p, COSE_KEY_LABEL_KTY) < 0 || cbor_put_int(p, COSE_KEY_KTY_AKP) < 0) return -1;
  if (cbor_put_int(p, COSE_KEY_LABEL_ALG) < 0 || cbor_put_int(p, COSE_ALG_ML_DSA_65) < 0) return -1;
  if (cbor_put_int(p, COSE_KEY_LABEL_AKP_PUB) < 0 || cbor_put_bytes_header(p, MLDSA_PK_BYTES) < 0) return -1;
  return 0;
}

static int ctap_mldsa65_cose_prefix_size(void) {
  uint8_t buf[16];
  uint8_t *p = buf;
  if (cbor_put_mldsa65_cose_prefix(&p) < 0) return -1;
  return (int)(p - buf);
}

static int ctap_mldsa_stream_fill_stage(CTAP_mldsa_stream_state *state) {
  int ret;
  state->stage_len = 0;
  state->stage_off = 0;
  if (state->kind == CTAP_MLDSA_STREAM_PK) {
    if (state->keygen.phase == 0) memcpy(state->keygen.seed, state->seed, PRI_KEY_SIZE);
    ret = ml_dsa_65_keygen_streaming(state->stage, sizeof(state->stage_buf), &state->keygen, NULL);
  } else if (state->kind == CTAP_MLDSA_STREAM_SIG) {
    if (state->sign.phase == 0) memcpy(state->sign.seed, state->seed, PRI_KEY_SIZE);
    ret = ml_dsa_65_sign_seed_streaming(state->stage, sizeof(state->stage_buf), &state->sign, state->msg,
                                        state->msg_len, NULL, 0, state->tr);
  } else {
    return -1;
  }
  if (ret < 0) return -1;
  state->stage_len = (size_t)ret;
  return 0;
}

static int ctap_mldsa_stream_read_generated(CTAP_mldsa_stream_state *state, uint8_t *out, size_t max_len,
                                            size_t *written) {
  size_t copied = 0;

  while (copied < max_len && state->kind != CTAP_MLDSA_STREAM_NONE) {
    if (state->stage_off == state->stage_len) {
      if ((state->kind == CTAP_MLDSA_STREAM_PK && state->keygen.phase == 0 && state->stage_len != 0) ||
          (state->kind == CTAP_MLDSA_STREAM_SIG && state->sign.phase == 0 && state->stage_len != 0)) {
        state->kind = CTAP_MLDSA_STREAM_NONE;
        break;
      }
      if (ctap_mldsa_stream_fill_stage(state) < 0) return -1;
      if (state->stage_len == 0) return -1;
    }

    size_t n = MIN(state->stage_len - state->stage_off, max_len - copied);
    memcpy(out + copied, state->stage + state->stage_off, n);
    state->stage_off += n;
    copied += n;
  }

  *written = copied;
  return 0;
}

static int ctap_mldsa_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_mldsa_stream_state *state = (CTAP_mldsa_stream_state *)ctx;
  size_t copied = 0;

  while (copied < max_len) {
    if (state->prefix_off < state->prefix_len) {
      size_t n = MIN(state->prefix_len - state->prefix_off, max_len - copied);
      memcpy(out + copied, state->prefix + state->prefix_off, n);
      state->prefix_off += n;
      copied += n;
      continue;
    }

    if (state->kind != CTAP_MLDSA_STREAM_NONE) {
      size_t n = 0;
      if (ctap_mldsa_stream_read_generated(state, out + copied, max_len - copied, &n) < 0) return -1;
      copied += n;
      if (n != 0) continue;
    }

    if (state->suffix_off < state->suffix_len) {
      size_t n = MIN(state->suffix_len - state->suffix_off, max_len - copied);
      memcpy(out + copied, state->suffix + state->suffix_off, n);
      state->suffix_off += n;
      copied += n;
      continue;
    }
    break;
  }

  *written = copied;
  return 0;
}

static int ctap_mldsa65_tr_from_seed(const uint8_t seed[PRI_KEY_SIZE], uint8_t tr[MLDSA_TRBYTES], uint8_t *scratch,
                                     size_t scratch_len) {
  mldsa_keygen_state_t st = {0};
  int ret;
  if (!scratch || scratch_len == 0) return -1;
  memcpy(st.seed, seed, PRI_KEY_SIZE);
  ret = ml_dsa_65_keygen_streaming(scratch, scratch_len, &st, tr);
  if (ret < 0) return -1;
  while (st.phase != 0) {
    ret = ml_dsa_65_keygen_streaming(scratch, scratch_len, &st, NULL);
    if (ret < 0) return -1;
  }
  return 0;
}

static int ctap_make_credential_stream_add_segment(CTAP_make_credential_stream_segment_kind kind, const uint8_t *buf,
                                                   const char *path, CTAP_mldsa_stream_state *mldsa, size_t file_off,
                                                   size_t len) {
  if (mc_stream_state.segment_count >= CTAP_MC_STREAM_MAX_SEGMENTS) return -1;
  CTAP_make_credential_stream_segment *segment = &mc_stream_state.segments[mc_stream_state.segment_count++];
  segment->kind = kind;
  segment->buf = buf;
  segment->path = path;
  segment->mldsa = mldsa;
  segment->file_off = file_off;
  segment->len = len;
  segment->off = 0;
  mc_stream_state.total_len += len;
  mc_stream_state.prepared = true;
  return 0;
}

static int ctap_make_credential_stream_add_mem(const uint8_t *buf, size_t len) {
  if (len == 0) return 0;
  return ctap_make_credential_stream_add_segment(CTAP_MC_STREAM_SEG_MEM, buf, NULL, NULL, 0, len);
}

static int ctap_make_credential_stream_add_file(const char *path, size_t file_off, size_t len) {
  if (len == 0) return 0;
  return ctap_make_credential_stream_add_segment(CTAP_MC_STREAM_SEG_FILE, NULL, path, NULL, file_off, len);
}

static int ctap_make_credential_stream_add_mldsa(CTAP_mldsa_stream_state *mldsa, size_t len) {
  return ctap_make_credential_stream_add_segment(CTAP_MC_STREAM_SEG_MLDSA, NULL, NULL, mldsa, 0, len);
}

static int ctap_make_credential_stream_read(void *ctx, uint8_t *out, size_t max_len, size_t *written) {
  CTAP_make_credential_stream_state *state = (CTAP_make_credential_stream_state *)ctx;
  size_t copied = 0;

  while (copied < max_len && state->current_segment < state->segment_count) {
    CTAP_make_credential_stream_segment *segment = &state->segments[state->current_segment];
    if (segment->off == segment->len) {
      ++state->current_segment;
      continue;
    }

    size_t n = MIN(segment->len - segment->off, max_len - copied);
    size_t written_now = n;
    switch (segment->kind) {
    case CTAP_MC_STREAM_SEG_MEM:
      memcpy(out + copied, segment->buf + segment->off, n);
      break;
    case CTAP_MC_STREAM_SEG_FILE:
      if (read_file(segment->path, out + copied, segment->file_off + segment->off, n) < 0) return -1;
      break;
    case CTAP_MC_STREAM_SEG_MLDSA:
      if (ctap_mldsa_stream_read_generated(segment->mldsa, out + copied, n, &written_now) < 0) return -1;
      if (written_now == 0) return -1;
      break;
    }
    segment->off += written_now;
    copied += written_now;
  }

  *written = copied;
  return 0;
}

static int ctap_make_credential_stream_read_at(void *ctx, uint32_t offset, uint8_t *out, uint16_t max_len) {
  CTAP_make_credential_stream_state *state = (CTAP_make_credential_stream_state *)ctx;
  size_t written = 0;

  if (offset != state->emitted) return -1;
  if (ctap_make_credential_stream_read(ctx, out, max_len, &written) < 0) return -1;
  state->emitted += written;
  return (int)written;
}

static void ctap_credential_management_reset_state(void) { memset(&cred_mgmt_state, 0, sizeof(cred_mgmt_state)); }

static void ctap_get_assertion_reset_state(void) {
  memset(&ga_state, 0, sizeof(ga_state));
  uv = false;
  up = false;
  user_details = false;
  timer = 0;
}

static void ctap_get_assertion_save_state(const CTAP_get_assertion *src) {
  ga_state.parsed_params = src->parsed_params;
  memcpy(ga_state.rp_id_hash, src->rp_id_hash, sizeof(ga_state.rp_id_hash));
  memcpy(ga_state.client_data_hash, src->client_data_hash, sizeof(ga_state.client_data_hash));
  ga_state.allow_list_size = src->allow_list_size;
  ga_state.options = src->options;
  ga_state.ext_hmac_secret_data = src->ext_hmac_secret_data;
  ga_state.ext_cred_blob = src->ext_cred_blob;
  ga_state.ext_third_party_payment = src->ext_third_party_payment;
}

#ifdef TEST
void ctap_test_seed_get_next_assertion_state(void) {
  ctap_get_assertion_reset_state();
  last_cmd = CTAP_GET_ASSERTION;
  ga_state.number_of_credentials = 2;
  ga_state.credential_counter = 1;
  timer = device_get_tick();
}

void ctap_test_seed_credential_management_state(void) {
  ctap_credential_management_reset_state();
  last_cmd = CTAP_CREDENTIAL_MANAGEMENT;
  cred_mgmt_state.last_subcommand = CM_CMD_ENUMERATE_CREDENTIALS_BEGIN;
  cred_mgmt_state.next_idx = 7;
  cred_mgmt_state.total = 3;
  cred_mgmt_state.has_rp_filter = true;
  memset(cred_mgmt_state.rp_id_hash, 0x10, sizeof(cred_mgmt_state.rp_id_hash));
}

int ctap_test_credential_management_state_active(void) {
  return last_cmd == CTAP_CREDENTIAL_MANAGEMENT &&
         cred_mgmt_state.last_subcommand == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN && cred_mgmt_state.next_idx == 7 &&
         cred_mgmt_state.total == 3 && cred_mgmt_state.has_rp_filter && cred_mgmt_state.rp_id_hash[0] == 0x10;
}
#endif

#if ENABLE_NFC
static void ctap_nfc_pending_reset(void) {
  if (nfc_pending_state.request_in_file) write_file(CTAP_NFC_PENDING_FILE, NULL, 0, 0, 1);
  memset(&nfc_pending_state, 0, sizeof(nfc_pending_state));
}

static int ctap_nfc_pending_store(const uint8_t *req, size_t req_len, uint8_t allow_poll) {
  if (!req || req_len == 0 || req_len > CTAP_MAX_REQUEST_SIZE) return -1;
  ctap_nfc_pending_reset();
  nfc_pending_state.request_len = (uint16_t)req_len;
  if (req_len <= sizeof(nfc_pending_state.request)) {
    if (current_req_src.read) {
      if (ctap_req_read_payload_bytes(0, nfc_pending_state.request, req_len) < 0) return -1;
    } else {
      memcpy(nfc_pending_state.request, req, req_len);
    }
    nfc_pending_state.request_in_file = 0;
  } else {
    size_t written = 0;
    uint8_t buf[APDU_INCOMING_DATA_SIZE];
    while (written < req_len) {
      size_t chunk = MIN(sizeof(buf), req_len - written);
      if (current_req_src.read) {
        if (ctap_req_read_payload_bytes(written, buf, chunk) < 0) return -1;
      } else {
        memcpy(buf, req + written, chunk);
      }
      if (write_file(CTAP_NFC_PENDING_FILE, buf, (lfs_soff_t)written, (lfs_size_t)chunk, written == 0) < 0) return -1;
      written += chunk;
    }
    nfc_pending_state.request_in_file = 1;
  }
  nfc_pending_state.allow_poll = allow_poll;
  nfc_pending_state.active = 1;
  nfc_pending_state.keepalive_status = KEEPALIVE_STATUS_UPNEEDED;
  return 0;
}

static int ctap_nfc_wait_for_user_presence(uint8_t timeout_response) {
  if (!is_nfc() || !nfc_pending_state.active || !nfc_pending_state.allow_poll) return -1;
  if (nfc_pending_state.touch_granted) return -1;

  if (nfc_pending_state.wait_start == 0) {
    nfc_pending_state.wait_start = device_get_tick();
    // Testmode only auto-generates a touch while blinking. Start blinking once
    // and return a keepalive so the next NFC poll can complete the command.
    start_blinking_interval(0, 200);
#ifdef TEST
    testmode_emulate_user_presence();
#endif
    nfc_pending_state.keepalive_status = KEEPALIVE_STATUS_UPNEEDED;
    return CTAP_NFC_KEEPALIVE_PENDING;
  }

  if (get_touch_result() != TOUCH_NO) {
    set_touch_result(TOUCH_NO);
    stop_blinking();
    nfc_pending_state.touch_granted = 1;
    return -1;
  }

  if (!device_is_blinking()) {
    // A PC/SC reconnect can reinitialize the device while preserving this NFC
    // pending request. Restart the user-presence indication so later polls can
    // still complete instead of spinning forever in 0x9100 keepalive state.
    start_blinking_interval(0, 200);
#ifdef TEST
    testmode_emulate_user_presence();
#endif
  }

  if (device_get_tick() - nfc_pending_state.wait_start >= 30000) {
    stop_blinking();
    return timeout_response;
  }

  nfc_pending_state.keepalive_status = KEEPALIVE_STATUS_UPNEEDED;
  return CTAP_NFC_KEEPALIVE_PENDING;
}
#else
static void ctap_nfc_pending_reset(void) {}
#endif

void ctap_schedule_runtime_reset(void) { runtime_reset_pending = true; }

void ctap_deselect(void) {
  last_cmd = CTAP_INVALID_CMD;
  ctap_get_assertion_reset_state();
  ctap_credential_management_reset_state();
}

void ctap_poweroff(void) {
  current_cmd_src = CTAP_SRC_NONE;
  cert_write_active = false;
  cert_write_len = 0;
  // HID response teardown calls ctap_poweroff between stateful CM commands.
  ctap_nfc_pending_reset();
  if (pke_buffer_release(PKE_BUFFER_OWNER_CTAP) == 0) {
    pke_buffer_clear();
  }
}

uint8_t ctap_install(uint8_t reset) {
  CTAP_persistent_config persistent_cfg;
  const bool has_littlefs_state = ctap_littlefs_state_present();
  const bool has_complete_state = has_littlefs_state && ctap_sm2_config_read_platform(&ctap_sm2_attr) == 0 &&
                                  ctap_config_read_platform(&persistent_cfg) == 0;
  const bool runtime_reset = reset || runtime_reset_pending || !has_complete_state;
  // Reader reconnects may re-run ctap_install(0) without a real device reset.
  // Preserve in-flight CTAP command state in that case so CM/GA "next" commands
  // can continue across implicit PowerICC cycles.
  if (runtime_reset) {
    consecutive_pin_counter = 3;
    last_cmd = CTAP_INVALID_CMD;
    cert_write_active = false;
    cert_write_len = 0;
    ctap_get_assertion_reset_state();
    ctap_credential_management_reset_state();
  }
  current_cmd_src = CTAP_SRC_NONE;
  if (runtime_reset) {
    // PowerICC reconnects can call ctap_install(0) while an NFC host is still
    // polling a keepalive response; keep that pending state on plain reconnect.
    ctap_nfc_pending_reset();
  }
  cp_initialize(runtime_reset);
  runtime_reset_pending = false;
  // Platform-backed CTAP config is part of the install completion marker. If
  // either platform config is absent or invalid, rebuild CTAP state.
  if (!reset && has_complete_state) {
    DBG_MSG("CTAP initialized\n");
    return 0;
  }
  CTAP_dc_general_attr dc_attr = {0};
  if (write_file(DC_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(DC_FILE, DC_GENERAL_ATTR, &dc_attr, sizeof(dc_attr)) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(DC_META_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(CTAP_CERT_FILE, NULL, 0, 0, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, kh_key, 4) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  CTAP_persistent_config cfg;
  ctap_config_default(&cfg);
  if (ctap_config_store(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(MIN_PIN_RPIDS_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, HE_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memcpy(
      kh_key,
      (uint8_t[]){0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c},
      17);
  if (write_file(LB_FILE, kh_key, 0, 17, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  ctap_sm2_config_set_default();
  if (ctap_platform_sm2_config_write(&ctap_sm2_attr, sizeof(ctap_sm2_attr)) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  memzero(kh_key, sizeof(kh_key));
  DBG_MSG("CTAP reset and initialized\n");
  return 0;
}

int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != PRI_KEY_SIZE) EXCEPT(SW_WRONG_LENGTH);
  // initialize SM2 config
  ctap_sm2_config_set_default();
  if (ctap_platform_sm2_config_write(&ctap_sm2_attr, sizeof(ctap_sm2_attr)) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  return write_attr(CTAP_CERT_FILE, KEY_ATTR, DATA, LC);
}

int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC > MAX_CERT_SIZE) EXCEPT(SW_WRONG_LENGTH);
  if (!cert_write_active) {
    if (write_file(CTAP_CERT_FILE, DATA, 0, LC, 1) < 0) return -1;
    cert_write_len = LC;
  } else {
    if ((uint32_t)cert_write_len + LC > MAX_CERT_SIZE) {
      cert_write_active = false;
      cert_write_len = 0;
      EXCEPT(SW_WRONG_LENGTH);
    }
    if (append_file(CTAP_CERT_FILE, DATA, LC) < 0) {
      cert_write_active = false;
      cert_write_len = 0;
      return -1;
    }
    cert_write_len += LC;
  }
  cert_write_active = (CLA & 0x10) != 0;
  if (!cert_write_active) cert_write_len = 0;
  return 0;
}

int ctap_read_sm2_config(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  CTAP_sm2_attr attr;
  const int ret = ctap_sm2_config_read_platform(&attr);
  if (ret < 0) return ret;
  memcpy(RDATA, &attr, sizeof(attr));
  LL = sizeof(attr);
  return 0;
}

int ctap_write_sm2_config(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != sizeof(ctap_sm2_attr)) EXCEPT(SW_WRONG_LENGTH);
  CTAP_sm2_attr attr;
  memcpy(&attr, DATA, sizeof(attr));
  if (!ctap_sm2_algo_id_valid(attr.algo_id)) EXCEPT(SW_WRONG_DATA);
  const int ret = ctap_platform_sm2_config_write(&attr, sizeof(attr));
  if (ret < 0) return ret;
  ctap_sm2_attr = attr;
  return 0;
}

static int build_cose_key(uint8_t *data, int kty, int algo, int curve, bool has_y) {
  uint8_t buf[80];
  CborEncoder encoder, map_encoder;

  cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
  CborError ret = cbor_encoder_create_map(&encoder, &map_encoder, has_y ? 5 : 4);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_KTY);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, kty);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_ALG);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, algo);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_CRV);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, curve);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_X);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map_encoder, data, 32);
  CHECK_CBOR_RET(ret);
  if (has_y) {
    ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_Y);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map_encoder, data + 32, 32);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&encoder, &map_encoder);
  CHECK_CBOR_RET(ret);

  const int len = cbor_encoder_get_buffer_size(&encoder, buf);
  memcpy(data, buf, len);
  return len;
}

int ctap_consistency_check(void) {
  CTAP_dc_general_attr attr;
  if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (attr.pending_op != CTAP_DC_PENDING_NONE) {
    DBG_MSG("Rolling back credential operations\n");
    ctap_credential_management_reset_state();
    if (get_file_size(DC_FILE) >= (int)((attr.pending_index + 1) * sizeof(CTAP_discoverable_credential))) {
      CTAP_discoverable_credential dc;
      if (read_file(DC_FILE, &dc, (lfs_soff_t)(attr.pending_index * sizeof(CTAP_discoverable_credential)),
                    sizeof(CTAP_discoverable_credential)) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      if (!dc.deleted) {
        // Roll back an interrupted add by tombstoning the just-written
        // credential. For interrupted delete this is already true.
        DBG_MSG("Delete cred at %lu\n", (unsigned long)attr.pending_index);
        dc.deleted = true;
        if (write_file(DC_FILE, &dc, (lfs_soff_t)(attr.pending_index * sizeof(CTAP_discoverable_credential)),
                       sizeof(CTAP_discoverable_credential), 0) < 0)
          return CTAP2_ERR_UNHANDLED_REQUEST;
      }
    }
    // Metadata is denormalized for fast RP enumeration, so recompute it after
    // the credential file has been restored to a consistent state.
    uint8_t rebuild_err = ctap_rebuild_rp_meta_counts();
    if (rebuild_err) return rebuild_err;
    if (attr.pending_op == CTAP_DC_PENDING_DELETE && attr.numbers > 0) attr.numbers--;

    attr.pending_op = CTAP_DC_PENDING_NONE;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  return 0;
}

static int ctap_build_cose_key_for_alg(int32_t alg_type, uint8_t *public_key) {
  if (alg_type == COSE_ALG_ES256)
    return build_cose_key(public_key, COSE_KEY_KTY_EC2, COSE_ALG_ES256, COSE_KEY_CRV_P256, true);
  if (alg_type == COSE_ALG_EDDSA)
    return build_cose_key(public_key, COSE_KEY_KTY_OKP, COSE_ALG_EDDSA, COSE_KEY_CRV_ED25519, false);
  if (alg_type == ctap_sm2_attr.algo_id)
    return build_cose_key(public_key, COSE_KEY_KTY_EC2, ctap_sm2_attr.algo_id, ctap_sm2_attr.curve_id, true);
  return -1;
}

static size_t ctap_auth_data_len(size_t cose_key_size, size_t extension_size) {
  return 37 + AAGUID_SIZE + sizeof(uint16_t) + sizeof(credential_id) + cose_key_size + extension_size;
}

static uint8_t *ctap_write_auth_data_header(uint8_t *p, const uint8_t *rp_id_hash, uint8_t flags, uint32_t ctr) {
  memcpy(p, rp_id_hash, SHA256_DIGEST_LENGTH);
  p += SHA256_DIGEST_LENGTH;
  *p++ = flags;
  ctr = htobe32(ctr);
  memcpy(p, &ctr, sizeof(ctr));
  return p + sizeof(ctr);
}

static uint8_t *ctap_write_attested_credential_prefix(uint8_t *p, const credential_id *cid) {
  memcpy(p, aaguid, AAGUID_SIZE);
  p += AAGUID_SIZE;
  *p++ = HI(sizeof(credential_id));
  *p++ = LO(sizeof(credential_id));
  memcpy(p, cid, sizeof(*cid));
  return p + sizeof(*cid);
}

static uint8_t ctap_make_auth_data_from_material(uint8_t *rp_id_hash, uint8_t *buf, uint8_t flags,
                                                 const uint8_t *extension, size_t extension_size, size_t *len,
                                                 const credential_id *cid, const uint8_t *cose_key,
                                                 size_t cose_key_size, uint32_t ctr) {
  // See https://www.w3.org/TR/webauthn/#sec-authenticator-data
  // auth data is a byte string
  // --------------------------------------------------------------------------------
  //  Name       |  Length  | Description
  // ------------|----------|---------------------------------------------------------
  //  rp_id_hash |  32      | SHA256 of rp_id, we generate it outside this function
  //  flags      |  1       | 0: UP, 2: UV, 6: AT, 7: ED
  //  sign_count |  4       | 32-bit endian number
  //  attCred    |  var     | Exist iff in authenticatorMakeCredential request
  //             |          | 16-byte aaguid
  //             |          | 2-byte key handle length
  //             |          | key handle
  //             |          | public key (in COSE_key format)
  //  extension  |  var     | Build outside
  // --------------------------------------------------------------------------------
  size_t outLen = 37; // without attCred
  uint8_t *p = buf;
  if (*len < outLen) return CTAP2_ERR_LIMIT_EXCEEDED;

  p = ctap_write_auth_data_header(p, rp_id_hash, flags, ctr);

  if (flags & FLAGS_AT) {
    if (!cid || !cose_key || cose_key_size == 0) {
      DBG_MSG("Missing attested credential material\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    if (*len < outLen + AAGUID_SIZE + sizeof(uint16_t) + sizeof(*cid) + cose_key_size) {
      DBG_MSG("Attestation is too long\n");
      return CTAP2_ERR_LIMIT_EXCEEDED;
    }

    p = ctap_write_attested_credential_prefix(p, cid);
    memcpy(p, cose_key, cose_key_size);
    p += cose_key_size;
    outLen += AAGUID_SIZE + sizeof(uint16_t) + sizeof(*cid) + cose_key_size;
  }
  if (flags & FLAGS_ED) {
    if (*len < outLen + extension_size) {
      DBG_MSG("Extension is too long\n");
      return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    memcpy(p, extension, extension_size);
    p += extension_size;
    outLen += extension_size;
  }
  *len = outLen;
  return 0;
}

uint8_t ctap_make_auth_data(uint8_t *rp_id_hash, uint8_t *buf, uint8_t flags, const uint8_t *extension,
                            size_t extension_size, size_t *len, int32_t alg_type, bool dc, uint8_t cred_protect) {
  credential_id cid;
  uint8_t public_key[MAX_COSE_KEY_SIZE];
  size_t cose_key_size = 0;

  if (flags & FLAGS_AT) {
    // If no credProtect extension was included in the request the authenticator SHOULD use the default value of 1 for
    // compatibility with CTAP2.0 platforms.
    if (cred_protect == CRED_PROTECT_ABSENT) cred_protect = CRED_PROTECT_VERIFICATION_OPTIONAL;

    memcpy(cid.rp_id_hash, rp_id_hash, sizeof(cid.rp_id_hash));
    if (generate_key_handle(&cid, public_key, alg_type, (uint8_t)dc, cred_protect, false) < 0) {
      DBG_MSG("Fail to generate a key handle\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    int cose_key_size_ret = ctap_build_cose_key_for_alg(alg_type, public_key);
    if (cose_key_size_ret < 0) {
      DBG_MSG("Unknown algorithm type\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    cose_key_size = (size_t)cose_key_size_ret;
  }

  uint32_t ctr;
  if (increase_counter(&ctr) < 0) {
    DBG_MSG("Fail to increase the counter\n");
    return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  return ctap_make_auth_data_from_material(rp_id_hash, buf, flags, extension, extension_size, len,
                                           (flags & FLAGS_AT) ? &cid : NULL, public_key, cose_key_size, ctr);
}

/**
 * Encode a PublicKeyCredentialDescriptor: {id: <bytes>, type: "public-key"}
 */
static uint8_t cbor_encode_credential_id(CborEncoder *map, const credential_id *cid) {
  CborEncoder sub_map;
  int ret = cbor_encoder_create_map(map, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "id");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&sub_map, (const uint8_t *)cid, sizeof(credential_id));
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "type");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "public-key");
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(map, &sub_map);
  CHECK_CBOR_RET(ret);
  return 0;
}

/**
 * Encode a PublicKeyCredentialUserEntity.
 * @param detail If true, include name and displayName; otherwise only id.
 */
static uint8_t cbor_encode_user_entity(CborEncoder *map, const user_entity *user, bool detail) {
  CborEncoder sub_map;
  int ret = cbor_encoder_create_map(map, &sub_map, detail ? 3 : 1);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "id");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&sub_map, user->id, user->id_size);
  CHECK_CBOR_RET(ret);
  if (detail) {
    ret = cbor_encode_text_stringz(&sub_map, "name");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, user->name);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "displayName");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, user->display_name);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(map, &sub_map);
  CHECK_CBOR_RET(ret);
  return 0;
}

/**
 * Verify PIN/UV auth token for MC and GA commands.
 * Checks: token validity, permission, RP ID, user verified flag.
 * On success, associates the RP ID with the token.
 *
 * @return 0 on success, CTAP2 error code on failure.
 */
static uint8_t verify_pin_uv_auth_token(const uint8_t *client_data_hash, const uint8_t *pin_uv_auth_param,
                                        uint8_t pin_uv_auth_protocol, uint8_t permission, const uint8_t *rp_id_hash) {
  if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
  if (!cp_verify_pin_token(client_data_hash, CLIENT_DATA_HASH_SIZE, pin_uv_auth_param, pin_uv_auth_protocol)) {
    DBG_MSG("Fail to verify pin token\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (!cp_has_permission(permission)) {
    DBG_MSG("Fail to verify pin permission\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (!cp_verify_rp_id(rp_id_hash)) {
    DBG_MSG("Fail to verify pin rp id\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (!cp_get_user_verified_flag_value()) {
    DBG_MSG("userVerifiedFlagValue is false\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  cp_associate_rp_id(rp_id_hash);
  return 0;
}

static uint8_t ctap_store_discoverable_credential(const CTAP_make_credential *mc, const credential_id *cid,
                                                  CTAP_discoverable_credential *dc) {
  if (mc->options.rk != OPTION_TRUE) return 0;

  uint32_t n_dc;
  uint8_t err = ctap_dc_record_count(&n_dc);
  if (err) return err;
  uint32_t pos = n_dc;
  uint32_t first_deleted = UINT32_MAX;
  bool replacing_active = false;
  for (uint32_t i = 0; i != n_dc; ++i) {
    if (read_file(DC_FILE, dc, (lfs_soff_t)(i * sizeof(CTAP_discoverable_credential)),
                  sizeof(CTAP_discoverable_credential)) < 0) {
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    if (dc->deleted) {
      if (first_deleted == UINT32_MAX) first_deleted = i;
      continue;
    }
    if (memcmp_s(mc->rp_id_hash, dc->credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
        mc->user.id_size == dc->user.id_size && memcmp_s(mc->user.id, dc->user.id, mc->user.id_size) == 0) {
      pos = i;
      replacing_active = true;
      break;
    }
  }
  if (!replacing_active && first_deleted != UINT32_MAX) pos = first_deleted;
  bool append_dc = pos == n_dc;
  bool new_credential = !replacing_active;

  uint32_t first_deleted_meta = UINT32_MAX, meta_pos = 0, n_meta = 0;
  CTAP_rp_meta meta = {0};
  err = ctap_find_rp_meta(mc->rp_id_hash, &meta, &meta_pos, &first_deleted_meta, &n_meta);
  bool has_meta = err == 0;
  if (err != 0 && err != CTAP2_ERR_NO_CREDENTIALS) return err;
  if (!has_meta) {
    meta_pos = first_deleted_meta != UINT32_MAX ? first_deleted_meta : n_meta;
    memset(&meta, 0, sizeof(meta));
    memcpy(meta.rp_id_hash, mc->rp_id_hash, SHA256_DIGEST_LENGTH);
    memcpy(meta.rp_id, mc->rp_id, MAX_STORED_RPID_LENGTH);
    meta.rp_id_len = (uint8_t)mc->rp_id_len;
    meta.deleted = false;
  }
  bool append_meta = !has_meta && first_deleted_meta == UINT32_MAX;

  // Only appends need new file capacity. Replacing an active credential or
  // reusing tombstoned DC/RP-meta records overwrites existing bytes.
  size_t required = sizeof(CTAP_dc_general_attr) + (append_dc ? sizeof(CTAP_discoverable_credential) : 0) +
                    (append_meta ? sizeof(CTAP_rp_meta) : 0);
  int has_space = fs_has_free_space((lfs_size_t)required, CTAP_FS_RESERVE_BYTES);
  if (has_space < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (has_space == 0) return CTAP2_ERR_KEY_STORE_FULL;

  memcpy(&dc->credential_id, cid, sizeof(*cid));
  memcpy(&dc->user, &mc->user, sizeof(user_entity));
  dc->has_large_blob_key = mc->ext_large_blob_key;
  dc->cred_blob_len = 0;
  if (mc->ext_has_cred_blob && mc->ext_cred_blob_len <= MAX_CRED_BLOB_LENGTH) {
    dc->cred_blob_len = mc->ext_cred_blob_len;
    memcpy(dc->cred_blob, mc->ext_cred_blob, mc->ext_cred_blob_len);
  }
  dc->deleted = false;

  CTAP_dc_general_attr attr;
  if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (new_credential) {
    attr.pending_op = CTAP_DC_PENDING_ADD;
    attr.pending_index = pos;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  int write_err = write_file(DC_FILE, dc, (lfs_soff_t)(pos * sizeof(CTAP_discoverable_credential)),
                             sizeof(CTAP_discoverable_credential), 0);
  if (write_err < 0) return ctap_storage_write_result(write_err);

  memcpy(meta.rp_id_hash, mc->rp_id_hash, SHA256_DIGEST_LENGTH);
  memcpy(meta.rp_id, mc->rp_id, MAX_STORED_RPID_LENGTH);
  meta.rp_id_len = (uint8_t)mc->rp_id_len;
  meta.deleted = false;
  if (new_credential || !has_meta) ++meta.live_count;
  write_err = write_file(DC_META_FILE, &meta, (lfs_soff_t)(meta_pos * sizeof(CTAP_rp_meta)), sizeof(CTAP_rp_meta), 0);
  if (write_err < 0) return ctap_storage_write_result(write_err);
  attr.pending_op = CTAP_DC_PENDING_NONE;
  if (new_credential) ++attr.numbers;
  if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  return 0;
}

static size_t ctap_hmac_secret_salt_len(const CTAP_hmac_secret_ext *hmac) {
  return hmac->pin_protocol == 1 ? hmac->salt_enc_len : hmac->salt_enc_len - HMAC_SECRET_SALT_IV_SIZE;
}

static uint8_t ctap_prepare_hmac_secret_input(CTAP_hmac_secret_ext *hmac) {
  if (cp_decapsulate(hmac->key_agreement, hmac->pin_protocol) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  DBG_MSG("Shared secret: ");
  PRINT_HEX(hmac->key_agreement, hmac->pin_protocol == 2 ? SHARED_SECRET_SIZE_P2 : SHARED_SECRET_SIZE_P1);
  if (!cp_verify(hmac->key_agreement, SHARED_SECRET_SIZE_HMAC, hmac->salt_enc, hmac->salt_enc_len, hmac->salt_auth,
                 hmac->pin_protocol)) {
    ERR_MSG("Hmac verification failed\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  if (cp_decrypt(hmac->key_agreement, hmac->salt_enc, hmac->salt_enc_len, hmac->salt_enc, hmac->pin_protocol) != 0) {
    ERR_MSG("Hmac decryption failed\n");
    return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  return 0;
}

static uint8_t ctap_build_hmac_secret_output(const CTAP_hmac_secret_ext *hmac, const credential_id *cid, bool uv,
                                             uint8_t *output, size_t *output_len) {
  const size_t salt_len = ctap_hmac_secret_salt_len(hmac);
  DBG_MSG("hmac-secret-salt: ");
  PRINT_HEX(hmac->salt_enc, salt_len);
  if (make_hmac_secret_output(cid->nonce, hmac->salt_enc, (uint8_t)salt_len, output, uv) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  DBG_MSG("hmac-secret %s UV (plain): ", uv ? "with" : "without");
  PRINT_HEX(output, salt_len);
  if (cp_encrypt(hmac->key_agreement, output, salt_len, output, hmac->pin_protocol) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  *output_len = hmac->salt_enc_len;
  DBG_MSG("hmac-secret output: ");
  PRINT_HEX(output, *output_len);
  return 0;
}

static uint8_t ctap_get_assertion_prepare_hmac_secret(void) {
  if (ga_state.credential_counter != 0) return 0;
  // If "up" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION.
  if (!up) return CTAP2_ERR_UNSUPPORTED_OPTION;
  return ctap_prepare_hmac_secret_input(&ga_state.ext_hmac_secret_data);
}

static uint8_t ctap_make_credential_build_extensions(const CTAP_make_credential *mc, const credential_id *cid, bool uv,
                                                     bool ext_min_pin_authorized,
                                                     uint8_t *extension_buffer, size_t extension_buffer_size,
                                                     size_t *extension_size) {
  *extension_size = 0;
  uint8_t extension_map_items = (mc->ext_hmac_secret ? 1 : 0) + (mc->ext_hmac_secret_mc ? 1 : 0) +
                                (ext_min_pin_authorized ? 1 : 0) +
                                // largeBlobKey has no outputs here
                                (mc->ext_cred_protect != CRED_PROTECT_ABSENT ? 1 : 0) + (mc->ext_has_cred_blob ? 1 : 0);
  if (extension_map_items == 0) return 0;

  CborEncoder extension_encoder, map;
  int ret;
  cbor_encoder_init(&extension_encoder, extension_buffer, extension_buffer_size, 0);
  ret = cbor_encoder_create_map(&extension_encoder, &map, extension_map_items);
  CHECK_CBOR_RET(ret);

  if (mc->ext_has_cred_blob) {
    bool accepted = false;
    if (mc->ext_cred_blob_len <= MAX_CRED_BLOB_LENGTH && mc->options.rk == OPTION_TRUE) {
      accepted = true;
    }
    ret = cbor_encode_text_stringz(&map, "credBlob");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&map, accepted);
    CHECK_CBOR_RET(ret);
  }
  if (mc->ext_cred_protect != CRED_PROTECT_ABSENT) {
    ret = cbor_encode_text_stringz(&map, "credProtect");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, mc->ext_cred_protect);
    CHECK_CBOR_RET(ret);
  }
  if (mc->ext_hmac_secret) {
    ret = cbor_encode_text_stringz(&map, "hmac-secret");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&map, true);
    CHECK_CBOR_RET(ret);
  } else if (mc->ext_hmac_secret_mc) {
    return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  if (ext_min_pin_authorized) {
    ret = cbor_encode_text_stringz(&map, "minPinLength");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_uint(&map, ctap_config_get_min_pin_length());
    CHECK_CBOR_RET(ret);
  }
  if (mc->ext_hmac_secret_mc) {
    CTAP_hmac_secret_ext hmac = mc->ext_hmac_secret_data;
    uint8_t hmac_secret_output[HMAC_SECRET_SALT_IV_SIZE + HMAC_SECRET_SALT_SIZE];
    size_t hmac_secret_output_len = 0;
    uint8_t err = ctap_prepare_hmac_secret_input(&hmac);
    if (err != 0) {
      memzero(&hmac, sizeof(hmac));
      return err;
    }
    err = ctap_build_hmac_secret_output(&hmac, cid, uv, hmac_secret_output, &hmac_secret_output_len);
    memzero(&hmac, sizeof(hmac));
    if (err != 0) return err;
    ret = cbor_encode_text_stringz(&map, "hmac-secret-mc");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, hmac_secret_output, hmac_secret_output_len);
    memzero(hmac_secret_output, sizeof(hmac_secret_output));
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&extension_encoder, &map);
  CHECK_CBOR_RET(ret);
  *extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
  DBG_MSG("extension_size=%zu\n", *extension_size);
  return 0;
}

static uint8_t ctap_prepare_make_credential_response(CborEncoder *encoder, CTAP_make_credential *mc, bool uv,
                                                     bool ext_min_pin_authorized) {
  CTAP_mldsa_stream_state *state = &mldsa_stream_state;
  credential_id cid;
  CTAP_discoverable_credential dc = {0};
  uint8_t cred_protect =
      mc->ext_cred_protect == CRED_PROTECT_ABSENT ? CRED_PROTECT_VERIFICATION_OPTIONAL : mc->ext_cred_protect;
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  size_t extension_size = 0;
  uint8_t data_buf[sizeof(CTAP_auth_data)];
  bool mldsa = mc->alg_type == COSE_ALG_ML_DSA_65;
  uint8_t public_key[MAX_COSE_KEY_SIZE];
  uint8_t *prefix =
      mldsa ? state->prefix : (stream_make_credential_response ? applet_session_scratch.buffer : encoder->data.ptr);
  uint8_t *p = prefix;
  sha256_ctx_t sha256;
  size_t cert_prefix_len;
  size_t sig_len;
  int cert_len;
  size_t cose_key_size;
  uint32_t ctr;

  if (mldsa && !stream_make_credential_response) return CTAP2_ERR_LIMIT_EXCEEDED;
  if (mldsa) {
    memset(state, 0, sizeof(*state));
    state->stage = state->stage_buf;
  }

  memcpy(cid.rp_id_hash, mc->rp_id_hash, sizeof(cid.rp_id_hash));
  if (generate_key_handle(&cid, mldsa ? state->seed : public_key, mc->alg_type, mc->options.rk == OPTION_TRUE,
                          cred_protect, mc->ext_third_party_payment) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;

  uint8_t err = ctap_make_credential_build_extensions(mc, &cid, uv, ext_min_pin_authorized, extension_buffer,
                                                      sizeof(extension_buffer), &extension_size);
  if (err != 0) return err;
  const uint8_t flags = FLAGS_AT | (extension_size > 0 ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | FLAGS_UP;

  if (increase_counter(&ctr) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  err = ctap_store_discoverable_credential(mc, &cid, &dc);
  if (err) return err;

  if (mldsa) {
    int cose_key_prefix_size = ctap_mldsa65_cose_prefix_size();
    if (cose_key_prefix_size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cose_key_size = (size_t)cose_key_prefix_size + MLDSA_PK_BYTES;
  } else {
    int cose_key_size_ret = ctap_build_cose_key_for_alg(mc->alg_type, public_key);
    if (cose_key_size_ret < 0) {
      DBG_MSG("Unknown algorithm type\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    cose_key_size = (size_t)cose_key_size_ret;
  }

  if (stream_make_credential_response) *p++ = 0;
  if (cbor_put_uint(&p, 3 + (mc->ext_large_blob_key ? 1 : 0), 0xA0) < 0 || cbor_put_int(&p, MC_RESP_FMT) < 0 ||
      cbor_put_text(&p, "packed") < 0 || cbor_put_int(&p, MC_RESP_AUTH_DATA) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;

  sha256_init(&sha256);
  if (mldsa) {
    const size_t auth_len = ctap_auth_data_len(cose_key_size, extension_size);
    uint8_t *auth_data_start;
    if (cbor_put_bytes_header(&p, auth_len) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    auth_data_start = p;
    p = ctap_write_auth_data_header(p, mc->rp_id_hash, flags, ctr);
    p = ctap_write_attested_credential_prefix(p, &cid);
    if (cbor_put_mldsa65_cose_prefix(&p) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    state->prefix_len = (size_t)(p - state->prefix);
    if (state->prefix_len > sizeof(state->prefix)) return CTAP2_ERR_LIMIT_EXCEEDED;
    sha256_update(&sha256, auth_data_start, p - auth_data_start);

    memset(&state->keygen, 0, sizeof(state->keygen));
    memcpy(state->keygen.seed, state->seed, PRI_KEY_SIZE);
    do {
      KEEPALIVE();
      int pk_len = ml_dsa_65_keygen_streaming(state->stage, sizeof(state->stage_buf), &state->keygen, NULL);
      if (pk_len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (pk_len != 0) sha256_update(&sha256, state->stage, (size_t)pk_len);
    } while (state->keygen.phase != 0);
    if (extension_size != 0) sha256_update(&sha256, extension_buffer, extension_size);
  } else {
    const size_t auth_data_len = ctap_auth_data_len(cose_key_size, extension_size);
    size_t len = sizeof(data_buf);
    if (stream_make_credential_response) {
      const size_t max_prefix_overhead = 32;
      const size_t max_suffix_without_cert = 160;
      const size_t max_tail = mc->ext_large_blob_key ? 35 : 0;
      if (auth_data_len + max_prefix_overhead + max_suffix_without_cert + max_tail > sizeof(applet_session_scratch.buffer))
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    if (auth_data_len > sizeof(data_buf)) return CTAP2_ERR_LIMIT_EXCEEDED;
    err = ctap_make_auth_data_from_material(mc->rp_id_hash, data_buf, flags, extension_buffer, extension_size, &len,
                                            &cid, public_key, cose_key_size, ctr);
    if (err != 0) return err;
    if (len != auth_data_len) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cbor_put_bytes_header(&p, auth_data_len) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(p, data_buf, auth_data_len);
    p += auth_data_len;
    sha256_update(&sha256, data_buf, auth_data_len);
  }
  sha256_update(&sha256, mc->client_data_hash, sizeof(mc->client_data_hash));
  sha256_final(&sha256, data_buf);
  sig_len = sign_with_device_key(data_buf, PRIVATE_KEY_LENGTH[SECP256R1], data_buf);
  if (!sig_len) return CTAP2_ERR_UNHANDLED_REQUEST;

  uint8_t *suffix = mldsa ? state->suffix : p;
  uint8_t *q = suffix;
  if (mldsa && extension_size + 160 + (mc->ext_large_blob_key ? 35 : 0) > sizeof(state->suffix))
    return CTAP2_ERR_LIMIT_EXCEEDED;
  if (mldsa && extension_size != 0) {
    memcpy(q, extension_buffer, extension_size);
    q += extension_size;
  }
  if (cbor_put_int(&q, MC_RESP_ATT_STMT) < 0 || cbor_put_uint(&q, 3, 0xA0) < 0 || cbor_put_text(&q, "alg") < 0 ||
      cbor_put_int(&q, COSE_ALG_ES256) < 0 || cbor_put_text(&q, "sig") < 0 || cbor_put_bytes_header(&q, sig_len) < 0)
    return CTAP2_ERR_UNHANDLED_REQUEST;
  memcpy(q, data_buf, sig_len);
  q += sig_len;
  if (cbor_put_text(&q, "x5c") < 0 || cbor_put_uint(&q, 1, 0x80) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  cert_len = get_file_size(CTAP_CERT_FILE);
  if (cert_len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (cbor_put_bytes_header(&q, (size_t)cert_len) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  cert_prefix_len = (size_t)(q - suffix);

  if (!stream_make_credential_response) {
    if (get_cert(q) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    q += cert_len;
  }

  uint8_t *tail = q;
  if (mc->ext_large_blob_key) {
    uint8_t large_blob_key[LARGE_BLOB_KEY_SIZE];
    if (make_large_blob_key(cid.nonce, large_blob_key) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cbor_put_int(&q, MC_RESP_LARGE_BLOB_KEY) < 0 || cbor_put_bytes_header(&q, LARGE_BLOB_KEY_SIZE) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(q, large_blob_key, LARGE_BLOB_KEY_SIZE);
    q += LARGE_BLOB_KEY_SIZE;
    memzero(large_blob_key, sizeof(large_blob_key));
  }

  if (mldsa) {
    state->suffix_len = (size_t)(q - state->suffix);
    state->kind = CTAP_MLDSA_STREAM_PK;
    memset(&state->keygen, 0, sizeof(state->keygen));
    state->stage_len = 0;
    state->stage_off = 0;
    state->total_len = state->prefix_len + MLDSA_PK_BYTES + state->suffix_len + (size_t)cert_len;
  }

  if (stream_make_credential_response) {
    const size_t prefix_len = mldsa ? state->prefix_len : (size_t)(p - prefix);
    const size_t tail_len = mldsa ? state->suffix_len - cert_prefix_len : (size_t)(q - tail);
    if (!mldsa && (prefix_len > sizeof(applet_session_scratch.buffer) ||
                   cert_prefix_len > sizeof(applet_session_scratch.buffer) - prefix_len ||
                   tail_len > sizeof(applet_session_scratch.buffer) - prefix_len - cert_prefix_len))
      return CTAP2_ERR_LIMIT_EXCEEDED;
    if (ctap_make_credential_stream_add_mem(prefix, prefix_len) < 0 ||
        (mldsa && ctap_make_credential_stream_add_mldsa(state, MLDSA_PK_BYTES) < 0) ||
        ctap_make_credential_stream_add_mem(mldsa ? state->suffix : suffix, cert_prefix_len) < 0 ||
        ctap_make_credential_stream_add_file(CTAP_CERT_FILE, 0, (size_t)cert_len) < 0 ||
        ctap_make_credential_stream_add_mem(tail, tail_len) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    mc_stream_state.prepared = true;
    if (mldsa) {
      DBG_MSG("makeCredential stream prefix=%zu mldsa-pk=%u suffix=%zu cert=%d total=%zu\n", state->prefix_len,
              MLDSA_PK_BYTES, state->suffix_len, cert_len, mc_stream_state.total_len);
    } else {
      DBG_MSG("makeCredential stream prefix=%zu cert=%d suffix=%zu total=%zu\n", prefix_len, cert_len, tail_len,
              mc_stream_state.total_len);
    }
  } else {
    encoder->data.ptr = q;
  }

  return 0;
}

static uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg
  CborParser parser;
  CTAP_make_credential mc;

  ctap_req_src_t param_src = ctap_param_req_src();
  int ret = current_req_src.read ? parse_make_credential_src(&parser, &mc, &param_src, len)
                                 : parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);
  ctap_req_lifetime_end();

  ret = ctap_consistency_check();
  CHECK_PARSER_RET(ret);
  KEEPALIVE();

  // 1. If authenticator supports clientPin features and the platform sends a zero length pin_uv_auth_param
  if ((mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && mc.pin_uv_auth_param_len == 0) {
    // a. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    // b. If the user declines permission, or the operation times out, then end the operation by returning
    //    CTAP2_ERR_OPERATION_DENIED.
    WAIT(CTAP2_ERR_OPERATION_DENIED);
    // c. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
    //    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    if (has_pin())
      return CTAP2_ERR_PIN_INVALID;
    else
      return CTAP2_ERR_PIN_NOT_SET;
  }

  // 2. If the pin_uv_auth_param parameter is present
  //   a. If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
  //     > This has been processed when parsing.
  //   b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
  if ((mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && !(mc.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
    DBG_MSG("Missing required pin_uv_auth_protocol\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }
  // 3. Validate pubKeyCredParams with the following steps
  //    > This has been processed when parsing.

  // 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as
  // false.
  bool uv = false; // up is always true, see 14.c

  // 5. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (mc.options.uv == OPTION_ABSENT) mc.options.uv = OPTION_FALSE;
  //    b. If the pin_uv_auth_param is present, let the "uv" option be treated as being present with the value false.
  if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) mc.options.uv = OPTION_FALSE;
  //    c. If the "uv" option is true then
  if (mc.options.uv == OPTION_TRUE) {
    //     1) If the authenticator does not support a built-in user verification method end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
    DBG_MSG("Rule 5-c-1 not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
    //     2) [N/A] If the built-in user verification method has not yet been enabled, end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
  }
  //    d. If the "rk" option is present then: DO NOTHING
  //    e. Else: (the "rk" option is absent): Let the "rk" option be treated as being present with the value false.
  if (mc.options.rk == OPTION_ABSENT) mc.options.rk = OPTION_FALSE;
  //    f. If the "up" option is present then:
  //       If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
  if (mc.options.up == OPTION_FALSE) {
    DBG_MSG("Rule 5-f not satisfied\n");
    return CTAP2_ERR_INVALID_OPTION;
  }
  //    g. If the "up" option is absent, let the "up" option be treated as being present with the value true
  mc.options.up = OPTION_TRUE;

  // 6. If the alwaysUv option ID is present and true
  if (ctap_config_always_uv_enabled()) {
    if (!(mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) return CTAP2_ERR_PUAT_REQUIRED;
  }

  // 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response
  //    If the following statements are all true:
  //    a) The authenticator is protected by some form of user verification.
  //    b) [ALWAYS TRUE] The "uv" option is set to false.
  //    c) The pin_uv_auth_param parameter is not present.
  //    d) The "rk" option is present and set to true.
  if (has_pin() /* a) */ && (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0 /* c) */ &&
      mc.options.rk == OPTION_TRUE) {
    // If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    // end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    DBG_MSG("Rule 7 not satisfied\n");
    return CTAP2_ERR_PUAT_REQUIRED;
    // [N/A] Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
  }

  // 8. [N/A] Else (the makeCredUvNotRqd option ID is present with the value false or is absent)

  // 9. [N/A] If the enterpriseAttestation parameter is present

  // 10. If the following statements are all true
  //     a) "rk" and "uv" [ALWAYS TRUE] options are both set to false or omitted.
  //     b) [ALWAYS TRUE] the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value
  //     true. c) the pin_uv_auth_param parameter is not present. Then go to Step 12.
  if (!ctap_config_always_uv_enabled() && mc.options.rk == OPTION_FALSE &&
      (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0) {
    DBG_MSG("Rule 10 satisfied, go to Step 12\n");
    goto step12;
  }

  // 11. If the authenticator is protected by some form of user verification, then:
  if (has_pin()) {
    //   11.1 If pin_uv_auth_param parameter is present (implying the "uv" option is false (see Step 5)):
    if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
      uint8_t err = verify_pin_uv_auth_token(mc.client_data_hash, mc.pin_uv_auth_param, mc.pin_uv_auth_protocol,
                                             CP_PERMISSION_MC, mc.rp_id_hash);
      if (err) {
        return err;
      } else {
        uv = true;
      }
    }
    //   11.2 [N/A] If the "uv" option is present and set to true
  }

step12:
  // 12. If the exclude_list parameter is present and contains a credential ID created by this authenticator,
  //     that is bound to the specified rp.id:
  if (mc.exclude_list_size > 0) {
    for (size_t i = 0; i < mc.exclude_list_size; ++i) {
      ecc_key_t key;
      credential_id *kh = &mc.exclude_list[i];
      // compare rp_id first
      if (memcmp_s(kh->rp_id_hash, mc.rp_id_hash, sizeof(kh->rp_id_hash)) != 0) goto next_exclude_list;
      // then verify key handle and get private key in rp_id_hash
      ret = verify_key_handle(kh, &key);
      memzero(&key, sizeof(key));
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (ret == 0) {
        // a) If the credential's credProtect value is not userVerificationRequired
        if (credential_cred_protect(kh) != CRED_PROTECT_VERIFICATION_REQUIRED ||
            // b) Else (implying the credential's credProtect value is userVerificationRequired)
            //    AND If the "uv" bit is true in the response:
            (credential_cred_protect(kh) == CRED_PROTECT_VERIFICATION_REQUIRED && uv)) {

          //    i. Let userPresentFlagValue be false.
          bool userPresentFlagValue = false;
          //    ii. If the pinUvAuthParam parameter is present then let userPresentFlagValue be the result of calling
          //        getUserPresentFlagValue().
          if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) userPresentFlagValue = cp_get_user_present_flag_value();
          //    iii. [N/A] Else, if evidence of user interaction was provided as part of Step 11 let
          //    userPresentFlagValue be true. iv. If userPresentFlagValue is false, then:
          //        (1) Wait for user presence.
          //        (2) Regardless of whether user presence is obtained or the authenticator times out,
          //            terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
          if (!userPresentFlagValue) WAIT(CTAP2_ERR_CREDENTIAL_EXCLUDED);
          //    v. Else, (implying userPresentFlagValue is true) terminate this procedure and return
          //    CTAP2_ERR_CREDENTIAL_EXCLUDED.
          return CTAP2_ERR_CREDENTIAL_EXCLUDED;

          // c) Else (implying user verification was not collected in Step 11),
          //    remove the credential from the excludeList and continue parsing the rest of the list.
        } else {
          DBG_MSG("Ignore this Exclude ID\n");
        }
      }
    next_exclude_list:
      continue;
    }
  }

  // 13. [N/A] If evidence of user interaction was provided as part of Step 11

  // 14. [ALWAYS TRUE] If the "up" option is set to true
  //     a) If the pin_uv_auth_param parameter is present then:
  if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
    if (!cp_get_user_present_flag_value()) {
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
  } else {
    //   b) Else (implying the pin_uv_auth_param parameter is not present)
    //     1. [ALWAYS TRUE] If the "up" bit is false in the response :
    WAIT(CTAP2_ERR_OPERATION_DENIED);
  }
  //     c) [N/A] Set the "up" bit to true in the response
  //     d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  // 15. If the extensions parameter is present:
  bool ext_min_pin_authorized = mc.ext_min_pin_length && ctap_min_pin_rpid_authorized(mc.rp_id_full, mc.rp_id_full_len);
  if (mc.ext_large_blob_key) {
    if (mc.options.rk != OPTION_TRUE) {
      DBG_MSG("largeBlobKey requires rk\n");
      return CTAP2_ERR_INVALID_OPTION;
    }
    // Generate key in Step 17
  }

  return ctap_prepare_make_credential_response(encoder, &mc, uv, ext_min_pin_authorized);
}

static void ecc_key_cleanup(ecc_key_t *k) { memzero(k, sizeof(*k)); }

static uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *params, size_t len, bool in_get_next_assertion) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
  CTAP_discoverable_credential dc = {0}; // We use dc to store the selected credential
  uint8_t data_buf[sizeof(CTAP_auth_data) + CLIENT_DATA_HASH_SIZE];
  // Auto-zero on every scope exit so partial private-key material from
  // verify_key_handle / ck_read_key never lingers on the stack across the many
  // CHECK_*/EXCEPT/early-return paths in this function.
  ecc_key_t key __attribute__((cleanup(ecc_key_cleanup))) = {0};
  CborParser parser;
  int ret;

  if (!in_get_next_assertion) {
    ga_state.credential_counter = 0;
    ga_state.number_of_credentials = 0;
    ga_state.next_dc_idx = 0;
    ret = ctap_consistency_check();
    CHECK_PARSER_RET(ret);
  } else {
    ctap_req_lifetime_end();
    // GET_NEXT_ASSERTION
    // 1. If authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
    if (last_cmd != CTAP_GET_ASSERTION && last_cmd != CTAP_GET_NEXT_ASSERTION) return CTAP2_ERR_NOT_ALLOWED;
    // 2. If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
    if (ga_state.credential_counter >= ga_state.number_of_credentials) return CTAP2_ERR_NOT_ALLOWED;
    // 3. If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than
    //    30 seconds, discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
    //    This step is OPTIONAL if transport is done over NFC.
    if (device_get_tick() - timer > 30000) return CTAP2_ERR_NOT_ALLOWED;
    // 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
    // 5. Update the response to include the selected credential's publicKeyCredentialUserEntity information.
    //    User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be
    //    returned if user verification was not done by the authenticator in the original authenticatorGetAssertion
    //    call.
    // 6. Sign the client_data_hash along with authData with the selected credential.
    goto step7;
    // 7. Reset the timer. This step is OPTIONAL if transport is done over NFC.
    // 8. Increment credentialCounter.
    // > Process at the end of this function.
  }
  ctap_req_src_t param_src = ctap_param_req_src();
  ret = current_req_src.read ? parse_get_assertion_src(&parser, &ga, &param_src, len)
                             : parse_get_assertion(&parser, &ga, params, len);
  CHECK_PARSER_RET(ret);
  ctap_get_assertion_save_state(&ga);
  ctap_req_lifetime_end();
  KEEPALIVE();

  // 1. If authenticator supports clientPin features and the platform sends a zero length pin_uv_auth_param
  if ((ga_state.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && ga.pin_uv_auth_param_len == 0) {
    // a. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    // b. If the user declines permission, or the operation times out, then end the operation by returning
    //    CTAP2_ERR_OPERATION_DENIED.
    WAIT(CTAP2_ERR_OPERATION_DENIED);
    // c. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
    //    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    if (has_pin())
      return CTAP2_ERR_PIN_INVALID;
    else
      return CTAP2_ERR_PIN_NOT_SET;
  }

  // 2. If the pin_uv_auth_param parameter is present
  //   a. If the pinUvAuthProtocol parameter's value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
  //     > This has been processed when parsing.
  //   b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
  if ((ga_state.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && !(ga_state.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
    DBG_MSG("Missing required pin_uv_auth_protocol\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }

  // 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as
  // false.
  uv = false;
  up = false;

  // 4. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (ga_state.options.uv == OPTION_ABSENT) ga_state.options.uv = OPTION_FALSE;
  //    b. If the pin_uv_auth_param is present, let the "uv" option be treated as being present with the value false.
  if (ga_state.parsed_params & PARAM_PIN_UV_AUTH_PARAM) ga_state.options.uv = OPTION_FALSE;
  //    c. If the "uv" option is true then
  if (ga_state.options.uv == OPTION_TRUE) {
    //     1) If the authenticator does not support a built-in user verification method end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
    DBG_MSG("Rule 4-c-1 not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
    //     2) [N/A] If the built-in user verification method has not yet been enabled, end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
  }
  //    d. If the "rk" option is present then: Return CTAP2_ERR_UNSUPPORTED_OPTION.
  if (ga_state.options.rk != OPTION_ABSENT) {
    DBG_MSG("Rule 4-d not satisfied.\n");
    return CTAP2_ERR_UNSUPPORTED_OPTION;
  }
  //    e. If the "up" option is not present then: Let the "up" option be treated as being present with the value true.
  if (ga_state.options.up == OPTION_ABSENT) ga_state.options.up = OPTION_TRUE;

  // 5. If the alwaysUv option ID is present and true
  if (ctap_config_always_uv_enabled() && !(ga_state.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
    return CTAP2_ERR_PUAT_REQUIRED;
  }

  // 6. If authenticator is protected by some form of user verification, then:
  //    6.2 [N/A] If the "uv" option is present and set to true
  //    6.1 If pin_uv_auth_param parameter is present
  if (has_pin() && (ga_state.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
    uint8_t err = verify_pin_uv_auth_token(ga_state.client_data_hash, ga.pin_uv_auth_param, ga.pin_uv_auth_protocol,
                                           CP_PERMISSION_GA, ga_state.rp_id_hash);
    if (err) return err;
    uv = true;
  }

step7:
  // 7. Locate all credentials that are eligible for retrieval under the specified criteria
  //    a) If the allow_list parameter is present and is non-empty, locate all denoted credentials created by this
  //       authenticator and bound to the specified rp_id.
  //    b) If an allow_list is not present, locate all discoverable credentials that are created by this authenticator
  //       and bound to the specified rp_id.
  //    c) Create an applicable credentials list populated with the located credentials.
  //    d) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationRequired, and the "uv" bit is false in the response, remove that credential from the
  //       applicable credentials list.
  //    e) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationOptionalWithCredentialIDList and there is no allow_list passed by the client and the "uv"
  //       bit is false in the response, remove that credential from the applicable credentials list.
  //    f) If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
  //    g) Let numberOfCredentials be the number of applicable credentials found.
  // NOTE: only one credential is used as stated in Step 11 & 12; therefore, we select that credential according to
  //       Step 11 & 12:
  // 11. If the allow_list parameter is present:
  //     Select any credential from the applicable credentials list.
  //     Delete the numberOfCredentials member.
  // 12. If allow_list is not present:
  //     a) If numberOfCredentials is one: Select that credential.
  //     b) If numberOfCredentials is more than one:
  //        1) Order the credentials in the applicable credentials list by the time when they were created in
  //           reverse order. (I.e. the first credential is the most recently created.)
  //        2）If the authenticator does not have a display:
  //           i. Remember the authenticatorGetAssertion parameters.
  //           ii. Create a credential counter (credentialCounter) and set it to 1. This counter signifies the next
  //               credential to be returned by the authenticator, assuming zero-based indexing.
  //           iii. Start a timer. This is used during authenticatorGetNextAssertion command. This step is OPTIONAL
  //                if transport is done over NFC.
  //           iv. Select the first credential.
  //        3) [N/A] If authenticator has a display and at least one of the "uv" and "up" options is true.
  //    c) Update the response to include the selected credential's publicKeyCredentialUserEntity information.
  //       User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity
  //       MUST NOT be returned if user verification is not done by the authenticator.
  if (ga_state.allow_list_size > 0) { // Step 11
    size_t i;
    for (i = 0; i < ga_state.allow_list_size; ++i) {
      memcpy(&dc.credential_id, &ga.allow_list[i], sizeof(dc.credential_id));
      // compare the rp_id first
      if (memcmp_s(dc.credential_id.rp_id_hash, ga_state.rp_id_hash, sizeof(dc.credential_id.rp_id_hash)) != 0)
        goto next;
      // then verify the key handle and get private key
      int err = verify_key_handle(&dc.credential_id, &key);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) {
        // Skip the credential which is protected
        if (!check_credential_protect_requirements(&dc.credential_id, true, uv)) goto next;
        if (dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS]) { // Verify if it's a valid dc.
          memcpy(data_buf, dc.credential_id.nonce,
                 sizeof(dc.credential_id.nonce)); // use data_buf to store the nonce temporarily
          int size = get_file_size(DC_FILE);
          if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
          int n_dc = (int)(size / sizeof(CTAP_discoverable_credential));
          bool found = false;
          DBG_MSG("%d discoverable credentials\n", n_dc);
          for (int j = 0; j < n_dc; ++j) {
            if (read_file(DC_FILE, &dc, j * (int)sizeof(CTAP_discoverable_credential),
                          sizeof(CTAP_discoverable_credential)) < 0)
              return CTAP2_ERR_UNHANDLED_REQUEST;
            if (dc.deleted) {
              DBG_MSG("Skipped DC at %d\n", j);
              continue;
            }
            if (memcmp_s(ga_state.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
                memcmp_s(data_buf, dc.credential_id.nonce, sizeof(dc.credential_id.nonce)) == 0) {
              found = true;
              break;
            }
          }
          DBG_MSG("matching credential_id%s found\n", (found ? "" : " not"));
          if (found) break;
          // if (!found) return CTAP2_ERR_NO_CREDENTIALS;
        } else { // not DC
          break; // Step 11: Select any credential from the applicable credentials list.
        }
      }
    next:
      continue;
    }
    // 7-f
    if (i == ga_state.allow_list_size) {
      DBG_MSG("no valid credential found in the allow list\n");
      return CTAP2_ERR_NO_CREDENTIALS;
    }
    ga_state.number_of_credentials = 1;
  } else { // Step 12
    uint32_t selected_idx = 0;
    uint32_t total = ga_state.number_of_credentials;
    uint32_t start = ga_state.credential_counter == 0 ? UINT32_MAX : ga_state.next_dc_idx;
    uint8_t err = ctap_find_next_assertion_dc(start, ga_state.credential_counter == 0, uv, &dc, &selected_idx, &total);
    if (err) return err;
    if (ga_state.credential_counter == 0) {
      ga_state.number_of_credentials = total;
      if (ga_state.number_of_credentials == 0) return CTAP2_ERR_NO_CREDENTIALS;
    }
    ga_state.next_dc_idx = selected_idx;
    if (verify_key_handle(&dc.credential_id, &key) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // For single account per RP case, authenticator returns "id" field to the platform which will be returned to the
  // [WebAuthn] layer. For multiple accounts per RP case, where the authenticator does not have a display, authenticator
  // returns "id" as well as other fields to the platform. User identifiable information (name, DisplayName, icon) MUST
  // NOT be returned if user verification is not done by the authenticator.
  user_details = uv && ga_state.number_of_credentials > 1;

  // 8. [N/A] If evidence of user interaction was provided as part of Step 6.2
  // 9. If the "up" option is set to true or not present:
  //    Note: This step is skipped in authenticatorGetNextAssertion
  if (ga_state.credential_counter == 0 && ga_state.options.up == OPTION_TRUE) {
    //    a) If the pin_uv_auth_param parameter is present then:
    if (ga_state.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
      if (!cp_get_user_present_flag_value()) {
        WAIT(CTAP2_ERR_OPERATION_DENIED);
      }
    } else {
      //    b) Else (implying the pin_uv_auth_param parameter is not present):
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
    //    c) Set the "up" bit to true in the response.
    up = true;
    //    d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    cp_clear_user_present_flag();
    cp_clear_user_verified_flag();
    cp_clear_pin_uv_auth_token_permissions_except_lbw();
  }

  DBG_MSG("Credential id: ");
  PRINT_HEX((const uint8_t *)&dc.credential_id, sizeof(dc.credential_id));

  // 10. If the extensions parameter is present:
  //     a) Process any extensions that this authenticator supports, ignoring any that it does not support.
  //     b) Authenticator extension outputs generated by the authenticator extension processing are returned to the
  //        authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to, or a subset
  //        of, the keys of the authenticator extension inputs map.

  // Process credProtect extension
  if (!check_credential_protect_requirements(&dc.credential_id, ga_state.allow_list_size > 0, uv))
    return CTAP2_ERR_NO_CREDENTIALS;

  CborEncoder map;
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  size_t extension_size = 0;
  uint8_t extension_map_items = (ga_state.ext_cred_blob ? 1 : 0) +
                                // largeBlobKey has no outputs here
                                ((ga_state.parsed_params & PARAM_HMAC_SECRET) ? 1 : 0) +
                                (ga_state.ext_third_party_payment ? 1 : 0);
  if (extension_map_items > 0) {
    CborEncoder extension_encoder;
    // build extensions
    cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
    ret = cbor_encoder_create_map(&extension_encoder, &map, extension_map_items);
    CHECK_CBOR_RET(ret);

    // Process credBlob extension
    if (ga_state.ext_cred_blob) {
      ret = cbor_encode_text_stringz(&map, "credBlob");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, dc.cred_blob, dc.cred_blob_len);
      CHECK_CBOR_RET(ret);
    }

    // Process hmac-secret extension
    if (ga_state.parsed_params & PARAM_HMAC_SECRET) {
      uint8_t hmac_secret_output[HMAC_SECRET_SALT_IV_SIZE + HMAC_SECRET_SALT_SIZE];
      size_t hmac_secret_output_len = 0;
      ret = ctap_get_assertion_prepare_hmac_secret();
      CHECK_PARSER_RET(ret);
      ret = ctap_build_hmac_secret_output(&ga_state.ext_hmac_secret_data, &dc.credential_id, uv, hmac_secret_output,
                                          &hmac_secret_output_len);
      CHECK_PARSER_RET(ret);
      if (ga_state.credential_counter + 1 == ga_state.number_of_credentials) { // encryption key will not be used any more
        memzero(ga_state.ext_hmac_secret_data.key_agreement, sizeof(ga_state.ext_hmac_secret_data.key_agreement));
      }

      ret = cbor_encode_text_stringz(&map, "hmac-secret");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, hmac_secret_output, hmac_secret_output_len);
      memzero(hmac_secret_output, sizeof(hmac_secret_output));
      CHECK_CBOR_RET(ret);
    }
    if (ga_state.ext_third_party_payment) {
      ret = cbor_encode_text_stringz(&map, "thirdPartyPayment");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_boolean(&map, credential_third_party_payment(&dc.credential_id));
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&extension_encoder, &map);
    CHECK_CBOR_RET(ret);
    extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
    DBG_MSG("extension_size=%zu\n", extension_size);
  }

  // 13. Sign the client_data_hash along with authData with the selected credential.
  bool has_user = dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS];
  bool has_multiple_credentials =
      ga_state.allow_list_size == 0 && ga_state.credential_counter == 0 && ga_state.number_of_credentials > 1;
  uint8_t map_items = 3;
  if (has_user) ++map_items; // user. For discoverable credentials on FIDO devices, at least user "id" is mandatory.
  if (has_multiple_credentials) ++map_items; // numberOfCredentials
  if (dc.has_large_blob_key) ++map_items;    // largeBlobKey
  uint8_t *stream_resp_start = encoder->data.ptr;
  ret = cbor_encoder_create_map(encoder, &map, map_items);
  CHECK_CBOR_RET(ret);

  // build credential id
  ret = cbor_encode_int(&map, GA_RESP_CREDENTIAL);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_credential_id(&map, &dc.credential_id);
  CHECK_CBOR_RET(ret);

  // auth data
  len = sizeof(data_buf);
  uint8_t flags = (extension_size > 0 ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | (up ? FLAGS_UP : 0);
  ret = ctap_make_auth_data(ga_state.rp_id_hash, data_buf, flags, extension_buffer, extension_size, &len,
                            dc.credential_id.alg_type, has_user, credential_cred_protect(&dc.credential_id));
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, MC_RESP_AUTH_DATA);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // signature
  ret = cbor_encode_int(&map, GA_RESP_SIGNATURE);
  CHECK_CBOR_RET(ret);
  if (dc.credential_id.alg_type == COSE_ALG_ML_DSA_65) {
    CTAP_mldsa_stream_state *state = &mldsa_stream_state;
    uint8_t prefix_snapshot[sizeof(state->prefix)];
    size_t prefix_snapshot_len = (size_t)(map.data.ptr - stream_resp_start);
    uint8_t *p;
    if (prefix_snapshot_len > sizeof(prefix_snapshot)) return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(prefix_snapshot, stream_resp_start, prefix_snapshot_len);
    memset(state, 0, sizeof(*state));
    state->stage = state->stage_buf;
    memcpy(state->seed, key.pri, PRI_KEY_SIZE);
    p = state->prefix;
    *p++ = 0;
    memcpy(p, prefix_snapshot, prefix_snapshot_len);
    p += prefix_snapshot_len;
    cbor_put_bytes_header(&p, MLDSA_SIG_BYTES);
    state->prefix_len = (size_t)(p - state->prefix);
    if (ctap_mldsa65_tr_from_seed(state->seed, state->tr, state->stage, sizeof(state->stage_buf)) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    memcpy(data_buf + len, ga_state.client_data_hash, CLIENT_DATA_HASH_SIZE);
    memcpy(state->msg, data_buf, len + CLIENT_DATA_HASH_SIZE);
    state->msg_len = len + CLIENT_DATA_HASH_SIZE;

    CborEncoder suffix_encoder;
    cbor_encoder_init(&suffix_encoder, state->suffix, sizeof(state->suffix), 0);
    if (has_user) {
      ret = cbor_encode_int(&suffix_encoder, GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_user_entity(&suffix_encoder, &dc.user, user_details);
      CHECK_CBOR_RET(ret);
    }
    if (has_multiple_credentials) {
      ret = cbor_encode_int(&suffix_encoder, GA_RESP_NUMBER_OF_CREDENTIALS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&suffix_encoder, ga_state.number_of_credentials);
      CHECK_CBOR_RET(ret);
    }
    if (dc.has_large_blob_key) {
      uint8_t *large_blob_key = dc.cred_blob;
      ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&suffix_encoder, GA_RESP_LARGE_BLOB_KEY);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&suffix_encoder, large_blob_key, LARGE_BLOB_KEY_SIZE);
      CHECK_CBOR_RET(ret);
    }
    state->suffix_len = cbor_encoder_get_buffer_size(&suffix_encoder, state->suffix);
    state->kind = CTAP_MLDSA_STREAM_SIG;
    state->total_len = state->prefix_len + MLDSA_SIG_BYTES + state->suffix_len;
    state->pending = true;
    ++ga_state.credential_counter;
    timer = device_get_tick();
    return 0;
  }
  memcpy(data_buf + len, ga_state.client_data_hash, CLIENT_DATA_HASH_SIZE);
  DBG_MSG("Message: ");
  PRINT_HEX(data_buf, len + CLIENT_DATA_HASH_SIZE);
  len = sign_with_private_key(dc.credential_id.alg_type, &key, data_buf, len + CLIENT_DATA_HASH_SIZE, data_buf);
  if (len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  DBG_MSG("Signature: ");
  PRINT_HEX(data_buf, len);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // user
  if (has_user) {
    ret = cbor_encode_int(&map, GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_user_entity(&map, &dc.user, user_details);
    CHECK_CBOR_RET(ret);
  }

  if (has_multiple_credentials) {
    ret = cbor_encode_int(&map, GA_RESP_NUMBER_OF_CREDENTIALS);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, ga_state.number_of_credentials);
    CHECK_CBOR_RET(ret);
  }

  if (dc.has_large_blob_key) {
    uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
    static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
    ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, GA_RESP_LARGE_BLOB_KEY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  ++ga_state.credential_counter;
  timer = device_get_tick();

  return 0;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetNextAssertion
static uint8_t ctap_get_next_assertion(CborEncoder *encoder) { return ctap_get_assertion(encoder, NULL, 0, true); }

static int ctap_get_remaining_discoverable_credentials(void) {
  return (int)ctap_capacity_remaining_new_credentials();
}

#include "ctap_get_info_cbor.inc"

static int ctap_prepare_get_info_stream(CTAPHID_TxSource *source) {
  if (!source) return -1;

  CTAP_const_stream_state *state = (CTAP_const_stream_state *)applet_session_scratch.buffer;
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return -1;
  const int pin_state = has_pin();
  if (pin_state < 0) return -1;
  const bool always_uv = cfg.always_uv != 0;

  ctap_const_stream_reset(state);
  if (ctap_const_stream_add_byte(state, CTAP1_ERR_SUCCESS) != 0 ||
      ctap_const_stream_add_mem(state,
                                cfg.force_pin_change ? cbor_gi_prefix_before_versions_force
                                                     : cbor_gi_prefix_before_versions,
                                sizeof(cbor_gi_prefix_before_versions)) != 0 ||
      ctap_const_stream_add_mem(state,
                                always_uv ? cbor_gi_versions_without_u2f : cbor_gi_versions_with_u2f,
                                always_uv ? sizeof(cbor_gi_versions_without_u2f) : sizeof(cbor_gi_versions_with_u2f)) !=
          0 ||
      ctap_const_stream_add_mem(state, cbor_gi_after_versions_before_always_uv,
                                sizeof(cbor_gi_after_versions_before_always_uv)) != 0 ||
      cbor_put_bool_inline(state, always_uv) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_after_always_uv_before_client_pin,
                                sizeof(cbor_gi_after_always_uv_before_client_pin)) != 0 ||
      cbor_put_bool_inline(state, pin_state > 0) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_after_client_pin_before_make_cred_uv_not_rqd,
                                sizeof(cbor_gi_after_client_pin_before_make_cred_uv_not_rqd)) != 0 ||
      cbor_put_bool_inline(state, !always_uv) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_after_make_cred_uv_not_rqd_before_max_msg_size,
                                sizeof(cbor_gi_after_make_cred_uv_not_rqd_before_max_msg_size)) != 0 ||
      cbor_put_uint_inline(state, CTAP_MAX_MSG_SIZE) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_after_max_msg_size_before_sm2_alg,
                                sizeof(cbor_gi_after_max_msg_size_before_sm2_alg)) != 0 ||
      cbor_put_int_inline(state, ctap_sm2_attr.algo_id) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_after_sm2_alg, sizeof(cbor_gi_after_sm2_alg)) != 0 ||
      (cfg.force_pin_change &&
       ctap_const_stream_add_mem(state, cbor_gi_force_pin_change_entry,
                                 sizeof(cbor_gi_force_pin_change_entry)) != 0) ||
      ctap_const_stream_add_mem(state, cbor_gi_suffix_before_min_pin_length,
                                sizeof(cbor_gi_suffix_before_min_pin_length)) != 0 ||
      cbor_put_uint_inline(state, cfg.min_pin_length) != 0 ||
      ctap_const_stream_add_mem(state,
                                cbor_gi_suffix_after_min_pin_length_before_remaining_discoverable_credentials,
                                sizeof(cbor_gi_suffix_after_min_pin_length_before_remaining_discoverable_credentials)) !=
          0 ||
      cbor_put_uint_inline(state, (uint64_t)ctap_get_remaining_discoverable_credentials()) != 0 ||
      ctap_const_stream_add_mem(
          state, cbor_gi_suffix_after_remaining_discoverable_credentials_before_long_touch_for_reset,
          sizeof(cbor_gi_suffix_after_remaining_discoverable_credentials_before_long_touch_for_reset)) != 0 ||
      cbor_put_bool_inline(state, cfg.long_touch_for_reset != 0) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_suffix_after_long_touch_for_reset_before_max_pin_length,
                                sizeof(cbor_gi_suffix_after_long_touch_for_reset_before_max_pin_length)) != 0 ||
      cbor_put_uint_inline(state, cfg.max_pin_length) != 0 ||
      ctap_const_stream_add_mem(state, cbor_gi_suffix_after_max_pin_length,
                                sizeof(cbor_gi_suffix_after_max_pin_length)) != 0)
    return -1;

  source->total_len = state->total_len;
  source->read = ctap_const_stream_read;
  source->close = NULL;
  source->ctx = state;
  return 0;
}

static uint8_t __attribute__((noinline)) ctap_client_pin(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_client_pin cp;
  ctap_req_src_t param_src = ctap_param_req_src();
  int ret = current_req_src.read ? parse_client_pin_src(&parser, &cp, &param_src, len)
                                 : parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);
  ctap_req_lifetime_end();

  CborEncoder map, key_map;
  uint8_t iv[16], buf[PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2], i, pin_code_points;
  memzero(iv, sizeof(iv));
  uint8_t *ptr;
  int err, retries, cose_key_size;
  switch (cp.sub_command) {
  case CP_CMD_GET_PIN_RETRIES:
    DBG_MSG("Subcommand Get Pin Retries\n");
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CP_RESP_PIN_RETRIES);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, get_pin_retries());
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CP_CMD_GET_KEY_AGREEMENT:
    DBG_MSG("Subcommand Get Key Agreement\n");
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CP_RESP_KEY_AGREEMENT);
    CHECK_CBOR_RET(ret);
    // to save RAM, generate an empty key first, then fill it manually
    ret = cbor_encoder_create_map(&map, &key_map, 0);
    CHECK_CBOR_RET(ret);
    ptr = key_map.data.ptr - 1;
    cp_get_public_key(ptr);
    cose_key_size = build_cose_key(ptr, COSE_KEY_KTY_EC2, COSE_ALG_ECDH_ES_HKDF_256, COSE_KEY_CRV_P256, true);
    key_map.data.ptr = ptr + cose_key_size;
    ret = cbor_encoder_close_container(&map, &key_map);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CP_CMD_SET_PIN:
    DBG_MSG("Subcommand Set Pin\n");
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err > 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
    CHECK_PARSER_RET(ret);
    DBG_MSG("Shared Secret: ");
    PRINT_HEX(cp.key_agreement, cp.pin_uv_auth_protocol == 2 ? SHARED_SECRET_SIZE_P2 : SHARED_SECRET_SIZE_P1);
    if (!cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, cp.new_pin_enc,
                   cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2, cp.pin_uv_auth_param,
                   cp.pin_uv_auth_protocol)) {
      ERR_MSG("CP verification failed\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (cp_decrypt(cp.key_agreement, cp.new_pin_enc, cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2,
                   cp.new_pin_enc, cp.pin_uv_auth_protocol) != 0) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    DBG_MSG("Decrypted key: ");
    PRINT_HEX(cp.new_pin_enc, 64);
    i = 63;
    while (i > 0 && cp.new_pin_enc[i] == 0)
      --i;
    ret = ctap_validate_new_pin(cp.new_pin_enc, i + 1, &pin_code_points);
    if (ret) return ret;
    err = set_pin(cp.new_pin_enc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (ctap_note_pin_changed(pin_code_points) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cp_reset_pin_uv_auth_token();
    break;

  case CP_CMD_CHANGE_PIN:
    DBG_MSG("Subcommand Change Pin\n");
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    retries = err - 1;
#endif
    ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
    CHECK_PARSER_RET(ret);
    if (cp.pin_uv_auth_protocol == 1) {
      memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P1);
      memcpy(buf + PIN_ENC_SIZE_P1, cp.pin_hash_enc, PIN_HASH_SIZE_P1);
      ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, buf, PIN_ENC_SIZE_P1 + PIN_HASH_SIZE_P1,
                      cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
    } else {
      memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P2);
      memcpy(buf + PIN_ENC_SIZE_P2, cp.pin_hash_enc, PIN_HASH_SIZE_P2);
      ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, buf, PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2,
                      cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
    }
    if (ret == false) {
      ERR_MSG("CP verification failed\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cp_decrypt(cp.key_agreement, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol == 1 ? PIN_HASH_SIZE_P1 : PIN_HASH_SIZE_P2, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol)) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    err = verify_pin_hash(cp.pin_hash_enc);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err > 0) {
      cp_regenerate();
      if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
      --consecutive_pin_counter;
      if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      return CTAP2_ERR_PIN_INVALID;
    }
#endif
    consecutive_pin_counter = 3;
    if (cp_decrypt(cp.key_agreement, cp.new_pin_enc, cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2,
                   cp.new_pin_enc, cp.pin_uv_auth_protocol) != 0) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    i = 63;
    while (i > 0 && cp.new_pin_enc[i] == 0)
      --i;
    ret = ctap_validate_new_pin(cp.new_pin_enc, i + 1, &pin_code_points);
    if (ret) return ret;
    err = set_pin(cp.new_pin_enc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (ctap_note_pin_changed(pin_code_points) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cp_reset_pin_uv_auth_token();
    break;

  case CP_CMD_GET_PIN_TOKEN:
  case CP_CMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS:
    DBG_MSG("Subcommand Get Pin Token\n");
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    if (ctap_config_force_pin_change_required()) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    retries = err - 1;
#endif
    ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
    CHECK_PARSER_RET(ret);
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cp_decrypt(cp.key_agreement, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol == 1 ? PIN_HASH_SIZE_P1 : PIN_HASH_SIZE_P2, cp.pin_hash_enc,
                   cp.pin_uv_auth_protocol)) {
      ERR_MSG("CP decryption failed\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    err = verify_pin_hash(cp.pin_hash_enc);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err > 0) {
      if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
      --consecutive_pin_counter;
      if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      return CTAP2_ERR_PIN_INVALID;
    }
#endif
    consecutive_pin_counter = 3;
    err = set_pin_retries(8);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cp_reset_pin_uv_auth_token();
    cp_begin_using_uv_auth_token(false);
    if (cp.sub_command == CP_CMD_GET_PIN_TOKEN) {
      cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA);
    } else {
      cp_set_permission(cp.permissions);
      if (cp.parsed_params & PARAM_RP) cp_associate_rp_id(cp.rp_id_hash);
    }
    cp_encrypt_pin_token(cp.key_agreement, buf, cp.pin_uv_auth_protocol);
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CP_RESP_PIN_UV_AUTH_TOKEN);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, buf, cp.pin_uv_auth_protocol == 1 ? PIN_TOKEN_SIZE : PIN_TOKEN_SIZE + 16);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;
  }

  return 0;
}

/**
 * Find a discoverable credential by credential_id.
 * On success, *dc is filled and *out_idx is set to the file index.
 *
 * @return 0 on success, CTAP2 error code on failure.
 */
static uint8_t cm_find_credential(const credential_id *target, CTAP_discoverable_credential *dc, uint32_t *out_idx) {
  uint32_t n;
  uint8_t err = ctap_dc_record_count(&n);
  if (err) return err;
  for (uint32_t i = 0; i < n; ++i) {
    int size = read_file(DC_FILE, dc, (lfs_soff_t)(i * sizeof(CTAP_discoverable_credential)),
                         sizeof(CTAP_discoverable_credential));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (dc->deleted) continue;
    if (memcmp_s(&dc->credential_id, target, sizeof(credential_id)) == 0) {
      DBG_MSG("Found, credential_id: ");
      PRINT_HEX((const uint8_t *)target, sizeof(credential_id));
      *out_idx = i;
      return 0;
    }
  }
  return CTAP2_ERR_NO_CREDENTIALS;
}

static uint8_t cm_find_next_rp(uint32_t start_idx, CTAP_rp_meta *meta, uint32_t *out_idx, uint32_t *total) {
  uint32_t n;
  uint8_t err = ctap_meta_record_count(&n);
  if (err) return err;
  uint32_t count = 0;
  bool found = false;
  CTAP_rp_meta candidate;
  for (uint32_t i = start_idx; i < n; ++i) {
    int size = read_file(DC_META_FILE, &candidate, (lfs_soff_t)(i * sizeof(CTAP_rp_meta)), sizeof(candidate));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (candidate.deleted || candidate.live_count == 0) continue;
    if (total) ++count;
    if (!found) {
      memcpy(meta, &candidate, sizeof(*meta));
      *out_idx = i;
      found = true;
      if (!total) break;
    }
  }
  if (total) *total = count;
  return found ? 0 : CTAP2_ERR_NO_CREDENTIALS;
}

static uint8_t cm_find_next_credential(uint32_t start_idx, const uint8_t rp_id_hash[SHA256_DIGEST_LENGTH],
                                       CTAP_discoverable_credential *dc, uint32_t *out_idx, uint32_t *total) {
  uint32_t n;
  uint8_t err = ctap_dc_record_count(&n);
  if (err) return err;
  uint32_t count = 0;
  bool found = false;
  CTAP_discoverable_credential candidate;
  for (uint32_t i = start_idx; i < n; ++i) {
    int size = read_file(DC_FILE, &candidate, (lfs_soff_t)(i * sizeof(CTAP_discoverable_credential)),
                         sizeof(candidate));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (candidate.deleted) continue;
    if (memcmp_s(candidate.credential_id.rp_id_hash, rp_id_hash, SHA256_DIGEST_LENGTH) != 0) continue;
    if (total) ++count;
    if (!found) {
      memcpy(dc, &candidate, sizeof(*dc));
      *out_idx = i;
      found = true;
      if (!total) break;
    }
  }
  if (total) *total = count;
  return found ? 0 : CTAP2_ERR_NO_CREDENTIALS;
}

static uint8_t __attribute__((noinline)) ctap_credential_management(CborEncoder *encoder, const uint8_t *params,
                                                                    size_t len) {
  CborParser parser;
  CTAP_credential_management cm;
  CTAP_credential_management_state *state = &cred_mgmt_state;
  ctap_req_src_t param_src = ctap_param_req_src();
  int ret = current_req_src.read ? parse_credential_management_src(&parser, &cm, &param_src, len)
                                 : parse_credential_management(&parser, &cm, params, len);
  CHECK_PARSER_RET(ret);
  // PIN-token verification signs subCommand || subCommandParams. Preserve that
  // exact CBOR byte range before dropping a possibly PKE-backed request source.
  uint8_t cm_pin_msg[sizeof(CTAP_discoverable_credential)] = {0};
  size_t cm_pin_msg_len = 0;
  if (cm.sub_command == CM_CMD_GET_CREDS_METADATA || cm.sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
      cm.sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN || cm.sub_command == CM_CMD_DELETE_CREDENTIAL ||
      cm.sub_command == CM_CMD_UPDATE_USER_INFORMATION) {
    cm_pin_msg[0] = cm.sub_command;
    if (cm.param_len + 1 > sizeof(cm_pin_msg)) return CTAP1_ERR_INVALID_LENGTH;
    if (cm.param_len > 0 && ctap_req_read_param_bytes(cm.sub_command_params_offset, &cm_pin_msg[1], cm.param_len) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    cm_pin_msg_len = cm.param_len + 1;
  }
  ctap_req_lifetime_end();
  ret = ctap_consistency_check();
  CHECK_PARSER_RET(ret);

  int counter;
  CborEncoder map, sub_map;
  uint32_t numbers = 0;
  CTAP_rp_meta meta;
  CTAP_discoverable_credential dc;
  bool include_numbers;

  if (cm.sub_command == CM_CMD_GET_CREDS_METADATA || cm.sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
      cm.sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN || cm.sub_command == CM_CMD_DELETE_CREDENTIAL ||
      cm.sub_command == CM_CMD_UPDATE_USER_INFORMATION) {
    ctap_credential_management_reset_state();
    state->last_subcommand = cm.sub_command;
    uint8_t *buf = (uint8_t *)&dc; // buffer reuse
    _Static_assert(sizeof(CTAP_dc_general_attr) < sizeof(dc), "CTAP_dc_general_attr buffer overflow");
    if (read_attr(DC_FILE, DC_GENERAL_ATTR, buf, sizeof(CTAP_dc_general_attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    numbers = ((CTAP_dc_general_attr *)buf)->numbers;

    if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    if (!cp_verify_pin_token(cm_pin_msg, cm_pin_msg_len, cm.pin_uv_auth_param, cm.pin_uv_auth_protocol)) {
      DBG_MSG("PIN token verification failed (msg_len=%zu, protocol=%d)\n", cm_pin_msg_len, cm.pin_uv_auth_protocol);
      PRINT_HEX(cm_pin_msg, cm_pin_msg_len);
      PRINT_HEX(cm.pin_uv_auth_param, 16);
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!cp_has_permission(CP_PERMISSION_CM)) {
      DBG_MSG("CM permission check failed\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
  }

  DBG_MSG("processing cm.sub_command %hhu\n", cm.sub_command);
  switch (cm.sub_command) {
  case CM_CMD_GET_CREDS_METADATA:
    if (cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
    ret = cbor_encoder_create_map(encoder, &map, 2);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_EXISTING_RESIDENT_CREDENTIALS_COUNT);
    CHECK_CBOR_RET(ret);
    DBG_MSG("Existing credentials: %d\n", numbers);
    ret = cbor_encode_int(&map, numbers);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_MAX_POSSIBLE_REMAINING_RESIDENT_CREDENTIALS_COUNT);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, ctap_capacity_remaining_new_credentials());
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CM_CMD_ENUMERATE_RPS_BEGIN:
    if (cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    KEEPALIVE();
    {
      uint32_t idx = 0, total_rps = 0;
      uint8_t err = cm_find_next_rp(0, &meta, &idx, &total_rps);
      if (err) return err;
      state->next_idx = idx + 1;
      state->total = total_rps;
      counter = (int)total_rps;
    }
    DBG_MSG("%d RPs found\n", counter);
    goto encode_rp_begin;

  case CM_CMD_ENUMERATE_RPS_GET_NEXT_RP:
    if (last_cmd != CTAP_CREDENTIAL_MANAGEMENT || (state->last_subcommand != CM_CMD_ENUMERATE_RPS_BEGIN &&
                                                   state->last_subcommand != CM_CMD_ENUMERATE_RPS_GET_NEXT_RP)) {
      ctap_credential_management_reset_state();
      return CTAP2_ERR_NOT_ALLOWED;
    }
    state->last_subcommand = cm.sub_command;
    {
      uint32_t idx = 0;
      uint8_t err = cm_find_next_rp(state->next_idx, &meta, &idx, NULL);
      if (err) {
        ctap_credential_management_reset_state();
        return CTAP2_ERR_NOT_ALLOWED;
      }
      DBG_MSG("Fetch RP at %lu\n", (unsigned long)idx);
      state->next_idx = idx + 1;
    }
    counter = -1; // signal: no TOTAL_RPS field
  encode_rp_begin:
    ret = cbor_encoder_create_map(encoder, &map, counter >= 0 ? 3 : 2);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_RP);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_create_map(&map, &sub_map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_string(&sub_map, (const char *)meta.rp_id, meta.rp_id_len);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_RP_ID_HASH);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, meta.rp_id_hash, SHA256_DIGEST_LENGTH);
    CHECK_CBOR_RET(ret);
    if (counter >= 0) {
      ret = cbor_encode_int(&map, CM_RESP_TOTAL_RPS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, counter);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CM_CMD_ENUMERATE_CREDENTIALS_BEGIN:
    if (!cp_verify_rp_id(cm.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    include_numbers = true;
    {
      uint32_t idx = 0, total_credentials = 0;
      uint8_t err = cm_find_next_credential(0, cm.rp_id_hash, &dc, &idx, &total_credentials);
      if (err != 0) return err;
      numbers = total_credentials;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      memcpy(state->rp_id_hash, cm.rp_id_hash, SHA256_DIGEST_LENGTH);
      state->has_rp_filter = true;
      state->next_idx = idx + 1;
      state->total = total_credentials;
    }
  generate_credential_response:
    if (!include_numbers) {
      uint32_t idx = 0;
      uint8_t err = cm_find_next_credential(state->next_idx, state->rp_id_hash, &dc, &idx, NULL);
      if (err) {
        ctap_credential_management_reset_state();
        return CTAP2_ERR_NOT_ALLOWED;
      }
      state->next_idx = idx + 1;
      numbers = state->total;
    }
    uint8_t *stream_resp_start = encoder->data.ptr;
    ret = cbor_encoder_create_map(encoder, &map, 5 + (uint8_t)include_numbers + (uint8_t)dc.has_large_blob_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_USER);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_user_entity(&map, &dc.user, true);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_CREDENTIAL_ID);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_credential_id(&map, &dc.credential_id);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, CM_RESP_PUBLIC_KEY);
    CHECK_CBOR_RET(ret);
    if (dc.credential_id.alg_type == COSE_ALG_ML_DSA_65) {
      CTAP_mldsa_stream_state *state = &mldsa_stream_state;
      uint8_t prefix_snapshot[sizeof(state->prefix)];
      size_t prefix_snapshot_len = (size_t)(map.data.ptr - stream_resp_start);
      uint8_t *p;
      if (prefix_snapshot_len > sizeof(prefix_snapshot)) return CTAP2_ERR_UNHANDLED_REQUEST;
      memcpy(prefix_snapshot, stream_resp_start, prefix_snapshot_len);
      memset(state, 0, sizeof(*state));
      state->stage = state->stage_buf;
      if (verify_mldsa65_key_handle(&dc.credential_id, state->seed) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      p = state->prefix;
      *p++ = 0;
      memcpy(p, prefix_snapshot, prefix_snapshot_len);
      p += prefix_snapshot_len;
      if (cbor_put_mldsa65_cose_prefix(&p) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      state->prefix_len = (size_t)(p - state->prefix);

      CborEncoder suffix_encoder;
      cbor_encoder_init(&suffix_encoder, state->suffix, sizeof(state->suffix), 0);
      if (include_numbers) {
        ret = cbor_encode_int(&suffix_encoder, CM_RESP_TOTAL_CREDENTIALS);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_int(&suffix_encoder, numbers);
        CHECK_CBOR_RET(ret);
      }
      ret = cbor_encode_int(&suffix_encoder, CM_RESP_CRED_PROTECT);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&suffix_encoder, credential_cred_protect(&dc.credential_id));
      CHECK_CBOR_RET(ret);
      if (dc.has_large_blob_key) {
        uint8_t *large_blob_key = dc.cred_blob;
        ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_int(&suffix_encoder, CM_RESP_LARGE_BLOB_KEY);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_byte_string(&suffix_encoder, large_blob_key, LARGE_BLOB_KEY_SIZE);
        CHECK_CBOR_RET(ret);
      }
      ret = cbor_encode_int(&suffix_encoder, CM_RESP_THIRD_PARTY_PAYMENT);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_boolean(&suffix_encoder, credential_third_party_payment(&dc.credential_id));
      CHECK_CBOR_RET(ret);
      state->suffix_len = cbor_encoder_get_buffer_size(&suffix_encoder, state->suffix);
      state->kind = CTAP_MLDSA_STREAM_PK;
      state->total_len = state->prefix_len + MLDSA_PK_BYTES + state->suffix_len;
      state->pending = true;
      break;
    }
    // to save RAM, generate an empty key first, then fill it manually
    ret = cbor_encoder_create_map(&map, &sub_map, 0);
    CHECK_CBOR_RET(ret);
    ecc_key_t key;
    ret = verify_key_handle(&dc.credential_id, &key);
    if (ret != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    key_type_t key_type = cose_alg_to_key_type(dc.credential_id.alg_type);
    if (ecc_complete_key(key_type, &key) < 0) {
      ERR_MSG("Failed to complete key\n");
      return -1;
    }
    uint8_t *ptr = sub_map.data.ptr - 1;
    memcpy(ptr, key.pub, PUBLIC_KEY_LENGTH[key_type]);
    if (dc.credential_id.alg_type == COSE_ALG_ES256) {
      int cose_key_size = build_cose_key(ptr, COSE_KEY_KTY_EC2, COSE_ALG_ES256, COSE_KEY_CRV_P256, true);
      sub_map.data.ptr = ptr + cose_key_size;
    } else if (dc.credential_id.alg_type == COSE_ALG_EDDSA) {
      int cose_key_size = build_cose_key(ptr, COSE_KEY_KTY_OKP, COSE_ALG_EDDSA, COSE_KEY_CRV_ED25519, false);
      sub_map.data.ptr = ptr + cose_key_size;
    }
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
    if (include_numbers) {
      ret = cbor_encode_int(&map, CM_RESP_TOTAL_CREDENTIALS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, numbers);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encode_int(&map, CM_RESP_CRED_PROTECT);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, credential_cred_protect(&dc.credential_id));
    CHECK_CBOR_RET(ret);
    if (dc.has_large_blob_key) {
      uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
      static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
      ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_LARGE_BLOB_KEY);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encode_int(&map, CM_RESP_THIRD_PARTY_PAYMENT);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&map, credential_third_party_payment(&dc.credential_id));
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL:
    if (last_cmd != CTAP_CREDENTIAL_MANAGEMENT ||
        (state->last_subcommand != CM_CMD_ENUMERATE_CREDENTIALS_BEGIN &&
         state->last_subcommand != CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL)) {
      ctap_credential_management_reset_state();
      return CTAP2_ERR_NOT_ALLOWED;
    }
    state->last_subcommand = cm.sub_command;
    include_numbers = false;
    goto generate_credential_response;

  case CM_CMD_DELETE_CREDENTIAL:
  {
    if (!cp_verify_rp_id(cm.credential_id.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    uint32_t credential_idx;
    {
      uint8_t err = cm_find_credential(&cm.credential_id, &dc, &credential_idx);
      if (err) return err;
    }

    CTAP_dc_general_attr attr;
    if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    attr.pending_index = credential_idx;
    attr.pending_op = CTAP_DC_PENDING_DELETE;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

    // delete dc first
    dc.deleted = true;
    int del_write_err = write_file(DC_FILE, &dc, (lfs_soff_t)(credential_idx * sizeof(CTAP_discoverable_credential)),
                                   sizeof(CTAP_discoverable_credential), 0);
    if (del_write_err < 0) return ctap_storage_write_result(del_write_err);
    DBG_MSG("Slot %lu deleted\n", (unsigned long)credential_idx);
    KEEPALIVE();
    uint8_t rebuild_err = ctap_rebuild_rp_meta_counts();
    if (rebuild_err) return rebuild_err;
    if (attr.numbers > 0) --attr.numbers;
    attr.pending_op = CTAP_DC_PENDING_NONE;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;
  }

  case CM_CMD_UPDATE_USER_INFORMATION:
  {
    if (!cp_verify_rp_id(cm.credential_id.rp_id_hash)) {
      DBG_MSG("RP ID verification failed in update_user_info\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    KEEPALIVE();
    uint32_t update_idx;
    {
      uint8_t err = cm_find_credential(&cm.credential_id, &dc, &update_idx);
      if (err) return err;
    }
    if (dc.user.id_size != cm.user.id_size || memcmp_s(&dc.user.id, &cm.user.id, dc.user.id_size) != 0) {
      DBG_MSG("Incorrect user id\n");
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    memcpy(&dc.user, &cm.user, sizeof(user_entity));
    if (write_file(DC_FILE, &dc, (lfs_soff_t)(update_idx * sizeof(CTAP_discoverable_credential)),
                   sizeof(CTAP_discoverable_credential), 0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    DBG_MSG("Slot %lu updated\n", (unsigned long)update_idx);
    break;
  }
  }

  return 0;
}

static bool ctap_config_subcommand_supported(uint8_t sub_command) {
  return sub_command == CONFIG_CMD_TOGGLE_ALWAYS_UV || sub_command == CONFIG_CMD_SET_MIN_PIN_LENGTH ||
         sub_command == CONFIG_CMD_ENABLE_LONG_TOUCH_FOR_RESET;
}

static uint8_t ctap_config_toggle_always_uv(void) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  cfg.always_uv = cfg.always_uv ? 0 : 1;
  if (ctap_config_store(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  return 0;
}

static uint8_t ctap_config_set_min_pin_length(const CTAP_config *cmd) {
  CTAP_persistent_config cfg;
  int pin_state = has_pin();
  if (pin_state < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  const bool pin_set = pin_state > 0;

  if (ctap_config_load(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  uint8_t new_min = (cmd->parsed_params & PARAM_NEW_MIN_PIN_LENGTH) ? cmd->new_min_pin_length : cfg.min_pin_length;
  if (new_min < cfg.min_pin_length) return CTAP2_ERR_PIN_POLICY_VIOLATION;
  if (new_min > cfg.max_pin_length) return CTAP1_ERR_INVALID_PARAMETER;
  if ((cmd->parsed_params & PARAM_FORCE_CHANGE_PIN) && cmd->force_change_pin && !pin_set) return CTAP2_ERR_PIN_NOT_SET;

  if (cmd->parsed_params & PARAM_MIN_PIN_LENGTH_RPIDS) {
    if (ctap_min_pin_rpids_store(cmd) < 0) return CTAP2_ERR_KEY_STORE_FULL;
  }

  if (cmd->parsed_params & PARAM_FORCE_CHANGE_PIN) {
    if (cmd->force_change_pin) cfg.force_pin_change = 1;
  }

  if (pin_set && new_min > cfg.min_pin_length &&
      (cfg.pin_code_point_length == 0 || cfg.pin_code_point_length < new_min)) {
    cfg.force_pin_change = 1;
  }

  cfg.min_pin_length = new_min;
  if (ctap_config_store(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (cfg.force_pin_change) cp_reset_pin_uv_auth_token();
  return 0;
}

static uint8_t ctap_config_enable_long_touch_for_reset(void) {
  CTAP_persistent_config cfg;
  if (ctap_config_load(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  cfg.long_touch_for_reset = 1;
  if (ctap_config_store(&cfg) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  return 0;
}

static uint8_t __attribute__((noinline)) ctap_config(CborEncoder *encoder, const uint8_t *params, size_t len) {
  UNUSED(encoder);
  if (len == 0) return CTAP2_ERR_UNHANDLED_REQUEST;

  CborParser parser;
  CTAP_config cfg;
  ctap_req_src_t param_src = ctap_param_req_src();
  int ret = current_req_src.read ? parse_config_src(&parser, &cfg, &param_src, len)
                                 : parse_config(&parser, &cfg, params, len);
  CHECK_PARSER_RET(ret);

  if (!ctap_config_subcommand_supported(cfg.sub_command)) {
    ctap_req_lifetime_end();
    return CTAP1_ERR_INVALID_PARAMETER;
  }

#define CONFIG_PIN_MSG_HEADER_SIZE (32 + 2)
  uint8_t cfg_pin_msg[CONFIG_PIN_MSG_HEADER_SIZE + sizeof(CTAP_config)];
  size_t cfg_pin_msg_len = CONFIG_PIN_MSG_HEADER_SIZE + cfg.param_len;
  if (cfg.param_len > sizeof(cfg_pin_msg) - CONFIG_PIN_MSG_HEADER_SIZE) {
    ctap_req_lifetime_end();
    return CTAP1_ERR_INVALID_LENGTH;
  }
  memset(cfg_pin_msg, 0xFF, 32);
  cfg_pin_msg[32] = CTAP_CONFIG;
  cfg_pin_msg[33] = cfg.sub_command;
  if (cfg.param_len > 0 && ctap_req_read_param_bytes(cfg.sub_command_params_offset,
                                                     cfg_pin_msg + CONFIG_PIN_MSG_HEADER_SIZE, cfg.param_len) < 0) {
    ctap_req_lifetime_end();
    return CTAP2_ERR_UNHANDLED_REQUEST;
  }
#undef CONFIG_PIN_MSG_HEADER_SIZE
  ctap_req_lifetime_end();

  int pin_state = has_pin();
  if (pin_state < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  const bool pin_set = pin_state > 0;
  const bool always_uv = ctap_config_always_uv_enabled();
  const bool auth_required = pin_set || always_uv;
  const bool unauthenticated_always_uv_disable =
      cfg.sub_command == CONFIG_CMD_TOGGLE_ALWAYS_UV && !pin_set && always_uv;

  if (auth_required && !unauthenticated_always_uv_disable) {
    if (!(cfg.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) return CTAP2_ERR_PUAT_REQUIRED;
    if (!(cfg.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) return CTAP2_ERR_MISSING_PARAMETER;
    if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    if (!cp_verify_pin_token(cfg_pin_msg, cfg_pin_msg_len, cfg.pin_uv_auth_param, cfg.pin_uv_auth_protocol))
      return CTAP2_ERR_PIN_AUTH_INVALID;
    if (!cp_has_permission(CP_PERMISSION_ACFG)) return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  switch (cfg.sub_command) {
  case CONFIG_CMD_TOGGLE_ALWAYS_UV:
    return ctap_config_toggle_always_uv();
  case CONFIG_CMD_SET_MIN_PIN_LENGTH:
    return ctap_config_set_min_pin_length(&cfg);
  case CONFIG_CMD_ENABLE_LONG_TOUCH_FOR_RESET:
    return ctap_config_enable_long_touch_for_reset();
  default:
    return CTAP1_ERR_INVALID_PARAMETER;
  }
}

static uint8_t ctap_selection(void) {
  ctap_req_lifetime_end();
  WAIT(CTAP2_ERR_USER_ACTION_TIMEOUT);
  return 0;
}

static uint8_t ctap_wait_for_long_reset_touch(void) {
#ifdef BYPASS_USER_PRESENCE
  return 0;
#endif
  uint32_t start = device_get_tick();
  uint32_t last = start;
  start_blinking(0);
  while (get_touch_result() != TOUCH_LONG) {
    if (get_touch_result() == TOUCH_SHORT) set_touch_result(TOUCH_NO);
    send_keepalive_during_processing(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID);
#if ENABLE_IFACE_CTAPHID
    if (current_cmd_src == CTAP_SRC_HID && CTAPHID_Loop(1) == LOOP_CANCEL) {
      stop_blinking();
      return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
#endif
    uint32_t now = device_get_tick();
    if (now - start >= 30000) {
      stop_blinking();
      return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
    if (now - last >= 100) {
      last = now;
#if ENABLE_IFACE_CTAPHID
      if (current_cmd_src == CTAP_SRC_HID) CTAPHID_SendKeepAlive(KEEPALIVE_STATUS_UPNEEDED);
#endif
    }
  }
  set_touch_result(TOUCH_NO);
  stop_blinking();
  return 0;
}

static uint8_t ctap_reset_data(void) {
  ctap_req_lifetime_end();
  // If the request comes after 10 seconds of powering up, the authenticator returns CTAP2_ERR_NOT_ALLOWED.
  if (device_get_tick() > 10000) {
    return CTAP2_ERR_NOT_ALLOWED;
  }
  if (ctap_config_long_touch_reset_enabled()) {
    uint8_t ret = ctap_wait_for_long_reset_touch();
    if (ret) return ret;
  } else {
    WAIT(CTAP2_ERR_USER_ACTION_TIMEOUT);
  }
  return ctap_install(1);
}

static uint8_t __attribute__((noinline)) ctap_large_blobs(CborEncoder *encoder, const uint8_t *params, size_t len) {
  static uint16_t expectedNextOffset, expectedLength;

  CborParser parser;
  CborEncoder map;
  CTAP_large_blobs lb;
  uint8_t set_buf[MAX_FRAGMENT_LENGTH];
  uint8_t buf[256]; // for pin auth
  ctap_req_src_t param_src = ctap_param_req_src();
  int ret = current_req_src.read ? parse_large_blobs_src(&parser, &lb, &param_src, len)
                                 : parse_large_blobs(&parser, &lb, params, len);
  CHECK_PARSER_RET(ret);
  uint8_t set_hash[SHA256_DIGEST_LENGTH] = {0};
  if (lb.parsed_params & PARAM_SET) {
    // The set byte string is used after PIN-token verification and keepalive.
    // Copy only that semantic fragment, and hash it while the request source is
    // still valid.
    sha256_ctx_t set_sha256;
    sha256_init(&set_sha256);
    size_t copied = 0;
    while (copied < lb.set_len) {
      size_t chunk = MIN(sizeof(buf), lb.set_len - copied);
      if (ctap_req_read_param_bytes(lb.set_offset + copied, set_buf + copied, chunk) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      sha256_update(&set_sha256, set_buf + copied, chunk);
      copied += chunk;
    }
    sha256_final(&set_sha256, set_hash);
  }
  ctap_req_lifetime_end();

  // 1. If offset is not present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // 2. If neither get nor set are present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // 3. If both get and set are present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // > Step 1-3 are checked when parsing.

  // 4. If get is present in the input map:
  if (lb.parsed_params & PARAM_GET) {
    //  a) If length is present, return CTAP1_ERR_INVALID_PARAMETER.
    //  b) If either of pinUvAuthParam or pinUvAuthProtocol are present, return CTAP1_ERR_INVALID_PARAMETER.
    //  c) If the value of get is greater than maxFragmentLength, return CTAP1_ERR_INVALID_LENGTH.
    //  > Step a-c are checked when parsing.

    int size = get_file_size(LB_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    //  d) If the value of offset is greater than the length of the stored serialized large-blob array,
    //     return CTAP1_ERR_INVALID_PARAMETER.
    if ((int)lb.offset > size) {
      DBG_MSG("4-d not satisfied\n");
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    //  e) Return a CBOR map, as defined below, where the value of config is a substring of the stored serialized
    //     large-blob array. The substring SHOULD start at the offset given in offset and contain the number of bytes
    //     specified as get's value. If too few bytes exist at that offset, return the maximum number available.
    //     Note that if offset is equal to the length of the serialized large-blob array then this will result
    //     in a zero-length substring.
    if (lb.offset + (int)lb.get > size) lb.get = size - lb.offset;
    DBG_MSG("read %hu bytes at %hu\n", lb.get, lb.offset);
    KEEPALIVE();
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, LB_RESP_CONFIG);
    CHECK_CBOR_RET(ret);
    // to save RAM, we encode the buffer manually
    uint8_t *ptr = map.data.ptr;
    ret = cbor_encode_uint(&map, lb.get);
    CHECK_CBOR_RET(ret);
    *ptr |= 0x40; // CBOR Major type 2
    if (read_file(LB_FILE, map.data.ptr, lb.offset, lb.get) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    map.data.ptr += lb.get;
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
  } else {
    // 5. Else (implying that set is present in the input map):
    //    a) If the length of the value of set is greater than maxFragmentLength, return CTAP1_ERR_INVALID_LENGTH.
    //       > Checked when paring.
    //    b) If the value of offset is zero:
    if (lb.offset == 0) {
      //     i. If length is not present, return CTAP1_ERR_INVALID_PARAMETER.
      //     ii. If the value of length is greater than 1024 bytes and exceeds the capacity of the device,
      //         return CTAP2_ERR_LARGE_BLOB_STORAGE_FULL. (Authenticators MUST be capable of storing at least 1024
      //         bytes.)
      //     iii. If the value of length is less than 17, return CTAP1_ERR_INVALID_PARAMETER.
      //         > Step i - iii are checked when parsing.

      //     iv. Set expectedLength to the value of length.
      expectedLength = lb.length;
      //     v. Set expectedNextOffset to zero.
      expectedNextOffset = 0;
    }
    //    c) Else (i.e. the value of offset is not zero):
    //       If length is present, return CTAP1_ERR_INVALID_PARAMETER.
    //       > Checked when paring.
    //    d) If the value of offset is not equal to expectedNextOffset, return CTAP1_ERR_INVALID_SEQ.
    if (lb.offset != expectedNextOffset) {
      DBG_MSG("5-d not satisfied\n");
      return CTAP1_ERR_INVALID_SEQ;
    }
    //    e) If the authenticator is protected by some form of user verification
    //       or the alwaysUv option ID is present and true:
    if (has_pin()) {
      //     i. If pinUvAuthParam is absent from the input map, then end the operation by
      //        returning CTAP2_ERR_PUAT_REQUIRED.
      if (!(lb.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
        DBG_MSG("5-e-i not satisfied\n");
        return CTAP2_ERR_PUAT_REQUIRED;
      }
      //     ii. If pinUvAuthProtocol is absent from the input map, then end the operation by
      //         returning CTAP2_ERR_MISSING_PARAMETER.
      if (!(lb.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
        DBG_MSG("5-e-ii not satisfied\n");
        return CTAP2_ERR_MISSING_PARAMETER;
      }
      //     iii. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
      //       > Checked when paring.
      //     iv. The authenticator calls verify(pinUvAuthToken, 32×0xff || h'0c00' || uint32LittleEndian(offset) ||
      //         SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two),
      //         pinUvAuthParam).
      //         If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID.
      memset(buf, 0xFF, 32);
      buf[32] = 0x0C;
      buf[33] = 0x00;
      buf[34] = lb.offset & 0xFF;
      buf[35] = lb.offset >> 8;
      buf[36] = 0x00;
      buf[37] = 0x00;
      memcpy(buf + 38, set_hash, SHA256_DIGEST_LENGTH);
      if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      if (!cp_verify_pin_token(buf, 70, lb.pin_uv_auth_param, lb.pin_uv_auth_protocol)) {
        DBG_MSG("Fail to verify pin token\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //     v. Check if the pinUvAuthToken has the lbw permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
      if (!cp_has_permission(CP_PERMISSION_LBW)) {
        DBG_MSG("Fail to verify pin permission\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
    }
    //    f) If the sum of offset and the length of the value of set is greater than the value of expectedLength,
    //       return CTAP1_ERR_INVALID_PARAMETER.
    if (lb.offset + lb.set_len > (size_t)expectedLength) {
      DBG_MSG("5-g not satisfied, %hu + %zu > %hu\n", lb.offset, lb.set_len, expectedLength);
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    //    g) If the value of offset is zero, prepare a buffer to receive a new serialized large-blob array.
    //    h) Append the value of set to the buffer containing the pending serialized large-blob array.
    KEEPALIVE();
    if (write_file(LB_FILE_TMP, set_buf, lb.offset, lb.set_len, lb.offset == 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    //    i) Update expectedNextOffset to be the new length of the pending serialized large-blob array.
    expectedNextOffset += lb.set_len;
    //    j) If the length of the pending serialized large-blob array is equal to expectedLength:
    if (expectedNextOffset == expectedLength) {
      //     i. Verify that the final 16 bytes in the buffer are the truncated SHA-256 hash of the preceding bytes.
      //        If the hash does not match, return CTAP2_ERR_INTEGRITY_FAILURE.
      int offset = 0;
      expectedLength -= 16;
      sha256_ctx_t sha256;
      sha256_init(&sha256);
      while (offset < expectedLength) {
        int to_read = sizeof(buf);
        if (to_read > expectedLength - offset) to_read = expectedLength - offset;
        if (read_file(LB_FILE_TMP, buf, offset, to_read) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        sha256_update(&sha256, buf, to_read);
        offset += to_read;
      }
      sha256_final(&sha256, buf);
      if (read_file(LB_FILE_TMP, buf + 16, offset, 16) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (memcmp_s(buf, buf + 16, 16)) return CTAP2_ERR_INTEGRITY_FAILURE;
      //     ii. Commit the contents of the buffer as the new serialized large-blob array for this authenticator.
      if (fs_rename(LB_FILE_TMP, LB_FILE) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      //     iii. Return CTAP2_OK and an empty response.
    }
    //    k) Else:
    //       i. More data is needed to complete the pending serialized large-blob array.
    //       ii. Return CTAP2_OK and an empty response. Await further writes.
    //    > DO NOTHING
  }
  return 0;
}

static int ctap_process_cbor(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len) {
  if (req_len == 0) return -1;

  cp_pin_uv_auth_token_usage_timer_observer();

  // Use the shared session buffer as the encoder buffer so that
  // large responses (e.g. getAssertion with hmac-secret, ~320 bytes) do not
  // overflow the APDU response buffer (shared_io_buffer, 256 bytes).  When the
  // response fits the APDU buffer it is copied back; otherwise it is streamed
  // via apdu_response_source_set.
  uint8_t *encode_buf = applet_session_scratch.buffer;
  const size_t encode_buf_size = sizeof(applet_session_scratch.buffer);

  CborEncoder encoder;
  cbor_encoder_init(&encoder, encode_buf, encode_buf_size, 0);

  uint8_t cmd;
  if (current_req_src.read) {
    if (ctap_req_read_payload_bytes(0, &cmd, sizeof(cmd)) < 0) {
      ctap_req_lifetime_end();
      return -1;
    }
  } else {
    cmd = *req++;
  }
  req_len--;
  uint8_t status = CTAP2_ERR_UNHANDLED_REQUEST;
  switch (cmd) {
  case CTAP_MAKE_CREDENTIAL:
    DBG_MSG("-----------------MC-------------------\n");
    status = ctap_make_credential(&encoder, req, req_len);
    goto set_resp;
  case CTAP_GET_ASSERTION:
    DBG_MSG("-----------------GA-------------------\n");
    status = ctap_get_assertion(&encoder, req, req_len, false);
    goto set_resp;
  case CTAP_GET_NEXT_ASSERTION:
    DBG_MSG("----------------NEXT------------------\n");
    status = ctap_get_next_assertion(&encoder);
    goto set_resp;
  case CTAP_CLIENT_PIN:
    DBG_MSG("-----------------CP-------------------\n");
    status = ctap_client_pin(&encoder, req, req_len);
    goto set_resp;
  case CTAP_RESET:
    DBG_MSG("----------------RESET-----------------\n");
    status = ctap_reset_data();
    goto set_resp;
  case CTAP_CRED_MANAGE_LEGACY: // compatible with old libfido2
    cmd = CTAP_CREDENTIAL_MANAGEMENT;
  case CTAP_CREDENTIAL_MANAGEMENT:
    DBG_MSG("----------------CM--------------------\n");
    status = ctap_credential_management(&encoder, req, req_len);
    goto set_resp;
  case CTAP_SELECTION:
    DBG_MSG("----------------SELECTION-------------\n");
    status = ctap_selection();
    goto set_resp;
  case CTAP_LARGE_BLOBS:
    DBG_MSG("----------------LB--------------------\n");
    status = ctap_large_blobs(&encoder, req, req_len);
    goto set_resp;
  case CTAP_CONFIG:
    DBG_MSG("----------------CONFIG----------------\n");
    status = ctap_config(&encoder, req, req_len);
    goto set_resp;
  default:
    *resp = CTAP2_ERR_UNHANDLED_REQUEST;
    goto finish_status_only;
  }

#if ENABLE_NFC
set_resp:
  if (status == CTAP_NFC_KEEPALIVE_PENDING) {
    *resp = nfc_pending_state.keepalive_status;
    *resp_len = 1;
    last_cmd = cmd;
    return 1;
  }
#else
set_resp:
#endif
  *resp = status;
  SET_RESP();
  if (*resp_len > APDU_BUFFER_SIZE && status == 0) {
    // Prepend the status byte by shifting the CBOR data right.
    size_t cbor_len = *resp_len - 1;
    memmove(encode_buf + 1, encode_buf, cbor_len);
    encode_buf[0] = *resp;
    if (!hid_cbor_stream_response_active) {
      // Response is too large for the APDU buffer; stream it via GET RESPONSE.
      apdu_response_source_set((uint32_t)*resp_len, SW_NO_ERROR, ctap_large_response_read_at, NULL, encode_buf);
      *resp_len = 1; // initial APDU payload: status byte only
    }
  } else if (*resp_len > 1 && status == 0) {
    memmove(resp + 1, encode_buf, *resp_len - 1);
  }
  goto finish;

finish_status_only:
  *resp_len = 1;

finish:
  last_cmd = cmd;
  if (*resp != 0) { // do not allow GET_NEXT_ASSERTION if error occurs
    last_cmd = CTAP_INVALID_CMD;
  }
  return 0;
}

static int ctap_req_source_begin(const ctap_req_src_t *src) {
  if (!src || !src->read) return -1;
  if (current_req_src.read != NULL) return -1;
  current_req_src = *src;
  return 0;
}

int ctap_process_cbor_with_src(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len, ctap_src_t src) {

  if (current_cmd_src != CTAP_SRC_NONE) return -1;
  // Must set current_cmd_src to CTAP_SRC_NONE before return
  current_cmd_src = src;
  current_req_mem = req;
  current_req_mem_len = req_len;
  int ret = ctap_process_cbor(req, req_len, resp, resp_len);
  ctap_req_lifetime_end();
  current_cmd_src = CTAP_SRC_NONE;
  return ret;
}

int ctap_process_cbor_stream_source_with_src(const ctap_req_src_t *req_src, uint8_t *scratch, size_t scratch_len,
                                             CTAPHID_TxSource *source, ctap_src_t src) {
  if (!req_src || !req_src->read || req_src->len == 0 || !scratch || scratch_len == 0 || !source) return -1;
  if (current_cmd_src != CTAP_SRC_NONE) return -1;

  memset(source, 0, sizeof(*source));
  memset(&mc_stream_state, 0, sizeof(mc_stream_state));
  memset(&mem_stream_state, 0, sizeof(mem_stream_state));
  memset(&mldsa_stream_state, 0, sizeof(mldsa_stream_state));

  if (ctap_req_source_begin(req_src) < 0) return -1;

  uint8_t cmd;
  if (ctap_req_read_payload_bytes(0, &cmd, sizeof(cmd)) < 0) {
    ctap_req_lifetime_end();
    return -1;
  }

  if (cmd == CTAP_GET_INFO) {
    cp_pin_uv_auth_token_usage_timer_observer();
    if (ctap_prepare_get_info_stream(source) == 0) {
      last_cmd = CTAP_GET_INFO;
      ctap_req_lifetime_end();
      return 1;
    }
    ctap_req_lifetime_end();
    return -1;
  }

  uint8_t *resp = NULL;
  size_t resp_len = 0;
  if (CTAPHID_AcquireSharedBuffer(&resp, &resp_len) != 0) {
    ctap_req_lifetime_end();
    return -1;
  }

  if (cmd != CTAP_MAKE_CREDENTIAL) {
    current_cmd_src = src;
    if (src == CTAP_SRC_HID) ctap_begin_hid_cbor_stream_response();
    int ret = ctap_process_cbor(scratch, req_src->len, resp, &resp_len);
    ctap_end_hid_cbor_stream_response();
    current_cmd_src = CTAP_SRC_NONE;
    if (ret < 0) {
      CTAPHID_ReleaseSharedBuffer();
      ctap_req_lifetime_end();
      return -1;
    }
    if (mldsa_stream_state.pending && resp[0] == 0) {
      source->total_len = mldsa_stream_state.total_len;
      source->read = ctap_mldsa_stream_read;
      source->close = CTAPHID_CloseSharedBufferSource;
      source->ctx = &mldsa_stream_state;
      ctap_req_lifetime_end();
      return 1;
    }

    if (ctap_prepare_hid_cbor_stream_source(resp[0], resp_len, source)) {
      ctap_req_lifetime_end();
      return 1;
    }

    mem_stream_state.buf = resp;
    mem_stream_state.len = resp_len;
    mem_stream_state.emitted = 0;
    source->total_len = mem_stream_state.len;
    source->read = ctap_mem_stream_read;
    source->close = CTAPHID_CloseSharedBufferSource;
    source->ctx = &mem_stream_state;
    ctap_req_lifetime_end();
    return 1;
  }

  stream_resp_base = resp;
  stream_make_credential_response = true;

  CborEncoder encoder;
  cbor_encoder_init(&encoder, resp + 1, resp_len - 1, 0);

  current_cmd_src = src;
  uint8_t status = ctap_make_credential(&encoder, scratch, req_src->len - 1);
  current_cmd_src = CTAP_SRC_NONE;
  ctap_req_lifetime_end();
  stream_make_credential_response = false;
  stream_resp_base = NULL;

  resp[0] = status;
  last_cmd = CTAP_MAKE_CREDENTIAL;
  if (status != 0) last_cmd = CTAP_INVALID_CMD;

  if (status == 0 && mc_stream_state.prepared) {
    source->total_len = mc_stream_state.total_len;
    source->read = ctap_make_credential_stream_read;
    source->close = CTAPHID_CloseSharedBufferSource;
    source->ctx = &mc_stream_state;
    return 1;
  }

  mem_stream_state.buf = resp;
  mem_stream_state.len = status == 0 ? 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1) : 1;
  mem_stream_state.emitted = 0;
  source->total_len = mem_stream_state.len;
  source->read = ctap_mem_stream_read;
  source->close = CTAPHID_CloseSharedBufferSource;
  source->ctx = &mem_stream_state;
  return 1;
}

int ctap_process_cbor_stream_with_src(uint8_t *req, size_t req_len, uint8_t *scratch, size_t scratch_len,
                                      CTAPHID_TxSource *source, ctap_src_t src) {
  if (!req) return -1;
  ctap_req_src_t req_src = {
      .read = ctap_mem_req_read,
      .ctx = req,
      .base_offset = 0,
      .len = req_len,
  };
  return ctap_process_cbor_stream_source_with_src(&req_src, scratch, scratch_len, source, src);
}

static int ctap_prepare_make_credential_apdu_response(uint8_t *req, size_t req_len, RAPDU *rapdu) {
  uint8_t *resp = rapdu->data;
  size_t resp_len = APDU_BUFFER_SIZE;

  memset(&mc_stream_state, 0, sizeof(mc_stream_state));
  stream_resp_base = resp;
  stream_make_credential_response = true;

  CborEncoder encoder;
  cbor_encoder_init(&encoder, resp + 1, resp_len - 1, 0);

  uint8_t status = ctap_make_credential(&encoder, req + 1, req_len - 1);
  ctap_req_lifetime_end();

  stream_make_credential_response = false;
  stream_resp_base = NULL;

  resp[0] = status;
  last_cmd = CTAP_MAKE_CREDENTIAL;
  if (status != 0) last_cmd = CTAP_INVALID_CMD;

#if ENABLE_NFC
  if (status == CTAP_NFC_KEEPALIVE_PENDING) {
    rapdu->data[0] = nfc_pending_state.keepalive_status;
    rapdu->len = 1;
    rapdu->sw = 0x9100;
    return 1;
  }
#endif

  if (status == 0 && mc_stream_state.prepared) {
    apdu_response_source_set((uint32_t)mc_stream_state.total_len, SW_NO_ERROR, ctap_make_credential_stream_read_at,
                             NULL, &mc_stream_state);
    return 0;
  }

  rapdu->len = status == 0 ? (uint16_t)(1 + cbor_encoder_get_buffer_size(&encoder, resp + 1)) : 1;
  return 0;
}

static int ctap_process_apdu_cbor_message(uint8_t *req, size_t req_len, RAPDU *rapdu) {
  if (req_len == 0) {
    rapdu->sw = SW_WRONG_LENGTH;
    return 0;
  }

  uint8_t cmd;
  if (current_req_src.read) {
    if (ctap_req_read_payload_bytes(0, &cmd, sizeof(cmd)) < 0) {
      rapdu->sw = SW_UNABLE_TO_PROCESS;
      ctap_req_lifetime_end();
      return 0;
    }
  } else {
    cmd = *req;
  }

  if (cmd == CTAP_GET_INFO) {
    cp_pin_uv_auth_token_usage_timer_observer();
    CTAPHID_TxSource source;
    memset(&source, 0, sizeof(source));
    if (ctap_prepare_get_info_stream(&source) == 0) {
      apdu_response_source_set((uint32_t)source.total_len, SW_NO_ERROR, ctap_const_stream_read_at, NULL,
                               source.ctx);
      last_cmd = CTAP_GET_INFO;
      ctap_req_lifetime_end();
      return 0;
    }
    last_cmd = CTAP_INVALID_CMD;
    rapdu->sw = SW_UNABLE_TO_PROCESS;
    ctap_req_lifetime_end();
    return 0;
  }

  if (cmd == CTAP_MAKE_CREDENTIAL) return ctap_prepare_make_credential_apdu_response(req, req_len, rapdu);

  size_t len = APDU_BUFFER_SIZE;
  int ret = ctap_process_cbor(req, req_len, rapdu->data, &len);
  ctap_req_lifetime_end();
  rapdu->len = (uint16_t)len;
  if (ret == 1) {
    rapdu->sw = 0x9100;
    return 1;
  }
  return ret;
}

int ctap_process_apdu_source_with_src(const CAPDU *capdu, const ctap_req_src_t *req_src, RAPDU *rapdu, ctap_src_t src) {
  int ret = 0;
  LL = 0;
  if (!capdu || !req_src || !req_src->read || req_src->len != LC) EXCEPT(SW_WRONG_LENGTH);
  if (current_cmd_src != CTAP_SRC_NONE) EXCEPT(SW_UNABLE_TO_PROCESS);
  // Must set current_cmd_src to CTAP_SRC_NONE before return
  current_cmd_src = src;
  if (ctap_req_source_begin(req_src) < 0) {
    current_cmd_src = CTAP_SRC_NONE;
    EXCEPT(SW_UNABLE_TO_PROCESS);
  }
  SW = SW_NO_ERROR;
  if (CLA == 0x80) {
    if (INS == CTAP_INS_MSG) {
#if ENABLE_NFC
      if (is_nfc() && (P1 & 0x80) != 0 && ctap_nfc_pending_store(DATA, LC, 1) < 0) {
        current_cmd_src = CTAP_SRC_NONE;
        ctap_req_lifetime_end();
        EXCEPT(SW_WRONG_LENGTH);
      }
#endif

      ret = ctap_process_apdu_cbor_message(DATA, LC, rapdu);
      if (ret != 1) ctap_nfc_pending_reset();
    } else {
#if ENABLE_NFC
      if (is_nfc() && INS == CTAP_NFC_GET_RESPONSE) {
        if (!nfc_pending_state.active || !nfc_pending_state.allow_poll) {
          current_cmd_src = CTAP_SRC_NONE;
          ctap_req_lifetime_end();
          EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
        }

        if (P1 == CTAP_NFC_GET_RESPONSE) {
          RDATA[0] = CTAP2_ERR_KEEPALIVE_CANCEL;
          LL = 1;
          ctap_nfc_pending_reset();
          current_cmd_src = CTAP_SRC_NONE;
          ctap_req_lifetime_end();
          return 0;
        }

        current_req_src.read = ctap_nfc_pending_req_read;
        current_req_src.ctx = &nfc_pending_state;
        current_req_src.base_offset = 0;
        current_req_src.len = nfc_pending_state.request_len;
        uint8_t pending_req_head[1];
        uint8_t *pending_req = nfc_pending_state.request;
        if (nfc_pending_state.request_in_file) {
          if (ctap_req_read_payload_bytes(0, pending_req_head, sizeof(pending_req_head)) < 0) {
            ctap_nfc_pending_reset();
            current_cmd_src = CTAP_SRC_NONE;
            ctap_req_lifetime_end();
            EXCEPT(SW_UNABLE_TO_PROCESS);
          }
          pending_req = pending_req_head;
        }
        ret = ctap_process_apdu_cbor_message(pending_req, nfc_pending_state.request_len, rapdu);
        if (ret != 1) ctap_nfc_pending_reset();
        current_cmd_src = CTAP_SRC_NONE;
        ctap_req_lifetime_end();
        if (ret < 0)
          EXCEPT(SW_UNABLE_TO_PROCESS);
        else
          return 0;
      }
#endif
      current_cmd_src = CTAP_SRC_NONE;
      ctap_req_lifetime_end();
      EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else if (CLA == 0x00) {
    switch (INS) {
    case U2F_REGISTER:
      if (ctap_config_always_uv_enabled()) EXCEPT(SW_INS_NOT_SUPPORTED);
      ret = u2f_register(capdu, rapdu);
      break;
    case U2F_AUTHENTICATE:
      if (ctap_config_always_uv_enabled()) EXCEPT(SW_INS_NOT_SUPPORTED);
      ret = u2f_authenticate(capdu, rapdu);
      break;
    case U2F_VERSION:
      ret = u2f_version(capdu, rapdu);
      break;
    case U2F_SELECT:
      ret = u2f_select(capdu, rapdu);
      break;
    case CTAP_INS_MSG:
      LL = 0;
      SW = SW_NO_ERROR;
      break;
    default:
      current_cmd_src = CTAP_SRC_NONE;
      ctap_req_lifetime_end();
      EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else {
    current_cmd_src = CTAP_SRC_NONE;
    ctap_req_lifetime_end();
    EXCEPT(SW_CLA_NOT_SUPPORTED);
  }

  if (is_nfc() && ret == 1) {
    current_cmd_src = CTAP_SRC_NONE;
    ctap_req_lifetime_end();
    return 0;
  }

  current_cmd_src = CTAP_SRC_NONE;
  ctap_req_lifetime_end();
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  else
    return 0;
}

int ctap_process_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src) {
  if (!capdu) {
    if (rapdu) {
      rapdu->len = 0;
      rapdu->sw = SW_WRONG_LENGTH;
    }
    return 0;
  }

  ctap_req_src_t req_src = {
      .read = ctap_mem_req_read,
      .ctx = (void *)capdu->data,
      .base_offset = 0,
      .len = LC,
  };
  return ctap_process_apdu_source_with_src(capdu, &req_src, rapdu, src);
}

int ctap_process_pke_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src) {
  if (!capdu || capdu->lc == 0 || capdu->lc > pke_buffer_size()) {
    rapdu->len = 0;
    rapdu->sw = SW_WRONG_LENGTH;
    return 0;
  }

  ctap_req_src_t req_src = {
      .read = ctap_pke_req_read,
      .ctx = NULL,
      .base_offset = 0,
      .len = capdu->lc,
  };
  return ctap_process_apdu_source_with_src(capdu, &req_src, rapdu, src);
}

int ctap_nfc_pending_active(void) {
#if ENABLE_NFC
  return nfc_pending_state.active != 0;
#else
  return 0;
#endif
}

int ctap_wink(void) {
  start_blinking_interval(1, 50);
  return 0;
}
