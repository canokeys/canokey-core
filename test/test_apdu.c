// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <cmocka.h>
#include <cbor.h>

#include <admin.h>
#include <applets.h>
#include <applet-scratch.h>
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <canokey-core-git-rev.h>
#include <ccid.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device-config.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <platform-config.h>
#include <pke.h>
#include "../applets/ctap/secret.h"
#include "../applets/ctap/cose-key.h"
#include "../applets/ctap/ctap-errors.h"
#include "../applets/ctap/ctap-parser.h"
#include "../applets/ctap/ctap-internal.h"
#include <ecc.h>
#include <hmac.h>
#include <sha.h>
#include <string.h>
#include <usb_device.h>
#include <usbd_ctaphid.h>
#include <usbd_ccid.h>
#include <usbd_kbdhid.h>
#include <usbd_ctlreq.h>

#include <ctap-parser.h>

#define CTAP_LARGE_BLOBS 0x0C
#define LB_FILE "ctap_lb"

#include "../virt-card/usb-dummy.h"

extern ccid_bulkin_data_t bulkin_data;

// One-shot read failure injection for the CTAP capacity-cache tests.
static bool bd_read_fails;
static int bd_read_fail_count;
static const struct lfs_config *test_apdu_fs_cfg;

static int test_bd_read(const struct lfs_config *cfg, lfs_block_t block, lfs_off_t off, void *buffer,
                        lfs_size_t size) {
  if (bd_read_fails || bd_read_fail_count > 0) {
    if (bd_read_fail_count > 0) --bd_read_fail_count;
    return LFS_ERR_IO;
  }
  return lfs_filebd_read(cfg, block, off, buffer, size);
}

static void encode_sm2_config(uint8_t wire[CTAP_SM2_CONFIG_WIRE_SIZE], const CTAP_sm2_attr *attr) {
  const uint32_t words[2] = {htobe32((uint32_t)attr->curve_id), htobe32((uint32_t)attr->algo_id)};
  memcpy(wire, words, CTAP_SM2_CONFIG_WIRE_SIZE);
}

static const void *find_bytes(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
  const uint8_t *h = haystack;
  const uint8_t *n = needle;

  if (needle_len == 0) return haystack;
  if (haystack_len < needle_len) return NULL;
  for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
    if (memcmp(h + i, n, needle_len) == 0) return h + i;
  }
  return NULL;
}

static void put_cbor_text(uint8_t **p, const char *text) {
  size_t len = strlen(text);

  if (len < 24) {
    *(*p)++ = 0x60 | (uint8_t)len;
  } else {
    assert_true(len <= UINT8_MAX);
    *(*p)++ = 0x78;
    *(*p)++ = (uint8_t)len;
  }
  memcpy(*p, text, len);
  *p += len;
}

static void put_cbor_bytes(uint8_t **p, const uint8_t *buf, size_t len) {
  if (len < 24) {
    *(*p)++ = 0x40 | (uint8_t)len;
  } else {
    assert_true(len <= UINT8_MAX);
    *(*p)++ = 0x58;
    *(*p)++ = (uint8_t)len;
  }
  memcpy(*p, buf, len);
  *p += len;
}

static void put_cbor_int(uint8_t **p, int32_t value) {
  uint8_t major = value < 0 ? 0x20 : 0x00;
  uint64_t encoded = value < 0 ? (uint64_t)(-1 - (int64_t)value) : (uint64_t)value;

  if (encoded < 24) {
    *(*p)++ = major | (uint8_t)encoded;
  } else if (encoded <= UINT8_MAX) {
    *(*p)++ = major | 24;
    *(*p)++ = (uint8_t)encoded;
  } else {
    assert_true(encoded <= UINT16_MAX);
    *(*p)++ = major | 25;
    *(*p)++ = (uint8_t)(encoded >> 8);
    *(*p)++ = (uint8_t)encoded;
  }
}

static size_t build_hmac_secret_mc_make_credential(uint8_t *req, bool include_hmac_secret, int32_t alg_type,
                                                   const uint8_t *key_agreement, const uint8_t *salt_enc,
                                                   const uint8_t *salt_auth) {
  uint8_t *p = req;
  uint8_t zero32[32] = {0};
  uint8_t default_key_agreement[64] = {0};
  uint8_t default_salt_enc[64] = {0};
  uint8_t default_salt_auth[16] = {0};
  const uint8_t user_id[] = {1};

  if (!key_agreement) key_agreement = default_key_agreement;
  if (!salt_enc) salt_enc = default_salt_enc;
  if (!salt_auth) salt_auth = default_salt_auth;

  *p++ = CTAP_MAKE_CREDENTIAL;
  *p++ = include_hmac_secret ? 0xA6 : 0xA5;
  *p++ = 0x01;
  put_cbor_bytes(&p, zero32, 32);
  *p++ = 0x02;
  *p++ = 0xA1;
  put_cbor_text(&p, "id");
  put_cbor_text(&p, "example.com");
  *p++ = 0x03;
  *p++ = 0xA1;
  put_cbor_text(&p, "id");
  put_cbor_bytes(&p, user_id, sizeof(user_id));
  *p++ = 0x04;
  *p++ = 0x81;
  *p++ = 0xA2;
  put_cbor_text(&p, "alg");
  put_cbor_int(&p, alg_type);
  put_cbor_text(&p, "type");
  put_cbor_text(&p, "public-key");
  *p++ = 0x06;
  *p++ = include_hmac_secret ? 0xA2 : 0xA1;
  if (include_hmac_secret) {
    put_cbor_text(&p, "hmac-secret");
    *p++ = 0xF5;
  }
  put_cbor_text(&p, "hmac-secret-mc");
  *p++ = 0xA3;
  *p++ = 0x01;
  *p++ = 0xA5;
  *p++ = 0x01;
  *p++ = COSE_KEY_KTY_EC2;
  *p++ = 0x03;
  *p++ = 0x38;
  *p++ = 24;
  *p++ = 0x20;
  *p++ = COSE_KEY_CRV_P256;
  *p++ = 0x21;
  put_cbor_bytes(&p, key_agreement, 32);
  *p++ = 0x22;
  put_cbor_bytes(&p, key_agreement + 32, 32);
  *p++ = 0x02;
  put_cbor_bytes(&p, salt_enc, 64);
  *p++ = 0x03;
  put_cbor_bytes(&p, salt_auth, 16);
  *p++ = 0x07;
  *p++ = 0xA0;

  return (size_t)(p - req);
}

static size_t build_third_party_payment_make_credential(uint8_t *req, bool rk, bool third_party_payment) {
  uint8_t *p = req;
  uint8_t zero32[32] = {0};
  const uint8_t user_id[] = {1};

  *p++ = CTAP_MAKE_CREDENTIAL;
  *p++ = 0xA6;
  *p++ = 0x01;
  put_cbor_bytes(&p, zero32, 32);
  *p++ = 0x02;
  *p++ = 0xA1;
  put_cbor_text(&p, "id");
  put_cbor_text(&p, "pay.example");
  *p++ = 0x03;
  *p++ = 0xA1;
  put_cbor_text(&p, "id");
  put_cbor_bytes(&p, user_id, sizeof(user_id));
  *p++ = 0x04;
  *p++ = 0x81;
  *p++ = 0xA2;
  put_cbor_text(&p, "alg");
  put_cbor_int(&p, COSE_ALG_ES256);
  put_cbor_text(&p, "type");
  put_cbor_text(&p, "public-key");
  *p++ = 0x06;
  *p++ = 0xA1;
  put_cbor_text(&p, "thirdPartyPayment");
  *p++ = third_party_payment ? 0xF5 : 0xF4;
  *p++ = 0x07;
  *p++ = 0xA1;
  put_cbor_text(&p, "rk");
  *p++ = rk ? 0xF5 : 0xF4;

  return (size_t)(p - req);
}

static size_t build_third_party_payment_get_assertion(uint8_t *req, const credential_id *cid) {
  uint8_t *p = req;
  uint8_t zero32[32] = {0};

  *p++ = CTAP_GET_ASSERTION;
  *p++ = 0xA5;
  *p++ = 0x01;
  put_cbor_text(&p, "pay.example");
  *p++ = 0x02;
  put_cbor_bytes(&p, zero32, 32);
  *p++ = 0x03;
  *p++ = 0x81;
  *p++ = 0xA2;
  put_cbor_text(&p, "id");
  put_cbor_bytes(&p, (const uint8_t *)cid, sizeof(*cid));
  put_cbor_text(&p, "type");
  put_cbor_text(&p, "public-key");
  *p++ = 0x04;
  *p++ = 0xA1;
  put_cbor_text(&p, "thirdPartyPayment");
  *p++ = 0xF5;
  *p++ = 0x05;
  *p++ = 0xA1;
  put_cbor_text(&p, "up");
  *p++ = 0xF4;

  return (size_t)(p - req);
}

static size_t build_enumerate_credentials_pin_message(uint8_t *msg, const uint8_t *rp_id_hash, bool metadata_only) {
  uint8_t *p = msg;

  *p++ = CM_CMD_ENUMERATE_CREDENTIALS_BEGIN;
  *p++ = metadata_only ? 0xA2 : 0xA1;
  *p++ = CM_PARAM_RP_ID_HASH;
  put_cbor_bytes(&p, rp_id_hash, SHA256_DIGEST_LENGTH);
  if (metadata_only) {
    put_cbor_int(&p, CM_PARAM_VENDOR_METADATA_ONLY);
    *p++ = 0xF5;
  }

  return (size_t)(p - msg);
}

static size_t build_third_party_payment_credential_management(uint8_t *req, const uint8_t *rp_id_hash,
                                                              const uint8_t *pin_auth, bool metadata_only) {
  uint8_t *p = req;

  *p++ = CTAP_CREDENTIAL_MANAGEMENT;
  *p++ = 0xA4;
  *p++ = CM_REQ_SUB_COMMAND;
  *p++ = CM_CMD_ENUMERATE_CREDENTIALS_BEGIN;
  *p++ = CM_REQ_SUB_COMMAND_PARAMS;
  *p++ = metadata_only ? 0xA2 : 0xA1;
  *p++ = CM_PARAM_RP_ID_HASH;
  put_cbor_bytes(&p, rp_id_hash, SHA256_DIGEST_LENGTH);
  if (metadata_only) {
    put_cbor_int(&p, CM_PARAM_VENDOR_METADATA_ONLY);
    *p++ = 0xF5;
  }
  *p++ = CM_REQ_PIN_UV_AUTH_PROTOCOL;
  *p++ = 0x01;
  *p++ = CM_REQ_PIN_UV_AUTH_PARAM;
  put_cbor_bytes(&p, pin_auth, PIN_AUTH_SIZE_P1);

  return (size_t)(p - req);
}

static size_t build_credential_management_get_next(uint8_t *req) {
  uint8_t *p = req;

  *p++ = CTAP_CREDENTIAL_MANAGEMENT;
  *p++ = 0xA1;
  *p++ = CM_REQ_SUB_COMMAND;
  *p++ = CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL;
  return (size_t)(p - req);
}

static int read_tx_source_all(CTAPHID_TxSource *source, uint8_t *out, size_t out_len, size_t *written) {
  size_t total = 0;

  while (total < source->total_len) {
    size_t chunk_written = 0;
    size_t chunk = MIN(out_len - total, source->total_len - total);
    if (chunk == 0) return -1;
    if (source->read(source->ctx, out + total, chunk, &chunk_written) != 0) return -1;
    if (chunk_written == 0) return -1;
    total += chunk_written;
  }
  *written = total;
  return 0;
}

enum { HID_CAPTURE_MAX_FRAMES = 64 };
static CTAPHID_FRAME hid_capture[HID_CAPTURE_MAX_FRAMES];
static size_t hid_capture_count;

static uint8_t capture_hid_report(USBD_HandleTypeDef *pdev, uint8_t *report, uint16_t len) {
  (void)pdev;
  if (len != sizeof(CTAPHID_FRAME) || hid_capture_count >= sizeof(hid_capture) / sizeof(hid_capture[0])) return 1;
  memcpy(&hid_capture[hid_capture_count++], report, sizeof(CTAPHID_FRAME));
  return 0;
}

static int capture_ctaphid_msg(const uint8_t *apdu, size_t apdu_len, uint8_t *response, size_t response_size,
                               size_t *response_len) {
  if (apdu_len > sizeof(((CTAPHID_FRAME *)0)->init.data)) return -1;

  hid_capture_count = 0;
  memset(hid_capture, 0, sizeof(hid_capture));
  CTAPHID_Init(capture_hid_report);

  CTAPHID_FRAME request = {0};
  request.cid = 0x12345678;
  request.init.cmd = CTAPHID_MSG;
  request.init.bcnth = (uint8_t)(apdu_len >> 8);
  request.init.bcntl = (uint8_t)apdu_len;
  memcpy(request.init.data, apdu, apdu_len);
  if (CTAPHID_OutEvent((uint8_t *)&request) != 1 || CTAPHID_Loop(0) != LOOP_SUCCESS || hid_capture_count == 0)
    return -1;

  const CTAPHID_FRAME *first = &hid_capture[0];
  const size_t total = MSG_LEN(*first);
  if (first->cid != request.cid || first->init.cmd != CTAPHID_MSG || total > response_size) return -1;

  size_t copied = MIN(total, sizeof(first->init.data));
  memcpy(response, first->init.data, copied);
  for (size_t i = 1; copied < total; ++i) {
    if (i >= hid_capture_count || hid_capture[i].cid != request.cid || hid_capture[i].cont.seq != i - 1) return -1;
    const size_t chunk = MIN(total - copied, sizeof(hid_capture[i].cont.data));
    memcpy(response + copied, hid_capture[i].cont.data, chunk);
    copied += chunk;
  }

  *response_len = total;
  return 0;
}

typedef struct {
  const uint8_t *ptr;
  size_t len;
} test_cbor_view;

static int test_cbor_read_len(const uint8_t **p, const uint8_t *end, uint8_t addl, size_t *len) {
  if (addl < 24) {
    *len = addl;
    return 0;
  }
  if (addl == 24) {
    if (*p >= end) return -1;
    *len = *(*p)++;
    return 0;
  }
  if (addl == 25) {
    if ((size_t)(end - *p) < 2) return -1;
    *len = ((size_t)(*p)[0] << 8) | (*p)[1];
    *p += 2;
    return 0;
  }
  return -1;
}

static int test_cbor_skip(const uint8_t **p, const uint8_t *end);

static int test_cbor_skip_array_or_map(const uint8_t **p, const uint8_t *end, uint8_t major, size_t len) {
  size_t items = major == 0xA0 ? len * 2 : len;
  for (size_t i = 0; i < items; ++i) {
    if (test_cbor_skip(p, end) < 0) return -1;
  }
  return 0;
}

static int test_cbor_skip(const uint8_t **p, const uint8_t *end) {
  if (*p >= end) return -1;
  uint8_t initial = *(*p)++;
  uint8_t major = initial & 0xE0;
  uint8_t addl = initial & 0x1F;
  size_t len;

  switch (major) {
  case 0x00:
  case 0x20:
    return test_cbor_read_len(p, end, addl, &len);
  case 0x40:
  case 0x60:
    if (test_cbor_read_len(p, end, addl, &len) < 0 || (size_t)(end - *p) < len) return -1;
    *p += len;
    return 0;
  case 0x80:
  case 0xA0:
    if (test_cbor_read_len(p, end, addl, &len) < 0) return -1;
    return test_cbor_skip_array_or_map(p, end, major, len);
  default:
    if (initial == 0xF4 || initial == 0xF5 || initial == 0xF6 || initial == 0xF7) return 0;
    return -1;
  }
}

static int test_cbor_map_lookup_int_key(const uint8_t *buf, size_t len, int key, test_cbor_view *value) {
  CborParser parser;
  CborValue map, item;
  if (cbor_parser_init(buf, len, 0, &parser, &map) != CborNoError || !cbor_value_is_map(&map) ||
      cbor_value_enter_container(&map, &item) != CborNoError)
    return -1;
  while (!cbor_value_at_end(&item)) {
    int64_t item_key;
    if (!cbor_value_is_integer(&item) || cbor_value_get_int64(&item, &item_key) != CborNoError ||
        cbor_value_advance(&item) != CborNoError || cbor_value_at_end(&item))
      return -1;
    const uint8_t *value_start = cbor_value_get_next_byte(&item);
    if (cbor_value_advance(&item) != CborNoError) return -1;
    if (item_key == key) {
      value->ptr = value_start;
      value->len = (size_t)(cbor_value_get_next_byte(&item) - value_start);
      return 0;
    }
  }
  return -1;
}

static int test_cbor_map_lookup_text_key(test_cbor_view map_value, const char *key, test_cbor_view *value) {
  const uint8_t *p = map_value.ptr;
  const uint8_t *end = map_value.ptr + map_value.len;
  size_t map_len;
  size_t key_len = strlen(key);

  if (p >= end || (*p & 0xE0) != 0xA0) return -1;
  if (test_cbor_read_len(&p, end, *p++ & 0x1F, &map_len) < 0) return -1;
  for (size_t i = 0; i < map_len; ++i) {
    size_t item_key_len;
    const uint8_t *item_key;
    const uint8_t *value_start;

    if (p >= end || (*p & 0xE0) != 0x60) return -1;
    if (test_cbor_read_len(&p, end, *p++ & 0x1F, &item_key_len) < 0 || (size_t)(end - p) < item_key_len) return -1;
    item_key = p;
    p += item_key_len;
    value_start = p;
    if (test_cbor_skip(&p, end) < 0) return -1;
    if (item_key_len == key_len && memcmp(item_key, key, key_len) == 0) {
      value->ptr = value_start;
      value->len = (size_t)(p - value_start);
      return 0;
    }
  }
  return -1;
}

static int test_cbor_get_bool(test_cbor_view value, bool *out) {
  if (value.len != 1) return -1;
  if (value.ptr[0] == 0xF4) {
    *out = false;
    return 0;
  }
  if (value.ptr[0] == 0xF5) {
    *out = true;
    return 0;
  }
  return -1;
}

static int test_cbor_get_byte_string(test_cbor_view value, const uint8_t **bytes, size_t *len) {
  const uint8_t *p = value.ptr;
  const uint8_t *end = value.ptr + value.len;

  if (p >= end || (*p & 0xE0) != 0x40) return -1;
  if (test_cbor_read_len(&p, end, *p++ & 0x1F, len) < 0 || (size_t)(end - p) < *len) return -1;
  *bytes = p;
  return 0;
}

static int test_cbor_get_uint(test_cbor_view value, uint64_t *out) {
  const uint8_t *p = value.ptr;
  const uint8_t *end = value.ptr + value.len;
  size_t value_len;

  if (p >= end || (*p & 0xE0) != 0x00) return -1;
  if (test_cbor_read_len(&p, end, *p++ & 0x1F, &value_len) < 0 || p != end) return -1;
  *out = value_len;
  return 0;
}

static int test_cbor_get_int(test_cbor_view value, int64_t *out) {
  CborParser parser;
  CborValue item;
  if (cbor_parser_init(value.ptr, value.len, 0, &parser, &item) != CborNoError || !cbor_value_is_integer(&item) ||
      cbor_value_get_int64(&item, out) != CborNoError || cbor_value_advance(&item) != CborNoError ||
      cbor_value_get_next_byte(&item) != value.ptr + value.len)
    return -1;
  return 0;
}

static int test_cbor_is_canonical(const uint8_t *buf, size_t len) {
  CborParser parser;
  CborValue value;

  if (cbor_parser_init(buf, len, 0, &parser, &value) != CborNoError) return -1;
  return cbor_value_validate(&value, CborValidateCanonicalFormat | CborValidateCompleteData) == CborNoError ? 0 : -1;
}

static int test_cbor_get_auth_data(const uint8_t *resp, size_t written, int auth_data_key, uint8_t *auth_data_buf,
                                   size_t auth_data_buf_len, size_t *auth_data_len) {
  test_cbor_view auth_data_value;
  const uint8_t *auth_data;
  size_t len = auth_data_buf_len;

  if (written == 0 || resp[0] != 0x00) return -1;
  if (test_cbor_map_lookup_int_key(resp + 1, written - 1, auth_data_key, &auth_data_value) < 0) return -1;
  if (test_cbor_get_byte_string(auth_data_value, &auth_data, &len) < 0) return -1;
  if (len > auth_data_buf_len || len <= 37) return -1;
  memcpy(auth_data_buf, auth_data, len);
  *auth_data_len = len;
  return 0;
}

static int test_cbor_get_auth_data_extensions(const uint8_t *resp, size_t written, int auth_data_key,
                                              uint8_t *auth_data_buf, size_t auth_data_buf_len,
                                              test_cbor_view *extension_map) {
  size_t auth_data_len;

  if (test_cbor_get_auth_data(resp, written, auth_data_key, auth_data_buf, auth_data_buf_len, &auth_data_len) < 0)
    return -1;
  if ((auth_data_buf[32] & 0x80) == 0) return -1;

  const uint8_t *auth_p = auth_data_buf + 37;
  const uint8_t *auth_end = auth_data_buf + auth_data_len;
  if (auth_data_buf[32] & 0x40) {
    auth_p += AAGUID_SIZE;
    if ((size_t)(auth_end - auth_p) < sizeof(uint16_t)) return -1;
    size_t cred_id_len = ((size_t)auth_p[0] << 8) | auth_p[1];
    auth_p += sizeof(uint16_t);
    if ((size_t)(auth_end - auth_p) < cred_id_len) return -1;
    auth_p += cred_id_len;
    if (test_cbor_skip(&auth_p, auth_end) < 0) return -1;
  }
  if (auth_p >= auth_end) return -1;
  extension_map->ptr = auth_p;
  extension_map->len = (size_t)(auth_end - auth_p);
  return 0;
}

static void assert_make_credential_auth_data_has_hmac_secret_mc(const uint8_t *resp, size_t written,
                                                                uint8_t *auth_data_buf, size_t auth_data_buf_len) {
  test_cbor_view extension_map, hmac_secret_value, hmac_secret_mc_value;
  const uint8_t *hmac_secret_mc;
  size_t hmac_secret_mc_len;
  bool hmac_secret;

  assert_int_equal(test_cbor_get_auth_data_extensions(resp, written, MC_RESP_AUTH_DATA, auth_data_buf,
                                                      auth_data_buf_len, &extension_map),
                   0);
  assert_true((auth_data_buf[32] & 0x40) != 0);
  assert_int_equal(test_cbor_map_lookup_text_key(extension_map, "hmac-secret", &hmac_secret_value), 0);
  assert_int_equal(test_cbor_get_bool(hmac_secret_value, &hmac_secret), 0);
  assert_true(hmac_secret);
  assert_int_equal(test_cbor_map_lookup_text_key(extension_map, "hmac-secret-mc", &hmac_secret_mc_value), 0);
  assert_int_equal(test_cbor_get_byte_string(hmac_secret_mc_value, &hmac_secret_mc, &hmac_secret_mc_len), 0);
  assert_int_equal(hmac_secret_mc_len, HMAC_SECRET_SALT_SIZE);
}

static void test_acquire_apdu_interface_releases_session_on_buffer_conflict(void **state) {
  (void)state;

  init_apdu_buffer();
  device_init();

  assert_int_equal(acquire_apdu_buffer(BUFFER_OWNER_CCID), 0);
  assert_int_equal(acquire_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID), -1);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);
  assert_int_equal(release_apdu_buffer(BUFFER_OWNER_CCID), 0);
}

static void test_ccid_power_on_does_not_steal_ctaphid_session(void **state) {
  (void)state;

  static const uint8_t power_on[] = {
      PC_TO_RDR_ICCPOWERON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  };
  static const uint8_t power_off[] = {
      PC_TO_RDR_ICCPOWEROFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  };

  init_apdu_buffer();
  device_init();
  CCID_Init();

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);
  assert_int_equal(acquire_apdu_buffer(BUFFER_OWNER_CTAPHID), 0);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_on, sizeof(power_on)), 0);
  CCID_Loop();
  CCID_InFinished(0);

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_off, sizeof(power_off)), 0);
  CCID_Loop();

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);
  assert_int_equal(release_apdu_buffer(BUFFER_OWNER_CTAPHID), 0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
}

static void test_ccid_slot_status_survives_ctaphid_release(void **state) {
  (void)state;
  uint8_t request[] = {PC_TO_RDR_GETSLOTSTATUS, 0, 0, 0, 0, 0, 0x37, 0, 0, 0};
  const uint8_t previous_state = usb_device.dev_state;
  init_apdu_buffer();
  device_init();
  USBD_CCID_Init(&usb_device);
  usb_device.dev_state = USBD_STATE_CONFIGURED;
  EPType *in = dummy_get_ep_by_addr(EP_IN(ccid));
  in->maxpacket = 64;
  in->xfer_buff = NULL;

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_CTAPHID), 0);
  // A USB interrupt queues the host's presence poll just before CTAP finishes.
  assert_int_equal(CCID_OutEvent(request, sizeof(request)), 0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
  CCID_Loop();

  assert_non_null(in->xfer_buff);
  const uint8_t *response = in->xfer_buff - CCID_CMD_HEADER_SIZE;
  assert_int_equal(response[0], RDR_TO_PC_SLOTSTATUS);
  assert_int_equal(response[6], 0x37);
  assert_int_equal(response[7], BM_ICC_PRESENT_INACTIVE);
  assert_int_equal(response[8], SLOT_NO_ERROR);
  USBD_CCID_DataIn(&usb_device);
  usb_device.dev_state = previous_state;
}

static void test_ctaphid_wait_services_only_ccid_presence_poll(void **state) {
  (void)state;
  uint8_t request[] = {PC_TO_RDR_GETSLOTSTATUS, 0, 0, 0, 0, 0, 0x38, 0, 0, 0};
  const uint8_t previous_state = usb_device.dev_state;
  init_apdu_buffer();
  device_init();
  CTAPHID_Init(capture_hid_report);
  USBD_CCID_Init(&usb_device);
  usb_device.dev_state = USBD_STATE_CONFIGURED;
  EPType *in = dummy_get_ep_by_addr(EP_IN(ccid));
  in->maxpacket = 64;
  in->xfer_buff = NULL;
  assert_int_equal(acquire_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID), 0);
  shared_io_buffer[0] = 0xA5;
  applet_session_scratch.buffer[0] = 0x5A;

  assert_int_equal(CCID_OutEvent(request, sizeof(request)), 0);
  assert_int_equal(CTAPHID_Loop(1), LOOP_SUCCESS);
  assert_non_null(in->xfer_buff);
  const uint8_t *response = in->xfer_buff - CCID_CMD_HEADER_SIZE;
  assert_int_equal(response[0], RDR_TO_PC_SLOTSTATUS);
  assert_int_equal(response[6], 0x38);
  assert_int_equal(response[7], BM_ICC_PRESENT_INACTIVE);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);
  assert_int_equal(shared_io_buffer[0], 0xA5);
  assert_int_equal(applet_session_scratch.buffer[0], 0x5A);
  USBD_CCID_DataIn(&usb_device);

  request[0] = PC_TO_RDR_ICCPOWERON;
  in->xfer_buff = NULL;
  assert_int_equal(CCID_OutEvent(request, sizeof(request)), 0);
  assert_int_equal(CTAPHID_Loop(1), LOOP_SUCCESS);
  assert_null(in->xfer_buff); // Power/reset commands must wait for the main loop.
  release_apdu_interface(DEVICE_APPLET_SESSION_CTAPHID, BUFFER_OWNER_CTAPHID);
  CCID_Init();
  usb_device.dev_state = previous_state;
}

static void test_ccid_rejects_reentrant_command_until_response_finishes(void **state) {
  (void)state;

  static const uint8_t first[] = {
      PC_TO_RDR_XFRBLOCK, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00,
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10,
  };
  static const uint8_t second[] = {
      PC_TO_RDR_XFRBLOCK, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00,
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x01,
  };
  const uint8_t *first_apdu = first + CCID_CMD_HEADER_SIZE;
  const uint8_t *second_apdu = second + CCID_CMD_HEADER_SIZE;

  init_apdu_buffer();
  device_init();
  CCID_Init();

  assert_int_equal(CCID_OutEvent((uint8_t *)first, sizeof(first)), 0);
  assert_memory_equal(shared_io_buffer, first_apdu, sizeof(first) - CCID_CMD_HEADER_SIZE);

  assert_int_equal(CCID_OutEvent((uint8_t *)second, sizeof(second)), 0);
  assert_memory_equal(shared_io_buffer, first_apdu, sizeof(first) - CCID_CMD_HEADER_SIZE);

  CCID_Loop();
  assert_int_equal(bulkin_data.bSeq, 0x11);
  ccid_bulkin_data_t first_response;
  memcpy(&first_response, &bulkin_data, sizeof(first_response));

  assert_int_equal(CCID_OutEvent((uint8_t *)second, sizeof(second)), 0);
  assert_memory_equal(&bulkin_data, &first_response, sizeof(first_response));

  CCID_InFinished(0);
  assert_int_equal(CCID_OutEvent((uint8_t *)second, sizeof(second)), 0);
  assert_memory_equal(shared_io_buffer, second_apdu, sizeof(second) - CCID_CMD_HEADER_SIZE);
  CCID_Loop();
  assert_int_equal(bulkin_data.bSeq, 0x22);
  CCID_InFinished(0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CCID);
}

static void test_pke_buffer_fallback_for_ctap(void **state) {
  (void)state;

  assert_true(pke_buffer_size() >= CTAP_MAX_REQUEST_SIZE);
  assert_int_equal(pke_buffer_clear(), 0);

  static const uint8_t payload[] = {
      0x01, 0xA6, 0x01, 0x58, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
  };
  uint8_t out[sizeof(payload)];
  uint8_t zero[sizeof(payload)] = {0};

  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), -1);
  assert_int_equal(pke_buffer_write(0, payload, sizeof(payload)), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_CTAP), 0);

  memset(out, 0, sizeof(out));
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_CTAP), 0);
  assert_int_equal(pke_buffer_read(0, out, sizeof(out)), 0);
  assert_memory_equal(out, payload, sizeof(payload));
  assert_int_equal(pke_buffer_clear(), 0);
  memset(out, 0xA5, sizeof(out));
  assert_int_equal(pke_buffer_read(0, out, sizeof(out)), 0);
  assert_memory_equal(out, zero, sizeof(out));
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_CTAP), 0);
}

static void test_ccid_extended_fido_request_uses_pke(void **state) {
  (void)state;

  enum { PAYLOAD_LEN = 300, APDU_LEN = 7 + PAYLOAD_LEN + 2, REQUEST_LEN = CCID_CMD_HEADER_SIZE + APDU_LEN };
  uint8_t request[REQUEST_LEN];
  memset(request, 0, sizeof(request));

  request[0] = PC_TO_RDR_XFRBLOCK;
  request[1] = APDU_LEN & 0xFF;
  request[2] = (APDU_LEN >> 8) & 0xFF;
  request[6] = 1;

  uint8_t *apdu = request + CCID_CMD_HEADER_SIZE;
  apdu[0] = 0x80;
  apdu[1] = CTAP_INS_MSG;
  apdu[2] = 0x80;
  apdu[4] = 0;
  apdu[5] = PAYLOAD_LEN >> 8;
  apdu[6] = PAYLOAD_LEN & 0xFF;
  apdu[7] = CTAP_GET_INFO;
  // The remaining payload bytes are ignored by GET INFO. Case 4E Le=0000
  // requests the maximum response and occupies the final two APDU bytes.

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  CCID_Init();

  for (size_t offset = 0; offset < sizeof(request);) {
    const uint8_t chunk = (uint8_t)MIN(sizeof(request) - offset, 64);
    assert_int_equal(CCID_OutEvent(request + offset, chunk), 0);
    offset += chunk;
  }
  CCID_Loop();

  assert_true(ccid_get_le32(bulkin_data.dwLength) > 2);
  assert_int_equal(bulkin_data.abData[0], CTAP1_ERR_SUCCESS);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);

  CCID_InFinished(0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CCID);

  CCID_Init();
  assert_int_equal(CCID_OutEvent(request, 64), 0);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), -1);
  CCID_AbortPendingCommand();
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CCID);
}

static void test_fido_chained_make_credential_nfc(void **state) {
  (void)state;

  static const uint8_t fido_private_key[PRI_KEY_SIZE] = {1};
  static const uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static const uint8_t mc_part1[] = {
      0x90, 0x10, 0x80, 0x00, 0xFA, 0x01, 0xA6, 0x01, 0x58, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
      0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63,
      0x64, 0x65, 0x66, 0x30, 0x02, 0xA2, 0x62, 0x69, 0x64, 0x6B, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x6F,
      0x72, 0x67, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x69, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x52, 0x50, 0x03, 0xA4,
      0x62, 0x69, 0x64, 0x58, 0x20, 0xF2, 0x0F, 0x6B, 0x47, 0xCB, 0x6E, 0xA1, 0x3C, 0x3E, 0xA4, 0x28, 0xE2, 0x4D, 0xF7,
      0x6B, 0x65, 0x8E, 0x8C, 0x7F, 0x3B, 0x39, 0x4E, 0x29, 0x3B, 0x44, 0x7D, 0xA3, 0x79, 0xB5, 0x7B, 0x78, 0x98, 0x64,
      0x69, 0x63, 0x6F, 0x6E, 0x78, 0x1F, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77,
      0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x54, 0x52, 0x2F, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6E, 0x2F, 0x64,
      0x6E, 0x61, 0x6D, 0x65, 0x74, 0x42, 0x72, 0x61, 0x6E, 0x61, 0x20, 0x44, 0x61, 0x63, 0x79, 0x20, 0x52, 0x6F, 0x73,
      0x65, 0x6D, 0x61, 0x72, 0x69, 0x61, 0x6B, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x4E, 0x61, 0x6D, 0x65, 0x78,
      0x1E, 0x44, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x20, 0x42, 0x72, 0x61, 0x6E, 0x61, 0x20, 0x44, 0x61,
      0x63, 0x79, 0x20, 0x52, 0x6F, 0x73, 0x65, 0x6D, 0x61, 0x72, 0x69, 0x61, 0x04, 0x81, 0xA2, 0x63, 0x61, 0x6C, 0x67,
      0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x06, 0xA1,
      0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65,
  };
  static const uint8_t mc_part2[] = {
      0x80, 0x10, 0x80, 0x00, 0x0B, 0x63, 0x72, 0x65, 0x74, 0xF5, 0x07, 0xA1, 0x62, 0x72, 0x6B, 0xF5, 0x00,
  };

  uint8_t c_buf[512], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, fido_private_key, sizeof(fido_private_key)), 0);
  assert_int_equal(write_file(CTAP_CERT_FILE, cert, 0, sizeof(cert), 1), 0);
  set_nfc_state(1);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, mc_part1, sizeof(mc_part1)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 0);

  assert_int_equal(build_capdu(&capdu, mc_part2, sizeof(mc_part2)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  // Match 7644370f: CTAP2 exposes ISO 7816 response chaining to the NFC
  // reader. The reader must issue 00 C0 GET RESPONSE to fetch later chunks.
  assert_int_equal(rapdu.sw & 0xFF00, 0x6100);
  assert_true(rapdu.len > 0);
  assert_int_equal(rapdu.data[0], 0x00);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);

  uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
  size_t total = rapdu.len;
  while (rapdu.sw != SW_NO_ERROR) {
    assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
    process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
    assert_true(rapdu.sw == SW_NO_ERROR || (rapdu.sw & 0xFF00) == 0x6100);
    total += rapdu.len;
  }
  assert_true(total > 1);

  ctap_poweroff();
  set_nfc_state(0);
}

static void test_fido_ctap1_register_nfc(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static const uint8_t register_apdu[] = {
      0x00, 0x01, 0x00, 0x00, 0x40, 0xE0, 0x78, 0xA7, 0xB2, 0xCA, 0xC4, 0x1D, 0xDC, 0x13, 0x14, 0x72, 0x90, 0x76,
      0xB6, 0xDF, 0xC1, 0xCD, 0x53, 0x45, 0x50, 0xFE, 0x0A, 0x78, 0xB8, 0x28, 0x5D, 0x8F, 0x06, 0xEC, 0x37, 0xC9,
      0xBD, 0xBF, 0xAB, 0xC3, 0x74, 0x32, 0x95, 0x8B, 0x06, 0x33, 0x60, 0xD3, 0xAD, 0x64, 0x61, 0xC9, 0xC4, 0x73,
      0x5A, 0xE7, 0xF8, 0xED, 0xD4, 0x65, 0x92, 0xA5, 0xE0, 0xF0, 0x14, 0x52, 0xB2, 0xE4, 0xB5, 0x00,
  };

  uint8_t c_buf[512], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  set_nfc_state(1);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, register_apdu, sizeof(register_apdu)), 0);
  process_apdu(&capdu, &rapdu);
  assert_true(rapdu.len > 0);
  assert_int_equal(rapdu.data[0], 0x05);

  uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
  size_t total = rapdu.len;
  unsigned int rounds = 0;
  while (rapdu.sw != SW_NO_ERROR) {
    assert_int_equal(rapdu.sw & 0xFF00, 0x6100);
    assert_true(++rounds < 64);
    assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
    process_apdu(&capdu, &rapdu);
    total += rapdu.len;
  }

  assert_true(total > 67);
}

static void test_large_blob_noncanonical_string_offset(void **state) {
  (void)state;

  // Map {2: h'000102...10', 3: 0, 4: 17}; the byte string uses a non-canonical
  // uint16 length header, so its payload starts at offset 5 rather than 3.
  static const uint8_t request[] = {0xA3, 0x02, 0x59, 0x00, 0x11, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                    0x03, 0x00, 0x04, 0x11};
  CborParser parser;
  CTAP_large_blobs large_blobs;

  assert_int_equal(parse_large_blobs(&parser, &large_blobs, request, sizeof(request)), 0);
  assert_int_equal(large_blobs.set_len, 17);
  assert_int_equal(large_blobs.set_offset, 5);
  for (size_t i = 0; i < large_blobs.set_len; ++i) {
    assert_int_equal(request[large_blobs.set_offset + i], i);
  }
}






static void test_fido_ctap1_register_rejects_missing_attestation_key(void **state) {
  (void)state;

  static const uint8_t private_key[PRI_KEY_SIZE] = {1};
  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static const uint8_t register_apdu[] = {
      0x00, 0x01, 0x00, 0x00, 0x40, 0xE0, 0x78, 0xA7, 0xB2, 0xCA, 0xC4, 0x1D, 0xDC, 0x13, 0x14, 0x72, 0x90, 0x76,
      0xB6, 0xDF, 0xC1, 0xCD, 0x53, 0x45, 0x50, 0xFE, 0x0A, 0x78, 0xB8, 0x28, 0x5D, 0x8F, 0x06, 0xEC, 0x37, 0xC9,
      0xBD, 0xBF, 0xAB, 0xC3, 0x74, 0x32, 0x95, 0x8B, 0x06, 0x33, 0x60, 0xD3, 0xAD, 0x64, 0x61, 0xC9, 0xC4, 0x73,
      0x5A, 0xE7, 0xF8, 0xED, 0xD4, 0x65, 0x92, 0xA5, 0xE0, 0xF0, 0x14, 0x52, 0xB2, 0xE4, 0xB5, 0x00,
  };

  uint8_t c_buf[512], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  set_nfc_state(1);
  assert_int_equal(remove_attr(CTAP_CERT_FILE, KEY_ATTR), 0);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, register_apdu, sizeof(register_apdu)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  assert_int_equal(rapdu.sw, SW_UNABLE_TO_PROCESS);
  assert_int_equal(rapdu.len, 0);
  assert_false(apdu_response_source_active());

  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, private_key, sizeof(private_key)), 0);
  set_nfc_state(0);
}

static void test_fido_reset_nfc_bypasses_user_presence(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static const uint8_t reset_apdu[] = {
      0x80, 0x10, 0x80, 0x00, 0x01, 0x07, 0x00,
  };

  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  testmode_set_initial_ticks(0);
  testmode_set_initial_ticks(device_get_tick());
  set_nfc_state(1);

  CTAP_sm2_attr saved_sm2, actual_sm2;
  const CTAP_sm2_attr custom_sm2 = {.curve_id = -65537, .algo_id = -65538};
  assert_int_equal(ctap_platform_sm2_config_read(&saved_sm2, sizeof(saved_sm2)), 0);
  uint8_t config_wire[CTAP_SM2_CONFIG_WIRE_SIZE];
  encode_sm2_config(config_wire, &custom_sm2);
  CAPDU config_capdu = {.data = config_wire, .lc = sizeof(config_wire)};
  assert_int_equal(ctap_write_sm2_config(&config_capdu, &rapdu), 0);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, reset_apdu, sizeof(reset_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 1);
  assert_int_equal(rapdu.data[0], 0x00);

  assert_int_equal(ctap_platform_sm2_config_read(&actual_sm2, sizeof(actual_sm2)), 0);
  assert_memory_equal(&actual_sm2, &custom_sm2, sizeof(actual_sm2));
  encode_sm2_config(config_wire, &saved_sm2);
  assert_int_equal(ctap_write_sm2_config(&config_capdu, &rapdu), 0);
  ctap_poweroff();
  set_nfc_state(0);
}

static void test_fido_cbor_after_reset_without_select(void **state) {
  (void)state;

  static const uint8_t get_info_apdu[] = {
      0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00,
  };

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(build_capdu(&capdu, get_info_apdu, sizeof(get_info_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_not_equal(rapdu.sw, SW_FILE_NOT_FOUND);
  assert_true(rapdu.sw == SW_NO_ERROR || (rapdu.sw & 0xFF00) == 0x6100);
  assert_true(rapdu.len > 0);
  assert_int_equal(rapdu.data[0], 0x00);
}

static void test_fido_chained_cbor_after_reset_without_select(void **state) {
  (void)state;

  static const uint8_t get_info_apdu[] = {
      0x90, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00,
  };

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(build_capdu(&capdu, get_info_apdu, sizeof(get_info_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_not_equal(rapdu.sw, SW_FILE_NOT_FOUND);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 0);
}

static void test_ctap_deselect_clears_get_next_assertion_state(void **state) {
  (void)state;

  uint8_t req[] = {0x08};
  uint8_t resp[16] = {0};
  size_t resp_len = sizeof(resp);

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  ctap_test_seed_get_next_assertion_state();
  ctap_deselect();

  assert_int_equal(ctap_process_cbor_with_src(req, sizeof(req), resp, &resp_len, CTAP_SRC_CCID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x30);
}

static void test_ctap_poweroff_keeps_credential_management_state(void **state) {
  (void)state;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  ctap_test_seed_credential_management_state();
  ctap_poweroff();

  assert_true(ctap_test_credential_management_state_active());
}

static void test_ctap_deselect_clears_credential_management_state(void **state) {
  (void)state;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  ctap_test_seed_credential_management_state();
  ctap_deselect();

  assert_false(ctap_test_credential_management_state_active());
}

static void write_ctap_dc_fixture(const CTAP_discoverable_credential *credentials, size_t credential_count,
                                  const CTAP_rp_meta *metadata, size_t metadata_count,
                                  const CTAP_dc_general_attr *attr) {
  assert_int_equal(write_file(DC_FILE, credentials, 0, (lfs_size_t)(credential_count * sizeof(*credentials)), 1), 0);
  assert_int_equal(write_file(DC_META_FILE, metadata, 0, (lfs_size_t)(metadata_count * sizeof(*metadata)), 1), 0);
  assert_int_equal(write_attr(DC_FILE, DC_GENERAL_ATTR, attr, sizeof(*attr)), 0);
}

static void init_dc_record(CTAP_discoverable_credential *dc, uint8_t rp_hash_byte, uint8_t nonce_byte) {
  memset(dc, 0, sizeof(*dc));
  memset(dc->credential_id.rp_id_hash, rp_hash_byte, SHA256_DIGEST_LENGTH);
  dc->credential_id.nonce[0] = nonce_byte;
  dc->credential_id.nonce[CREDENTIAL_NONCE_DC_POS] = 1;
  dc->credential_id.alg_type = COSE_ALG_ES256;
}

static void init_rp_meta(CTAP_rp_meta *meta, uint8_t rp_hash_byte, uint32_t live_count) {
  memset(meta, 0, sizeof(*meta));
  memset(meta->rp_id_hash, rp_hash_byte, SHA256_DIGEST_LENGTH);
  meta->live_count = live_count;
  meta->deleted = live_count == 0;
}

static void test_ctap_capacity_uses_credential_metadata(void **state) {
  (void)state;
  CTAP_discoverable_credential credentials[3];
  CTAP_rp_meta metadata[2];
  CTAP_dc_general_attr attr = {.numbers = 2, .pending_op = CTAP_DC_PENDING_NONE};
  init_dc_record(&credentials[0], 0x11, 1);
  init_dc_record(&credentials[1], 0x22, 2);
  init_dc_record(&credentials[2], 0x33, 3);
  credentials[1].deleted = true;
  init_rp_meta(&metadata[0], 0x11, 1);
  init_rp_meta(&metadata[1], 0x33, 1);
  write_ctap_dc_fixture(credentials, 3, metadata, 2, &attr);

  uint32_t with_tombstone = ctap_test_capacity_remaining_new_credentials();

  attr.numbers = 3;
  assert_int_equal(write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)), 0);
  uint32_t without_tombstone = ctap_test_capacity_remaining_new_credentials();
  assert_int_equal(with_tombstone, without_tombstone + 1);
}

static void test_ctap_capacity_cached_by_fs_generation(void **state) {
  (void)state;
  CTAP_discoverable_credential credentials[1];
  CTAP_rp_meta metadata[1];
  CTAP_dc_general_attr attr = {.numbers = 1, .pending_op = CTAP_DC_PENDING_NONE};
  init_dc_record(&credentials[0], 0x44, 1);
  init_rp_meta(&metadata[0], 0x44, 1);
  write_ctap_dc_fixture(credentials, 1, metadata, 1, &attr);

  const uint32_t first = ctap_test_capacity_remaining_new_credentials();
  const uint32_t computes0 = ctap_test_capacity_compute_count();

  // Consecutive read-only queries reuse the cache.
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0);

  // A write through any fs helper invalidates the cache.
  assert_int_equal(write_file("cap-probe", "x", 0, 1, 1), 0);
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 1);
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 1);

  // A failed write also invalidates: it may still have compacted.
  testmode_inject_error(TESTMODE_ERR_WRITE, 0, 9, (const uint8_t *)"cap-probe");
  assert_int_equal(write_file("cap-probe", "y", 0, 1, 1), LFS_ERR_IO);
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 2);

  // A remount advances the generation and invalidates the cache.
  assert_int_equal(fs_mount(test_apdu_fs_cfg), 0);
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 3);

  // A failed computation is not cached; the next query retries even without
  // an intervening write. Invalidate first so the failed call is a cache miss.
  assert_int_equal(write_file("cap-probe", "z", 0, 1, 0), 0);
  bd_read_fails = true;
  ctap_test_capacity_remaining_new_credentials();
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 4);
  bd_read_fails = false;
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 5);
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), first);
  assert_int_equal(ctap_test_capacity_compute_count(), computes0 + 5);

  assert_int_equal(remove_file("cap-probe"), 0);
}

static void test_ctap_capacity_dc_read_failure_not_cached(void **state) {
  (void)state;
  CTAP_discoverable_credential credentials[2];
  CTAP_rp_meta metadata[1];
  CTAP_dc_general_attr attr = {.numbers = 1, .pending_op = CTAP_DC_PENDING_NONE};
  init_dc_record(&credentials[0], 0x55, 1);
  init_dc_record(&credentials[1], 0x55, 2);
  credentials[1].deleted = true; // one tombstone: reusable = 1
  init_rp_meta(&metadata[0], 0x55, 1);
  write_ctap_dc_fixture(credentials, 2, metadata, 1, &attr);

  const uint32_t full = ctap_test_capacity_remaining_new_credentials();

  // Remount to drop littlefs caches and invalidate the capacity cache.
  assert_int_equal(fs_mount(test_apdu_fs_cfg), 0);
  // Fail only the first block-device read: the DC record count fails, but
  // the free-space scan afterwards still succeeds.
  bd_read_fail_count = 1;
  // The DC reads fail, so the result is the bare (zero) reusable count
  // without the free-space estimate, and it must not be cached.
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), 0);
  const uint32_t computes = ctap_test_capacity_compute_count();
  // The failed computation must not be cached: the next query recomputes
  // even without any intervening write.
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), full);
  assert_int_equal(ctap_test_capacity_compute_count(), computes + 1);
  // And the query after that hits the cache again.
  assert_int_equal(ctap_test_capacity_remaining_new_credentials(), full);
  assert_int_equal(ctap_test_capacity_compute_count(), computes + 1);
}

static void test_ctap_pending_recovery_rebuilds_metadata(void **state) {
  (void)state;
  for (uint8_t pending_op = CTAP_DC_PENDING_ADD; pending_op <= CTAP_DC_PENDING_DELETE; ++pending_op) {
    CTAP_discoverable_credential credentials[2];
    CTAP_rp_meta metadata[2];
    CTAP_dc_general_attr attr = {
        .numbers = pending_op == CTAP_DC_PENDING_ADD ? 1 : 2,
        .pending_index = 0,
        .pending_op = pending_op,
    };
    init_dc_record(&credentials[0], 0x41, 1);
    init_dc_record(&credentials[1], 0x42, 2);
    init_rp_meta(&metadata[0], 0x41, 1);
    init_rp_meta(&metadata[1], 0x42, 9);
    write_ctap_dc_fixture(credentials, 2, metadata, 2, &attr);

    assert_int_equal(ctap_consistency_check(), 0);
    assert_int_equal(read_file(DC_FILE, &credentials[0], 0, sizeof(credentials[0])), sizeof(credentials[0]));
    assert_true(credentials[0].deleted);
    assert_int_equal(read_file(DC_META_FILE, metadata, 0, sizeof(metadata)), sizeof(metadata));
    assert_true(metadata[0].deleted);
    assert_int_equal(metadata[0].live_count, 0);
    assert_false(metadata[1].deleted);
    assert_int_equal(metadata[1].live_count, 1);
    assert_int_equal(read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)), sizeof(attr));
    assert_int_equal(attr.pending_op, CTAP_DC_PENDING_NONE);
    assert_int_equal(attr.numbers, 1);
  }
}

static void test_ctap_delete_updates_only_target_rp(void **state) {
  (void)state;
  CTAP_discoverable_credential credentials[2];
  CTAP_rp_meta metadata[2], unchanged;
  CTAP_dc_general_attr attr = {.numbers = 2, .pending_op = CTAP_DC_PENDING_NONE};
  init_dc_record(&credentials[0], 0x51, 1);
  init_dc_record(&credentials[1], 0x52, 2);
  init_rp_meta(&metadata[0], 0x51, 1);
  init_rp_meta(&metadata[1], 0x52, 9);
  unchanged = metadata[1];
  write_ctap_dc_fixture(credentials, 2, metadata, 2, &attr);

  assert_int_equal(ctap_test_delete_discoverable_credential(&credentials[0].credential_id), 0);
  assert_int_equal(read_file(DC_FILE, credentials, 0, sizeof(credentials)), sizeof(credentials));
  assert_true(credentials[0].deleted);
  assert_false(credentials[1].deleted);
  assert_int_equal(read_file(DC_META_FILE, metadata, 0, sizeof(metadata)), sizeof(metadata));
  assert_true(metadata[0].deleted);
  assert_int_equal(metadata[0].live_count, 0);
  assert_memory_equal(&metadata[1], &unchanged, sizeof(unchanged));
  assert_int_equal(read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)), sizeof(attr));
  assert_int_equal(attr.numbers, 1);
  assert_int_equal(attr.pending_op, CTAP_DC_PENDING_NONE);
}

static void test_ctap_allow_list_matches_multiple_dc_ids_in_one_scan(void **state) {
  (void)state;
  CTAP_discoverable_credential credentials[2], selected;
  CTAP_rp_meta metadata;
  CTAP_dc_general_attr attr = {.numbers = 2, .pending_op = CTAP_DC_PENDING_NONE};
  credential_id allow_list[2];
  init_dc_record(&credentials[0], 0x61, 1);
  init_dc_record(&credentials[1], 0x61, 2);
  init_rp_meta(&metadata, 0x61, 2);
  write_ctap_dc_fixture(credentials, 2, &metadata, 1, &attr);
  allow_list[0] = credentials[0].credential_id;
  allow_list[0].nonce[0] = 0x7f;
  allow_list[1] = credentials[1].credential_id;

  assert_int_equal(
      ctap_test_find_allow_list_dc(allow_list, 2, credentials[0].credential_id.rp_id_hash, false, &selected), 0);
  assert_memory_equal(&selected.credential_id, &credentials[1].credential_id, sizeof(credential_id));
}

static void provision_test_attestation(void) {
  static const uint8_t private_key[PRI_KEY_SIZE] = {1};
  static const uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};

  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, private_key, sizeof(private_key)), 0);
  assert_int_equal(write_file(CTAP_CERT_FILE, cert, 0, sizeof(cert), 1), 0);
}

static void assert_ctap_install_resets_counter(void) {
  uint32_t counter = UINT32_MAX;

  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(read_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), sizeof(counter));
  assert_int_equal(counter, 0);
  provision_test_attestation();
  assert_int_equal(ctap_install(0), 0);
}

static void test_ctap_install_preserves_complete_attestation_state(void **state) {
  (void)state;
  const uint32_t expected_counter = 0x12345678;
  uint32_t actual_counter = 0;

  provision_test_attestation();
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &expected_counter, sizeof(expected_counter)), 0);
  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(read_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &actual_counter, sizeof(actual_counter)),
                   sizeof(actual_counter));
  assert_int_equal(actual_counter, expected_counter);
}

static void test_ctap_install_rebuilds_state_without_attestation_key(void **state) {
  (void)state;
  const uint32_t counter = 0x12345678;

  provision_test_attestation();
  assert_int_equal(remove_attr(CTAP_CERT_FILE, KEY_ATTR), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), 0);
  assert_ctap_install_resets_counter();
}

static void test_ctap_install_rebuilds_state_with_short_attestation_key(void **state) {
  (void)state;
  const uint8_t short_key[PRI_KEY_SIZE - 1] = {1};
  const uint32_t counter = 0x12345678;

  provision_test_attestation();
  assert_int_equal(write_attr(CTAP_CERT_FILE, KEY_ATTR, short_key, sizeof(short_key)), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), 0);
  assert_ctap_install_resets_counter();
}

static void test_ctap_install_rebuilds_state_with_empty_attestation_cert(void **state) {
  (void)state;
  const uint32_t counter = 0x12345678;

  provision_test_attestation();
  assert_int_equal(write_file(CTAP_CERT_FILE, NULL, 0, 0, 1), 0);
  assert_int_equal(write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, &counter, sizeof(counter)), 0);
  assert_ctap_install_resets_counter();
}

static void test_ctap_hid_get_info_stream_source(void **state) {
  (void)state;

  uint8_t req[] = {0x04};
  uint8_t scratch[64] = {0};
  uint8_t chunk[APPLET_SHARED_BUFFER_LENGTH] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;
  const uint8_t canonical_options[] = {
      0x04, 0xA9, 0x62, 'r',  'k', 0xF5, 0x68, 'a',  'l', 'w',  'a',  'y', 's', 'U', 'v', 0xF4, 0x68, 'c',  'r',
      'e',  'd',  'M',  'g',  'm', 't',  0xF5, 0x69, 'a', 'u',  't',  'h', 'n', 'r', 'C', 'f',  'g',  0xF5, 0x69,
      'c',  'l',  'i',  'e',  'n', 't',  'P',  'i',  'n', 0xF4, 0x6A, 'l', 'a', 'r', 'g', 'e',  'B',  'l',  'o',
      'b',  's',  0xF5, 0x6E, 'p', 'i',  'n',  'U',  'v', 'A',  'u',  't', 'h', 'T', 'o', 'k',  'e',  'n',  0xF5,
      0x6F, 's',  'e',  't',  'M', 'i',  'n',  'P',  'I', 'N',  'L',  'e', 'n', 'g', 't', 'h',  0xF5, 0x70, 'm',
      'a',  'k',  'e',  'C',  'r', 'e',  'd',  'U',  'v', 'N',  'o',  't', 'R', 'q', 'd', 0xF5,
  };

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len > 1);
  assert_true(source.total_len <= sizeof(chunk));
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(written, source.total_len);
  assert_int_equal(chunk[0], 0x00);
  assert_non_null(find_bytes(chunk, written, "FIDO_2_3", sizeof("FIDO_2_3") - 1));
  assert_non_null(find_bytes(chunk, written, "minPinLength", sizeof("minPinLength") - 1));
  assert_non_null(find_bytes(chunk, written, "thirdPartyPayment", sizeof("thirdPartyPayment") - 1));
  assert_non_null(find_bytes(chunk + 1, written - 1, canonical_options, sizeof(canonical_options)));
  test_cbor_view algorithms;
  assert_int_equal(test_cbor_map_lookup_int_key(chunk + 1, written - 1, GI_RESP_ALGORITHMS, &algorithms), 0);
  CborParser parser;
  CborValue array, entry, alg;
  size_t count;
  CTAP_sm2_attr sm2;
  assert_int_equal(ctap_platform_sm2_config_read(&sm2, sizeof(sm2)), 0);
  const int32_t expected[] = {COSE_ALG_ES256, COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65, sm2.algo_id};
  assert_int_equal(cbor_parser_init(algorithms.ptr, algorithms.len, 0, &parser, &array), CborNoError);
  assert_int_equal(cbor_value_get_array_length(&array, &count), CborNoError);
  assert_int_equal(count, CTAP_RESTRICT_ALGORITHMS ? 2 : 4);
  assert_int_equal(cbor_value_enter_container(&array, &entry), CborNoError);
  for (size_t i = 0; i < count; ++i) {
    int algorithm;
    assert_int_equal(cbor_value_map_find_value(&entry, "alg", &alg), CborNoError);
    assert_int_equal(cbor_value_get_int(&alg, &algorithm), CborNoError);
    assert_int_equal(algorithm, expected[i]);
    assert_int_equal(cbor_value_advance(&entry), CborNoError);
  }
  assert_true(cbor_value_at_end(&entry));
}

static void test_ctap_algorithm_policy(void **state) {
  (void)state;
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  CTAP_sm2_attr sm2;
  assert_int_equal(ctap_platform_sm2_config_read(&sm2, sizeof(sm2)), 0);
  const int32_t algorithms[] = {COSE_ALG_ES256, COSE_ALG_EDDSA, COSE_ALG_ML_DSA_65, sm2.algo_id};
  for (size_t i = 0; i < 4; ++i) {
    // Exercise unsupported-only lists and fallback to the RP's next choice.
    for (size_t fallback = 0; fallback < 2; ++fallback) {
      uint8_t req[256], zero32[32] = {0}, *p = req;
      *p++ = 0xA4;
      *p++ = 1;
      put_cbor_bytes(&p, zero32, sizeof(zero32));
      *p++ = 2;
      *p++ = 0xA1;
      put_cbor_text(&p, "id");
      put_cbor_text(&p, "pay.example");
      *p++ = 3;
      *p++ = 0xA1;
      put_cbor_text(&p, "id");
      put_cbor_bytes(&p, zero32, 1);
      *p++ = 4;
      *p++ = 0x81 + fallback;
      for (size_t j = 0; j <= fallback; ++j) {
        *p++ = 0xA2;
        put_cbor_text(&p, "alg");
        put_cbor_int(&p, j ? COSE_ALG_EDDSA : algorithms[i]);
        put_cbor_text(&p, "type");
        put_cbor_text(&p, "public-key");
      }
      CborParser parser;
      CTAP_make_credential mc = {0};
      bool restricted = CTAP_RESTRICT_ALGORITHMS && i >= 2;
      assert_int_equal(parse_make_credential(&parser, &mc, req, p - req),
                       restricted && !fallback ? CTAP2_ERR_UNSUPPORTED_ALGORITHM : 0);
      if (!restricted || fallback) assert_int_equal(mc.alg_type, restricted ? COSE_ALG_EDDSA : algorithms[i]);
    }

    // Construct genuine pre-existing credentials independent of registration policy.
    for (int mode = 0; mode < 3; ++mode) {
      bool resident = mode != 0;
      CTAP_discoverable_credential dc = {0};
      uint8_t pub[64], req[256], scratch[64], resp[8192];
      size_t written = 0;
      CTAPHID_TxSource source = {0};
      sha256_raw((const uint8_t *)"pay.example", 11, dc.credential_id.rp_id_hash);
      assert_int_equal(generate_key_handle(&dc.credential_id, pub, algorithms[i], resident,
                                           CRED_PROTECT_VERIFICATION_OPTIONAL, false), 0);
      assert_int_equal(write_file(DC_FILE, resident ? &dc : NULL, 0, resident ? sizeof(dc) : 0, 1), 0);
      size_t len = build_third_party_payment_get_assertion(req, &dc.credential_id);
      if (mode == 2) {
        // Discoverable assertion without an allowList must enforce the same policy.
        uint8_t zero32[32] = {0}, *p = req;
        *p++ = CTAP_GET_ASSERTION;
        *p++ = 0xA3;
        *p++ = 1;
        put_cbor_text(&p, "pay.example");
        *p++ = 2;
        put_cbor_bytes(&p, zero32, sizeof(zero32));
        *p++ = 5;
        *p++ = 0xA1;
        put_cbor_text(&p, "up");
        *p++ = 0xF4;
        len = p - req;
      }
      assert_int_equal(ctap_process_cbor_stream_with_src(req, len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
      assert_int_equal(read_tx_source_all(&source, resp, sizeof(resp), &written), 0);
      assert_int_equal(resp[0], CTAP_RESTRICT_ALGORITHMS && i >= 2 ? CTAP2_ERR_NO_CREDENTIALS : 0);
      if (source.close) source.close(source.ctx);
    }
  }
  assert_int_equal(write_file(DC_FILE, NULL, 0, 0, 1), 0);
}

static void test_ctap_kh_cache_lifecycle(void **state) {
  (void)state;
  static const uint8_t path[] = CTAP_CERT_FILE;
  credential_id first = {0}, second = {0};
  ecc_key_t key;
  uint8_t pub[64], stored_kh[KH_KEY_SIZE];
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  provision_test_attestation();
  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(generate_key_handle(&first, pub, COSE_ALG_ES256, 0, 0, false), 0);

  // A warm allow/exclude-list verification and new credential generation do
  // not read KH_KEY again, even across unrelated commits or applet switches.
  testmode_inject_error(TESTMODE_ERR_READ, 0, sizeof(path) - 1, path);
  assert_int_equal(write_file("kh-probe", NULL, 0, 0, 1), 0);
  ctap_deselect();
  assert_int_equal(verify_key_handle(&first, &key), 0);
  assert_int_equal(generate_key_handle(&second, pub, COSE_ALG_ES256, 0, 0, false), 0);
  assert_int_equal(verify_key_handle(&second, &key), 0);
  assert_true(testmode_err_triggered(CTAP_CERT_FILE, false));
  assert_int_equal(remove_file("kh-probe"), 0);

  // Reconnect/install invalidates RAM, but preserves existing credentials.
  assert_int_equal(ctap_install(0), 0);
  testmode_inject_error(TESTMODE_ERR_READ, 0, sizeof(path) - 1, path);
  assert_int_equal(verify_key_handle(&first, &key), LFS_ERR_IO);
  assert_int_equal(verify_key_handle(&first, &key), 0); // Retry after read failure.

  assert_int_equal(read_attr(CTAP_CERT_FILE, KH_KEY_ATTR, stored_kh, sizeof(stored_kh)), sizeof(stored_kh));
  assert_int_equal(write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, stored_kh, 1), 0);
  ctap_kh_cache_reset(); // Fault injection bypasses the sole production writer.
  assert_int_equal(verify_key_handle(&first, &key), LFS_ERR_CORRUPT);
  assert_int_equal(verify_key_handle(&first, &key), LFS_ERR_CORRUPT);
  assert_int_equal(write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, stored_kh, sizeof(stored_kh)), 0);
  assert_int_equal(verify_key_handle(&first, &key), 0);

  // Factory reset rotates KH_KEY; neither old credential may use a stale cache.
  assert_int_equal(ctap_install(1), 0);
  assert_int_equal(verify_key_handle(&first, &key), 1);
  assert_int_equal(verify_key_handle(&second, &key), 1);
  assert_int_equal(generate_key_handle(&second, pub, COSE_ALG_ES256, 0, 0, false), 0);
  assert_int_equal(verify_key_handle(&second, &key), 0);
}

static void test_ctap_pin_state_read_errors_are_propagated(void **state) {
  (void)state;

  static const uint8_t cert_path[] = CTAP_CERT_FILE;
  static const uint8_t dc_path[] = DC_FILE;
  uint8_t req[] = {CTAP_GET_INFO};
  uint8_t scratch[64] = {0};
  CTAPHID_TxSource source = {0};
  CTAP_dc_general_attr attr;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  testmode_inject_error(TESTMODE_ERR_WRITE, 0, sizeof(dc_path) - 1, dc_path);
  assert_int_equal(read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)), sizeof(attr));
  assert_int_equal(write_file(DC_FILE, NULL, 0, 0, 0), LFS_ERR_IO);

  testmode_inject_error(TESTMODE_ERR_READ, 0, sizeof(cert_path) - 1, cert_path);
  assert_int_equal(has_pin(), LFS_ERR_IO);

  testmode_inject_error(TESTMODE_ERR_READ, 0, sizeof(cert_path) - 1, cert_path);
  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   -1);
  assert_null(source.read);
}


static void test_ctaphid_msg_case3_and_case4_send_complete_response(void **state) {
  (void)state;

  static const uint8_t case3_get_info[] = {
      0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04,
  };
  static const uint8_t case4_get_info[] = {
      0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00,
  };
  static const uint8_t case4_limited_get_info[] = {
      0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x01,
  };
  static const uint8_t get_response[] = {
      0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  uint8_t case3_response[1024] = {0};
  uint8_t case4_response[1024] = {0};
  uint8_t limited_response[8] = {0};
  uint8_t continuation_response[1024] = {0};
  size_t case3_len = 0, case4_len = 0, limited_len = 0, continuation_len = 0;

  init_apdu_buffer();
  device_init();
  set_nfc_state(0);
  assert_int_equal(applets_install(), 0);

  assert_int_equal(
      capture_ctaphid_msg(case3_get_info, sizeof(case3_get_info), case3_response, sizeof(case3_response), &case3_len),
      0);
  assert_true(case3_len > APDU_BUFFER_SIZE + 2);
  assert_int_equal(case3_response[0], 0x00);
  assert_int_equal(case3_response[case3_len - 2], HI(SW_NO_ERROR));
  assert_int_equal(case3_response[case3_len - 1], LO(SW_NO_ERROR));

  device_init();
  assert_int_equal(applets_install(), 0);
  assert_int_equal(
      capture_ctaphid_msg(case4_get_info, sizeof(case4_get_info), case4_response, sizeof(case4_response), &case4_len),
      0);
  assert_int_equal(case4_len, case3_len);
  assert_memory_equal(case4_response, case3_response, case3_len);

  device_init();
  assert_int_equal(applets_install(), 0);
  assert_int_equal(capture_ctaphid_msg(case4_limited_get_info, sizeof(case4_limited_get_info), limited_response,
                                       sizeof(limited_response), &limited_len),
                   0);
  assert_int_equal(limited_len, 3);
  assert_int_equal(limited_response[0], 0x00);
  assert_int_equal(limited_response[1], 0x61);
  assert_true(apdu_response_source_active());

  assert_int_equal(capture_ctaphid_msg(get_response, sizeof(get_response), continuation_response,
                                       sizeof(continuation_response), &continuation_len),
                   0);
  assert_int_equal(continuation_len, case3_len - 1);
  assert_memory_equal(continuation_response, case3_response + 1, continuation_len);
  assert_false(apdu_response_source_active());
}




static void test_ctap_hid_make_credential_accepts_p9_pub_key_param_order(void **state) {
  (void)state;

  static uint8_t req[] = {
      0x01, 0xA5, 0x01, 0x58, 0x20, 0xA5, 0x14, 0x7D, 0x80, 0x4F, 0xFC, 0x8B, 0x7E, 0xAD, 0x9F, 0x64, 0x7A, 0x9C, 0x8B,
      0x30, 0x29, 0xCB, 0x37, 0xAE, 0x35, 0xB7, 0x2A, 0xB1, 0xD5, 0xEA, 0x58, 0x1A, 0xB7, 0x75, 0x47, 0xD6, 0x1F, 0x02,
      0xA2, 0x62, 0x69, 0x64, 0x6F, 0x68, 0x61, 0x70, 0x6C, 0x65, 0x73, 0x73, 0x67, 0x75, 0x69, 0x64, 0x65, 0x2E, 0x72,
      0x65, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x78, 0x29, 0x54, 0x68, 0x65, 0x20, 0x45, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
      0x20, 0x43, 0x6F, 0x72, 0x70, 0x6F, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x66,
      0x61, 0x6B, 0x65, 0x20, 0x64, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x21, 0x03, 0xA3, 0x62, 0x69, 0x64, 0x58, 0x20, 0x9B,
      0xD3, 0xD8, 0xBA, 0x12, 0xC6, 0xA3, 0x05, 0xBB, 0x96, 0xB2, 0x2F, 0x8A, 0xE5, 0xEE, 0xEF, 0x34, 0xA3, 0x19, 0x12,
      0x29, 0x16, 0xD0, 0x6A, 0xBA, 0x49, 0x86, 0x08, 0x16, 0xBF, 0x9B, 0xC3, 0x64, 0x6E, 0x61, 0x6D, 0x65, 0x78, 0x1D,
      0x72, 0x6F, 0x73, 0x61, 0x6C, 0x69, 0x61, 0x6A, 0x61, 0x72, 0x72, 0x65, 0x74, 0x40, 0x6E, 0x6F, 0x69, 0x73, 0x65,
      0x6C, 0x65, 0x73, 0x73, 0x66, 0x69, 0x67, 0x2E, 0x63, 0x76, 0x6B, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x4E,
      0x61, 0x6D, 0x65, 0x6E, 0x52, 0x6F, 0x73, 0x61, 0x6C, 0x69, 0x61, 0x20, 0x4A, 0x61, 0x72, 0x72, 0x65, 0x74, 0x04,
      0x82, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
      0x2D, 0x6B, 0x65, 0x79, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x27, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62,
      0x6C, 0x69, 0x63, 0x2D, 0x6B, 0x65, 0x79, 0x07, 0xA0,
  };
  uint8_t scratch[64] = {0};
  uint8_t resp[8] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len > 0);
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, resp, MIN(source.total_len, sizeof(resp)), &written), 0);
  assert_true(written > 0);
  assert_int_not_equal(resp[0], 0x11);
  if (source.close) source.close(source.ctx);
}

static void test_ctap_make_credential_rejects_enterprise_attestation(void **state) {
  (void)state;

  static const struct {
    uint8_t value;
    uint8_t status;
  } cases[] = {
      {0x01, CTAP1_ERR_INVALID_PARAMETER},
      {0x02, CTAP1_ERR_INVALID_PARAMETER},
      {0x03, CTAP1_ERR_INVALID_PARAMETER},
      {0x20, CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
      {0xF5, CTAP2_ERR_CBOR_UNEXPECTED_TYPE},
  };
  uint8_t req[256];
  uint8_t resp[8];

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    size_t req_len = build_third_party_payment_make_credential(req, false, true);
    req[1] = 0xA7;
    req[req_len++] = MC_REQ_ENTERPRISE_ATTESTATION;
    req[req_len++] = cases[i].value;
    size_t resp_len = sizeof(resp);

    assert_int_equal(ctap_process_cbor_with_src(req, req_len, resp, &resp_len, CTAP_SRC_HID), 0);
    assert_int_equal(resp_len, 1);
    assert_int_equal(resp[0], cases[i].status);
  }
}

static void test_ctap_hid_make_credential_hmac_secret_mc_requires_hmac_secret(void **state) {
  (void)state;

  uint8_t req[384] = {0};
  uint8_t resp[16] = {0};
  size_t resp_len = sizeof(resp);
  size_t req_len = build_hmac_secret_mc_make_credential(req, false, COSE_ALG_ES256, NULL, NULL, NULL);
  assert_true(req_len <= sizeof(req));

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(ctap_process_cbor_with_src(req, req_len, resp, &resp_len, CTAP_SRC_HID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], CTAP2_ERR_MISSING_PARAMETER);
}

static void test_ctap_hid_make_credential_hmac_secret_mc_output_key_is_separate(void **state) {
  (void)state;

  uint8_t req[384] = {0};
  uint8_t scratch[64] = {0};
  uint8_t resp[APPLET_SHARED_BUFFER_LENGTH] = {0};
  uint8_t fido_private_key[32] = {1};
  uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  uint8_t salt[64] = {0};
  uint8_t salt_auth[16] = {0};
  uint8_t shared_secret[64] = {0};
  uint8_t key_agreement[64] = {0};
  uint8_t auth_data_buf[sizeof(CTAP_auth_data)] = {0};
  size_t written = 0;
  size_t req_len;
  CTAPHID_TxSource source = {0};
  uint8_t mac[32] = {0};
  uint8_t authenticator_pub[64] = {0};
  ecc_key_t platform_key = {0};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(write_attr("ctap_cert", 0, fido_private_key, sizeof(fido_private_key)), 0);
  assert_int_equal(write_file("ctap_cert", cert, 0, sizeof(cert), 1), 0);

  memset(platform_key.pri, 1, 32);
  assert_int_equal(ecc_complete_key(SECP256R1, &platform_key), 0);
  memcpy(key_agreement, platform_key.pub, sizeof(key_agreement));

  cp_get_public_key(authenticator_pub);
  assert_int_equal(ecdh(SECP256R1, platform_key.pri, authenticator_pub, shared_secret), 0);
  sha256_raw(shared_secret, 32, shared_secret);
  hmac_sha256(shared_secret, 32, salt, sizeof(salt), mac);
  memcpy(salt_auth, mac, sizeof(salt_auth));

  req_len = build_hmac_secret_mc_make_credential(req, true, COSE_ALG_ES256, key_agreement, salt, salt_auth);
  assert_true(req_len <= sizeof(req));

  assert_int_equal(ctap_process_cbor_stream_with_src(req, req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_true(source.total_len > APDU_BUFFER_SIZE);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, resp, sizeof(resp), &written), 0);
  assert_int_equal(written, source.total_len);
  assert_make_credential_auth_data_has_hmac_secret_mc(resp, written, auth_data_buf, sizeof(auth_data_buf));

  if (source.close) source.close(source.ctx);
}

static void test_ctap_hid_make_credential_mldsa_hmac_secret_mc_output_key_is_separate(void **state) {
  (void)state;

  static uint8_t resp[4096];
  static uint8_t auth_data_buf[sizeof(CTAP_auth_data) + MLDSA_PK_BYTES];
  uint8_t req[384] = {0};
  uint8_t scratch[64] = {0};
  uint8_t fido_private_key[32] = {1};
  uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  uint8_t salt[64] = {0};
  uint8_t salt_auth[16] = {0};
  uint8_t shared_secret[64] = {0};
  uint8_t key_agreement[64] = {0};
  size_t written = 0;
  size_t req_len;
  CTAPHID_TxSource source = {0};
  uint8_t mac[32] = {0};
  uint8_t authenticator_pub[64] = {0};
  ecc_key_t platform_key = {0};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  memset(resp, 0, sizeof(resp));
  memset(auth_data_buf, 0, sizeof(auth_data_buf));

  assert_int_equal(write_attr("ctap_cert", 0, fido_private_key, sizeof(fido_private_key)), 0);
  assert_int_equal(write_file("ctap_cert", cert, 0, sizeof(cert), 1), 0);

  memset(platform_key.pri, 1, 32);
  assert_int_equal(ecc_complete_key(SECP256R1, &platform_key), 0);
  memcpy(key_agreement, platform_key.pub, sizeof(key_agreement));

  cp_get_public_key(authenticator_pub);
  assert_int_equal(ecdh(SECP256R1, platform_key.pri, authenticator_pub, shared_secret), 0);
  sha256_raw(shared_secret, 32, shared_secret);
  hmac_sha256(shared_secret, 32, salt, sizeof(salt), mac);
  memcpy(salt_auth, mac, sizeof(salt_auth));

  req_len = build_hmac_secret_mc_make_credential(req, true, COSE_ALG_ML_DSA_65, key_agreement, salt, salt_auth);
  assert_true(req_len <= sizeof(req));

  assert_int_equal(ctap_process_cbor_stream_with_src(req, req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_true(source.total_len > 0);
  assert_true(source.total_len <= sizeof(resp));
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, resp, sizeof(resp), &written), 0);
#if CTAP_RESTRICT_ALGORITHMS
  assert_int_equal(written, 1);
  assert_int_equal(resp[0], CTAP2_ERR_UNSUPPORTED_ALGORITHM);
#else
  assert_make_credential_auth_data_has_hmac_secret_mc(resp, written, auth_data_buf, sizeof(auth_data_buf));
#endif

  if (source.close) source.close(source.ctx);
}

static void test_ctap_hid_third_party_payment_round_trip(void **state) {
  (void)state;

  uint8_t mc_req[256] = {0};
  uint8_t ga_req[256] = {0};
  uint8_t scratch[64] = {0};
  uint8_t mc_resp[APPLET_SHARED_BUFFER_LENGTH] = {0};
  uint8_t ga_resp[APPLET_SHARED_BUFFER_LENGTH] = {0};
  uint8_t auth_data_buf[sizeof(CTAP_auth_data)] = {0};
  uint8_t fido_private_key[32] = {1};
  uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  size_t mc_written = 0;
  size_t ga_written = 0;
  size_t mc_req_len;
  size_t ga_req_len;
  CTAPHID_TxSource source = {0};
  test_cbor_view extension_map, third_party_payment_value;
  bool third_party_payment;
  credential_id cid;
  size_t auth_data_len;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(write_attr("ctap_cert", 0, fido_private_key, sizeof(fido_private_key)), 0);
  assert_int_equal(write_file("ctap_cert", cert, 0, sizeof(cert), 1), 0);

  mc_req_len = build_third_party_payment_make_credential(mc_req, false, true);
  assert_int_equal(
      ctap_process_cbor_stream_with_src(mc_req, mc_req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, mc_resp, sizeof(mc_resp), &mc_written), 0);
  assert_int_equal(mc_resp[0], 0x00);
  assert_int_equal(test_cbor_get_auth_data(mc_resp, mc_written, MC_RESP_AUTH_DATA, auth_data_buf, sizeof(auth_data_buf),
                                           &auth_data_len),
                   0);
  assert_true((auth_data_buf[32] & 0x80) == 0);
  assert_true((auth_data_buf[32] & 0x40) != 0);
  memcpy(&cid, auth_data_buf + 37 + AAGUID_SIZE + sizeof(uint16_t), sizeof(cid));
  assert_false(cid.nonce[CREDENTIAL_NONCE_DC_POS]);
  assert_true(credential_third_party_payment(&cid));
  if (source.close) source.close(source.ctx);

  memset(&source, 0, sizeof(source));
  ga_req_len = build_third_party_payment_get_assertion(ga_req, &cid);
  assert_int_equal(
      ctap_process_cbor_stream_with_src(ga_req, ga_req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, ga_resp, sizeof(ga_resp), &ga_written), 0);
  assert_int_equal(test_cbor_get_auth_data_extensions(ga_resp, ga_written, GA_RESP_AUTH_DATA, auth_data_buf,
                                                      sizeof(auth_data_buf), &extension_map),
                   0);
  assert_int_equal(test_cbor_map_lookup_text_key(extension_map, "thirdPartyPayment", &third_party_payment_value), 0);
  assert_int_equal(test_cbor_get_bool(third_party_payment_value, &third_party_payment), 0);
  assert_true(third_party_payment);
  if (source.close) source.close(source.ctx);
}

static void test_ctap_hid_credential_management_returns_third_party_payment(void **state) {
  (void)state;

  uint8_t mc_req[256] = {0};
  uint8_t cm_req[128] = {0};
  uint8_t scratch[64] = {0};
  uint8_t mc_resp[APPLET_SHARED_BUFFER_LENGTH] = {0};
  uint8_t cm_resp[APPLET_SHARED_BUFFER_LENGTH] = {0};
  uint8_t cm_pin_msg[64] = {0};
  uint8_t pin_auth[PIN_AUTH_SIZE_P1] = {0};
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH] = {0};
  uint8_t fido_private_key[32] = {1};
  uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  size_t mc_written = 0;
  size_t cm_written = 0;
  size_t mc_req_len;
  size_t cm_req_len;
  size_t cm_pin_msg_len;
  CTAPHID_TxSource source = {0};
  test_cbor_view value;
  bool third_party_payment;
  int64_t algorithm;
  uint64_t total_credentials;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(write_attr("ctap_cert", 0, fido_private_key, sizeof(fido_private_key)), 0);
  assert_int_equal(write_file("ctap_cert", cert, 0, sizeof(cert), 1), 0);

  mc_req_len = build_third_party_payment_make_credential(mc_req, true, true);
  assert_int_equal(
      ctap_process_cbor_stream_with_src(mc_req, mc_req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, mc_resp, sizeof(mc_resp), &mc_written), 0);
  assert_int_equal(mc_resp[0], 0x00);
  if (source.close) source.close(source.ctx);

  sha256_raw((const uint8_t *)"pay.example", sizeof("pay.example") - 1, rp_id_hash);
  cp_reset_pin_uv_auth_token();
  cp_begin_using_uv_auth_token(false);
  cp_set_permission(CP_PERMISSION_CM);
  cm_pin_msg_len = build_enumerate_credentials_pin_message(cm_pin_msg, rp_id_hash, true);
  cp_test_authenticate_pin_token(cm_pin_msg, cm_pin_msg_len, pin_auth, 1);
  cm_req_len = build_third_party_payment_credential_management(cm_req, rp_id_hash, pin_auth, true);

  memset(&source, 0, sizeof(source));
  assert_int_equal(
      ctap_process_cbor_stream_with_src(cm_req, cm_req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, cm_resp, sizeof(cm_resp), &cm_written), 0);
  assert_int_equal(cm_resp[0], 0x00);
  assert_int_equal(test_cbor_is_canonical(cm_resp + 1, cm_written - 1), 0);
  assert_int_equal(test_cbor_map_lookup_int_key(cm_resp + 1, cm_written - 1, CM_RESP_TOTAL_CREDENTIALS, &value), 0);
  assert_int_equal(test_cbor_get_uint(value, &total_credentials), 0);
  assert_int_equal(total_credentials, 1);
  assert_int_equal(test_cbor_map_lookup_int_key(cm_resp + 1, cm_written - 1, CM_RESP_PUBLIC_KEY, &value), -1);
  assert_int_equal(test_cbor_map_lookup_int_key(cm_resp + 1, cm_written - 1, CM_RESP_VENDOR_ALGORITHM, &value), 0);
  assert_int_equal(test_cbor_get_int(value, &algorithm), 0);
  assert_int_equal(algorithm, COSE_ALG_ES256);
  assert_int_equal(test_cbor_map_lookup_int_key(cm_resp + 1, cm_written - 1, CM_RESP_THIRD_PARTY_PAYMENT, &value), 0);
  assert_int_equal(test_cbor_get_bool(value, &third_party_payment), 0);
  assert_true(third_party_payment);
  if (source.close) source.close(source.ctx);
}

static void test_ctap_apdu_credential_management_streams_mldsa_public_key(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };
  static uint8_t response[4096];
  static uint8_t expected_public_key[MLDSA_PK_BYTES];
  uint8_t cm_req[128] = {0};
  uint8_t cm_apdu[5 + sizeof(cm_req)] = {0};
  uint8_t cm_pin_msg[64] = {0};
  uint8_t pin_auth[PIN_AUTH_SIZE_P1] = {0};
  uint8_t seed[PRI_KEY_SIZE] = {0};
  uint8_t c_buf[APDU_COMMAND_BUFFER_SIZE] = {0};
  uint8_t r_buf[APDU_COMMAND_BUFFER_SIZE] = {0};
  CTAP_discoverable_credential dc = {0};
  CTAP_discoverable_credential credentials[2] = {0};
  CTAP_rp_meta meta = {0};
  CTAP_dc_general_attr attr = {.numbers = 2, .pending_op = CTAP_DC_PENDING_NONE};
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  test_cbor_view algorithm_value, public_key, total_value;
  int64_t algorithm;
  uint64_t total_credentials;
  size_t cm_pin_msg_len;
  size_t cm_req_len;
  size_t response_len = 0;

  init_apdu_buffer();
  device_init();
  assert_int_equal(ctap_install(1), 0);

  sha256_raw((const uint8_t *)"demo.yubico.com", sizeof("demo.yubico.com") - 1, dc.credential_id.rp_id_hash);
  assert_int_equal(generate_key_handle(&dc.credential_id, seed, COSE_ALG_ML_DSA_65, 1,
                                       CRED_PROTECT_VERIFICATION_OPTIONAL, false),
                   0);
  assert_int_equal(ml_dsa_65_keygen(expected_public_key, NULL, NULL, seed), 0);
  dc.user.id[0] = 1;
  dc.user.id_size = 1;
  memcpy(&credentials[0], &dc, sizeof(dc));
  memcpy(&credentials[1], &dc, sizeof(dc));
  assert_int_equal(generate_key_handle(&credentials[1].credential_id, seed, COSE_ALG_ML_DSA_65, 1,
                                       CRED_PROTECT_VERIFICATION_OPTIONAL, false),
                   0);
  credentials[1].user.id[0] = 2;
  memcpy(meta.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH);
  memcpy(meta.rp_id, "demo.yubico.com", sizeof("demo.yubico.com") - 1);
  meta.rp_id_len = sizeof("demo.yubico.com") - 1;
  meta.live_count = 2;
  write_ctap_dc_fixture(credentials, 2, &meta, 1, &attr);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  cp_reset_pin_uv_auth_token();
  cp_begin_using_uv_auth_token(false);
  cp_set_permission(CP_PERMISSION_CM);
  cm_pin_msg_len = build_enumerate_credentials_pin_message(cm_pin_msg, dc.credential_id.rp_id_hash, true);
  cp_test_authenticate_pin_token(cm_pin_msg, cm_pin_msg_len, pin_auth, 1);
  cm_req_len = build_third_party_payment_credential_management(cm_req, dc.credential_id.rp_id_hash, pin_auth, true);
  assert_true(cm_req_len <= UINT8_MAX);
  cm_apdu[0] = 0x80;
  cm_apdu[1] = CTAP_INS_MSG;
  cm_apdu[4] = (uint8_t)cm_req_len;
  memcpy(cm_apdu + 5, cm_req, cm_req_len);

  assert_int_equal(build_capdu(&capdu, cm_apdu, 5 + cm_req_len), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_true(rapdu.len > 1);
  assert_int_equal(rapdu.data[0], CTAP1_ERR_SUCCESS);
  assert_int_equal(test_cbor_is_canonical(rapdu.data + 1, rapdu.len - 1), 0);
  assert_int_equal(test_cbor_map_lookup_int_key(rapdu.data + 1, rapdu.len - 1, CM_RESP_PUBLIC_KEY, &public_key), -1);
  assert_int_equal(
      test_cbor_map_lookup_int_key(rapdu.data + 1, rapdu.len - 1, CM_RESP_VENDOR_ALGORITHM, &algorithm_value), 0);
  assert_int_equal(test_cbor_get_int(algorithm_value, &algorithm), 0);
  assert_int_equal(algorithm, COSE_ALG_ML_DSA_65);
  assert_int_equal(test_cbor_map_lookup_int_key(rapdu.data + 1, rapdu.len - 1, CM_RESP_TOTAL_CREDENTIALS, &total_value),
                   0);
  assert_int_equal(test_cbor_get_uint(total_value, &total_credentials), 0);
  assert_int_equal(total_credentials, 2);

  cm_req_len = build_credential_management_get_next(cm_req);
  cm_apdu[4] = (uint8_t)cm_req_len;
  memcpy(cm_apdu + 5, cm_req, cm_req_len);
  assert_int_equal(build_capdu(&capdu, cm_apdu, 5 + cm_req_len), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_true(rapdu.len > 1);
  assert_int_equal(rapdu.data[0], CTAP1_ERR_SUCCESS);
  assert_int_equal(test_cbor_is_canonical(rapdu.data + 1, rapdu.len - 1), 0);
  assert_int_equal(test_cbor_map_lookup_int_key(rapdu.data + 1, rapdu.len - 1, CM_RESP_PUBLIC_KEY, &public_key), -1);
  assert_int_equal(
      test_cbor_map_lookup_int_key(rapdu.data + 1, rapdu.len - 1, CM_RESP_VENDOR_ALGORITHM, &algorithm_value), 0);
  assert_int_equal(test_cbor_get_int(algorithm_value, &algorithm), 0);
  assert_int_equal(algorithm, COSE_ALG_ML_DSA_65);
  assert_int_equal(test_cbor_map_lookup_int_key(rapdu.data + 1, rapdu.len - 1, CM_RESP_TOTAL_CREDENTIALS, &total_value),
                   -1);

  cm_pin_msg_len = build_enumerate_credentials_pin_message(cm_pin_msg, dc.credential_id.rp_id_hash, false);
  cp_test_authenticate_pin_token(cm_pin_msg, cm_pin_msg_len, pin_auth, 1);
  cm_req_len = build_third_party_payment_credential_management(cm_req, dc.credential_id.rp_id_hash, pin_auth, false);
  cm_apdu[4] = (uint8_t)cm_req_len;
  memcpy(cm_apdu + 5, cm_req, cm_req_len);
  assert_int_equal(build_capdu(&capdu, cm_apdu, 5 + cm_req_len), 0);
  process_apdu(&capdu, &rapdu);
  assert_true((rapdu.sw & 0xFF00) == 0x6100);
  assert_true(rapdu.len > 1);
  assert_int_equal(rapdu.data[0], CTAP1_ERR_SUCCESS);
  memcpy(response, rapdu.data, rapdu.len);
  response_len = rapdu.len;

  const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
  while (rapdu.sw != SW_NO_ERROR) {
    assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
    process_apdu(&capdu, &rapdu);
    assert_true(rapdu.sw == SW_NO_ERROR || (rapdu.sw & 0xFF00) == 0x6100);
    assert_true(response_len + rapdu.len <= sizeof(response));
    memcpy(response + response_len, rapdu.data, rapdu.len);
    response_len += rapdu.len;
  }

  assert_true(response_len > MLDSA_PK_BYTES);
  assert_int_equal(test_cbor_is_canonical(response + 1, response_len - 1), 0);
  assert_int_equal(test_cbor_map_lookup_int_key(response + 1, response_len - 1, CM_RESP_PUBLIC_KEY, &public_key), 0);
  test_cbor_view public_bytes;
  const uint8_t *public_data;
  size_t public_len;
  assert_int_equal(test_cbor_map_lookup_int_key(public_key.ptr, public_key.len, COSE_KEY_LABEL_AKP_PUB, &public_bytes),
                   0);
  assert_int_equal(test_cbor_get_byte_string(public_bytes, &public_data, &public_len), 0);
  assert_int_equal(public_len, sizeof(expected_public_key));
  assert_memory_equal(public_data, expected_public_key, public_len);
  assert_int_equal(
      test_cbor_map_lookup_int_key(response + 1, response_len - 1, CM_RESP_TOTAL_CREDENTIALS, &total_value), 0);
  assert_int_equal(test_cbor_get_uint(total_value, &total_credentials), 0);
  assert_int_equal(total_credentials, 2);

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_COMMAND_NOT_ALLOWED);
  assert_int_equal(rapdu.len, 0);
}

static void test_pin_uv_auth_clear_permissions_except_lbw(void **state) {
  (void)state;

  cp_reset_pin_uv_auth_token();
  cp_begin_using_uv_auth_token(false);
  cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA | CP_PERMISSION_LBW);

  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  assert_false(cp_has_permission(CP_PERMISSION_MC));
  assert_false(cp_has_permission(CP_PERMISSION_GA));
  assert_true(cp_has_permission(CP_PERMISSION_LBW));
}

static void test_ctap_hid_large_cbor_response_keeps_payload(void **state) {
  (void)state;

  static uint8_t req[] = {
      CTAP_LARGE_BLOBS, 0xA2, 0x01, 0x19, HI(MAX_FRAGMENT_LENGTH), LO(MAX_FRAGMENT_LENGTH), 0x03, 0x00,
  };
  uint8_t blob[MAX_FRAGMENT_LENGTH];
  uint8_t scratch[64] = {0};
  uint8_t chunk[16] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  for (size_t i = 0; i < sizeof(blob); ++i) {
    blob[i] = (uint8_t)i;
  }
  assert_int_equal(write_file(LB_FILE, blob, 0, sizeof(blob), 1), 0);

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_int_equal(source.total_len, 1 + 1 + 1 + 3 + sizeof(blob));
  assert_non_null(source.read);
  assert_int_equal(source.read(source.ctx, chunk, sizeof(chunk), &written), 0);
  assert_int_equal(written, sizeof(chunk));
  assert_int_equal(chunk[0], 0x00);
  assert_int_equal(chunk[1], 0xA1);
  assert_int_equal(chunk[2], 0x01);
  assert_int_equal(chunk[3], 0x59);
  assert_int_equal(chunk[4], HI(MAX_FRAGMENT_LENGTH));
  assert_int_equal(chunk[5], LO(MAX_FRAGMENT_LENGTH));
  assert_int_equal(chunk[6], 0x00);
  assert_int_equal(chunk[7], 0x01);
  if (source.close) source.close(source.ctx);
}

static void test_ctap_install_preserves_sm2_during_state_rebuild(void **state) {
  (void)state;
  CTAP_sm2_attr saved, actual;
  const CTAP_sm2_attr custom = {.curve_id = INT32_MIN, .algo_id = INT32_MAX};
  const CTAP_sm2_attr invalid = {.curve_id = 1, .algo_id = -54};
  assert_int_equal(ctap_platform_sm2_config_read(&saved, sizeof(saved)), 0);
  assert_int_equal(ctap_platform_sm2_config_write(&custom, sizeof(custom)), 0);
  assert_int_equal(write_file(LB_FILE, NULL, 0, 0, 1), 0);
  assert_int_equal(remove_attr(CTAP_CERT_FILE, KEY_ATTR), 0);
  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(ctap_platform_sm2_config_read(&actual, sizeof(actual)), 0);
  assert_memory_equal(&actual, &custom, sizeof(actual));

  assert_int_equal(ctap_platform_sm2_config_write(&invalid, sizeof(invalid)), 0);
  assert_int_equal(ctap_install(0), 0);
  assert_int_equal(ctap_platform_sm2_config_read(&actual, sizeof(actual)), 0);
  assert_int_equal(actual.curve_id, 9);
  assert_int_equal(actual.algo_id, -54);
  assert_int_equal(ctap_platform_sm2_config_write(&saved, sizeof(saved)), 0);
  provision_test_attestation();
  assert_int_equal(ctap_install(0), 0);
}

static size_t read_cm_response(bool hid, uint8_t *req, size_t req_len, uint8_t *out, size_t capacity) {
  size_t total = 0;
  if (hid) {
    uint8_t scratch[128];
    CTAPHID_TxSource source = {0};
    assert_int_equal(ctap_process_cbor_stream_with_src(req, req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                     1);
    assert_true(source.total_len <= capacity);
    while (total < source.total_len) {
      size_t written = 0;
      assert_int_equal(source.read(source.ctx, out + total, MIN(57, source.total_len - total), &written), 0);
      assert_true(written > 0);
      total += written;
    }
    source.close(source.ctx);
  } else {
    uint8_t c_buf[APDU_COMMAND_BUFFER_SIZE], r_buf[APDU_COMMAND_BUFFER_SIZE];
    CAPDU capdu = {.cla = 0x80, .ins = CTAP_INS_MSG, .lc = req_len, .le = APDU_BUFFER_SIZE, .data = c_buf};
    RAPDU rapdu = {.data = r_buf};
    assert_true(req_len <= sizeof(c_buf));
    memcpy(c_buf, req, req_len);
    process_apdu(&capdu, &rapdu);
    for (;;) {
      assert_true(rapdu.sw == SW_NO_ERROR || (rapdu.sw & 0xFF00) == 0x6100);
      assert_true(total + rapdu.len <= capacity);
      memcpy(out + total, rapdu.data, rapdu.len);
      total += rapdu.len;
      if (rapdu.sw == SW_NO_ERROR) break;
      assert_int_equal(build_capdu(&capdu, (const uint8_t[]){0, 0xC0, 0, 0, 0}, 5), 0);
      process_apdu(&capdu, &rapdu);
    }
  }
  return total;
}

static void test_ctap_cm_mixed_algorithms(void **state) {
  (void)state;
  const CTAP_sm2_attr sm2_configs[] = {{9, -54}, {INT32_MIN, INT32_MAX}, {INT32_MAX, INT32_MIN}};
  CTAP_sm2_attr saved;
  CTAP_discoverable_credential credentials[6] = {0};
  CTAP_rp_meta meta = {0};
  CTAP_dc_general_attr attr = {.numbers = 6};
  static uint8_t expected[6][MLDSA_PK_BYTES], response[4096];
  uint8_t req[128], msg[64], auth[PIN_AUTH_SIZE_P1], seed[PRI_KEY_SIZE];
  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  const uint8_t select_fido[] = {0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1};

  init_apdu_buffer();
  device_init();
  assert_int_equal(ctap_install(1), 0);
  assert_int_equal(ctap_platform_sm2_config_read(&saved, sizeof(saved)), 0);
  provision_test_attestation();
  for (size_t config = 0; config < sizeof(sm2_configs) / sizeof(sm2_configs[0]); ++config) {
    uint8_t config_wire[CTAP_SM2_CONFIG_WIRE_SIZE];
    encode_sm2_config(config_wire, &sm2_configs[config]);
    CAPDU config_capdu = {.data = config_wire, .lc = sizeof(config_wire)};
    assert_int_equal(ctap_write_sm2_config(&config_capdu, &rapdu), 0);
    const int32_t algorithms[] = {sm2_configs[config].algo_id, COSE_ALG_ML_DSA_65, COSE_ALG_ES256,
                                  COSE_ALG_ML_DSA_65,          COSE_ALG_EDDSA,     sm2_configs[config].algo_id};
    sha256_raw((const uint8_t *)"cm.example", 10, meta.rp_id_hash);
    memcpy(meta.rp_id, "cm.example", 10);
    meta.rp_id_len = 10;
    meta.live_count = 6;
    for (size_t i = 0; i < 6; ++i) {
      memcpy(credentials[i].credential_id.rp_id_hash, meta.rp_id_hash, SHA256_DIGEST_LENGTH);
      assert_int_equal(generate_key_handle(&credentials[i].credential_id,
                                           algorithms[i] == COSE_ALG_ML_DSA_65 ? seed : expected[i], algorithms[i], 1,
                                           CRED_PROTECT_VERIFICATION_OPTIONAL, true),
                       0);
      if (algorithms[i] == COSE_ALG_ML_DSA_65) assert_int_equal(ml_dsa_65_keygen(expected[i], NULL, NULL, seed), 0);
      credentials[i].user.id[0] = (uint8_t)i;
      credentials[i].user.id_size = 1;
    }
    write_ctap_dc_fixture(credentials, 6, &meta, 1, &attr);
    for (int hid = 0; hid <= 1; ++hid) {
      assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
      process_apdu(&capdu, &rapdu);
      assert_int_equal(rapdu.sw, SW_NO_ERROR);
      cp_reset_pin_uv_auth_token();
      cp_begin_using_uv_auth_token(false);
      cp_set_permission(CP_PERMISSION_CM);
      size_t msg_len = build_enumerate_credentials_pin_message(msg, meta.rp_id_hash, false);
      cp_test_authenticate_pin_token(msg, msg_len, auth, 1);
      size_t req_len = build_third_party_payment_credential_management(req, meta.rp_id_hash, auth, false);
      for (size_t i = 0; i < 6; ++i) {
        size_t len = read_cm_response(hid, req, req_len, response, sizeof(response));
        test_cbor_view key, value;
        int64_t integer;
        const uint8_t *bytes;
        size_t bytes_len;
        assert_true(len > 1);
        assert_int_equal(response[0], CTAP1_ERR_SUCCESS);
        assert_int_equal(test_cbor_is_canonical(response + 1, len - 1), 0);
        assert_int_equal(test_cbor_map_lookup_int_key(response + 1, len - 1, CM_RESP_TOTAL_CREDENTIALS, &value),
                         i == 0 ? 0 : -1);
        assert_int_equal(test_cbor_map_lookup_int_key(response + 1, len - 1, CM_RESP_PUBLIC_KEY, &key), 0);
        assert_int_equal(test_cbor_map_lookup_int_key(key.ptr, key.len, COSE_KEY_LABEL_ALG, &value), 0);
        assert_int_equal(test_cbor_get_int(value, &integer), 0);
        assert_int_equal(integer, algorithms[i]);
        bool mldsa = algorithms[i] == COSE_ALG_ML_DSA_65;
        bool eddsa = algorithms[i] == COSE_ALG_EDDSA;
        assert_int_equal(test_cbor_map_lookup_int_key(key.ptr, key.len, COSE_KEY_LABEL_KTY, &value), 0);
        assert_int_equal(test_cbor_get_int(value, &integer), 0);
        assert_int_equal(integer, mldsa ? COSE_KEY_KTY_AKP : eddsa ? COSE_KEY_KTY_OKP : COSE_KEY_KTY_EC2);
        assert_int_equal(
            test_cbor_map_lookup_int_key(key.ptr, key.len, mldsa ? COSE_KEY_LABEL_AKP_PUB : COSE_KEY_LABEL_X, &value),
            0);
        assert_int_equal(test_cbor_get_byte_string(value, &bytes, &bytes_len), 0);
        assert_int_equal(bytes_len, mldsa ? MLDSA_PK_BYTES : 32);
        assert_memory_equal(bytes, expected[i], bytes_len);
        if (!mldsa) {
          assert_int_equal(test_cbor_map_lookup_int_key(key.ptr, key.len, COSE_KEY_LABEL_CRV, &value), 0);
          assert_int_equal(test_cbor_get_int(value, &integer), 0);
          assert_int_equal(integer, eddsa                             ? COSE_KEY_CRV_ED25519
                                    : algorithms[i] == COSE_ALG_ES256 ? COSE_KEY_CRV_P256
                                                                      : sm2_configs[config].curve_id);
          if (!eddsa) {
            assert_int_equal(test_cbor_map_lookup_int_key(key.ptr, key.len, COSE_KEY_LABEL_Y, &value), 0);
            assert_int_equal(test_cbor_get_byte_string(value, &bytes, &bytes_len), 0);
            assert_int_equal(bytes_len, 32);
            assert_memory_equal(bytes, expected[i] + 32, 32);
          }
        }
        req_len = build_credential_management_get_next(req);
      }
      size_t len = read_cm_response(hid, req, req_len, response, sizeof(response));
      assert_int_equal(len, 1);
      assert_int_equal(response[0], CTAP2_ERR_NOT_ALLOWED);
    }
  }
  uint8_t config_wire[CTAP_SM2_CONFIG_WIRE_SIZE];
  encode_sm2_config(config_wire, &saved);
  CAPDU config_capdu = {.data = config_wire, .lc = sizeof(config_wire)};
  assert_int_equal(ctap_write_sm2_config(&config_capdu, &rapdu), 0);
}



int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  struct lfs_filebd_config bdcfg = {.read_size = 1, .prog_size = 512, .erase_size = 512, .erase_count = 256};
  bd.cfg = &bdcfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &test_bd_read;
  cfg.prog = &lfs_filebd_prog;
  cfg.erase = &lfs_filebd_erase;
  cfg.sync = &lfs_filebd_sync;
  cfg.read_size = 1;
  cfg.prog_size = 512;
  cfg.block_size = 512;
  cfg.block_count = 256;
  cfg.block_cycles = 50000;
  cfg.cache_size = 512;
  cfg.lookahead_size = 32;
  // Static littlefs work buffers: the capacity-cache test remounts mid-suite,
  // and malloc'd buffers would leak on every re-init.
  static uint8_t read_buffer[512], prog_buffer[512], lookahead_buffer[32];
  cfg.read_buffer = read_buffer;
  cfg.prog_buffer = prog_buffer;
  cfg.lookahead_buffer = lookahead_buffer;
  test_apdu_fs_cfg = &cfg;
  lfs_filebd_create(&cfg, "lfs-root-apdu", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ctap_install_preserves_sm2_during_state_rebuild),
      cmocka_unit_test(test_ctap_cm_mixed_algorithms),
      cmocka_unit_test(test_acquire_apdu_interface_releases_session_on_buffer_conflict),
      cmocka_unit_test(test_ccid_power_on_does_not_steal_ctaphid_session),
      cmocka_unit_test(test_ccid_slot_status_survives_ctaphid_release),
      cmocka_unit_test(test_ctaphid_wait_services_only_ccid_presence_poll),
      cmocka_unit_test(test_ccid_rejects_reentrant_command_until_response_finishes),
      cmocka_unit_test(test_pke_buffer_fallback_for_ctap),
      cmocka_unit_test(test_ccid_extended_fido_request_uses_pke),
      cmocka_unit_test(test_fido_chained_make_credential_nfc),
      cmocka_unit_test(test_fido_ctap1_register_nfc),
      cmocka_unit_test(test_large_blob_noncanonical_string_offset),
      cmocka_unit_test(test_fido_ctap1_register_rejects_missing_attestation_key),
      cmocka_unit_test(test_fido_reset_nfc_bypasses_user_presence),
      cmocka_unit_test(test_fido_cbor_after_reset_without_select),
      cmocka_unit_test(test_fido_chained_cbor_after_reset_without_select),
      cmocka_unit_test(test_ctap_deselect_clears_get_next_assertion_state),
      cmocka_unit_test(test_ctap_poweroff_keeps_credential_management_state),
      cmocka_unit_test(test_ctap_deselect_clears_credential_management_state),
      cmocka_unit_test(test_ctap_capacity_uses_credential_metadata),
      cmocka_unit_test(test_ctap_capacity_cached_by_fs_generation),
      cmocka_unit_test(test_ctap_capacity_dc_read_failure_not_cached),
      cmocka_unit_test(test_ctap_pending_recovery_rebuilds_metadata),
      cmocka_unit_test(test_ctap_delete_updates_only_target_rp),
      cmocka_unit_test(test_ctap_allow_list_matches_multiple_dc_ids_in_one_scan),
      cmocka_unit_test(test_ctap_install_preserves_complete_attestation_state),
      cmocka_unit_test(test_ctap_install_rebuilds_state_without_attestation_key),
      cmocka_unit_test(test_ctap_install_rebuilds_state_with_short_attestation_key),
      cmocka_unit_test(test_ctap_install_rebuilds_state_with_empty_attestation_cert),
      cmocka_unit_test(test_ctap_hid_get_info_stream_source),
      cmocka_unit_test(test_ctap_algorithm_policy),
      cmocka_unit_test(test_ctap_kh_cache_lifecycle),
      cmocka_unit_test(test_ctap_pin_state_read_errors_are_propagated),
      cmocka_unit_test(test_ctaphid_msg_case3_and_case4_send_complete_response),
      cmocka_unit_test(test_ctap_hid_make_credential_accepts_p9_pub_key_param_order),
      cmocka_unit_test(test_ctap_make_credential_rejects_enterprise_attestation),
      cmocka_unit_test(test_ctap_hid_make_credential_hmac_secret_mc_requires_hmac_secret),
      cmocka_unit_test(test_ctap_hid_make_credential_hmac_secret_mc_output_key_is_separate),
      cmocka_unit_test(test_ctap_hid_make_credential_mldsa_hmac_secret_mc_output_key_is_separate),
      cmocka_unit_test(test_ctap_hid_third_party_payment_round_trip),
      cmocka_unit_test(test_ctap_hid_credential_management_returns_third_party_payment),
      cmocka_unit_test(test_ctap_apdu_credential_management_streams_mldsa_public_key),
      cmocka_unit_test(test_pin_uv_auth_clear_permissions_except_lbw),
      cmocka_unit_test(test_ctap_hid_large_cbor_response_keeps_payload),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
