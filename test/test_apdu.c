// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <cmocka.h>

#include <admin.h>
#include <applets.h>
#include <applet-scratch.h>
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <canokey-core-git-rev.h>
#include <ccid.h>
#include <ctap.h>
#include <device-config.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <oath.h>
#include <pke.h>
#include "../applets/ctap/secret.h"
#include "../applets/ctap/cose-key.h"
#include "../applets/ctap/ctap-errors.h"
#include "../applets/ctap/ctap-internal.h"
#include <ecc.h>
#include <hmac.h>
#include <sha.h>
#include <string.h>

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

static size_t build_third_party_payment_credential_management(uint8_t *req, const uint8_t *rp_id_hash,
                                                              const uint8_t *pin_auth) {
  uint8_t *p = req;

  *p++ = CTAP_CREDENTIAL_MANAGEMENT;
  *p++ = 0xA4;
  *p++ = CM_REQ_SUB_COMMAND;
  *p++ = CM_CMD_ENUMERATE_CREDENTIALS_BEGIN;
  *p++ = CM_REQ_SUB_COMMAND_PARAMS;
  *p++ = 0xA1;
  *p++ = CM_PARAM_RP_ID_HASH;
  put_cbor_bytes(&p, rp_id_hash, SHA256_DIGEST_LENGTH);
  *p++ = CM_REQ_PIN_UV_AUTH_PROTOCOL;
  *p++ = 0x01;
  *p++ = CM_REQ_PIN_UV_AUTH_PARAM;
  put_cbor_bytes(&p, pin_auth, PIN_AUTH_SIZE_P1);

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
  const uint8_t *p = buf;
  const uint8_t *end = buf + len;
  size_t map_len;

  if (p >= end || (*p & 0xE0) != 0xA0) return -1;
  if (test_cbor_read_len(&p, end, *p++ & 0x1F, &map_len) < 0) return -1;
  for (size_t i = 0; i < map_len; ++i) {
    size_t item_key;
    const uint8_t *value_start;

    if (p >= end || (*p & 0xE0) != 0x00) return -1;
    if (test_cbor_read_len(&p, end, *p++ & 0x1F, &item_key) < 0) return -1;
    value_start = p;
    if (test_cbor_skip(&p, end) < 0) return -1;
    if ((int)item_key == key) {
      value->ptr = value_start;
      value->len = (size_t)(p - value_start);
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

static void test_input_chaining(void **state) {
  (void)state;

  uint8_t c_buf[1024], total_buf[2048];
  uint8_t data[] = {0x74, 0x05, 0x21, 0x06, 0x00, 0x01, 0x02};
  CAPDU C = {.data = c_buf};
  CAPDU_CHAINING CC = {.capdu.data = total_buf, .in_chaining = 0};

  // test no chaining
  C.cla = 0x80;
  C.ins = 0x00;
  C.p1 = 0x01;
  C.p2 = 0xFF;
  C.lc = sizeof(data);
  memcpy(C.data, data, C.lc);
  int ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);

  // test normal chaining
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 3);

  // test abnormal chaining 1
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.ins = 0x20;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 2);

  // test abnormal chaining 2
  C.cla = 0x90;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_NOT_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 1);
  C.cla = 0x80;
  C.ins = 0x10;
  ret = apdu_input(&CC, &C);
  assert_int_equal(ret, APDU_CHAINING_LAST_BLOCK);
  assert_int_equal(CC.in_chaining, 0);
  assert_int_equal(CC.capdu.lc, sizeof(data) * 1);
}

static void test_output_chaining(void **state) {
  (void)state;

  uint8_t r_buf[1024], total_buf[2048];
  RAPDU R = {.data = r_buf, .len = 254};
  RAPDU_CHAINING RC = {.rapdu.data = total_buf, .rapdu.len = 512, .rapdu.sw = 0x9000, .sent = 0};

  int ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 254);
  assert_int_equal(R.sw, 0x61FF);

  ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 254);
  assert_int_equal(R.sw, 0x6104);

  ret = apdu_output(&RC, &R);
  assert_int_equal(ret, 0);
  assert_int_equal(R.len, 4);
  assert_int_equal(R.sw, 0x9000);
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

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_off, sizeof(power_off)), 0);
  CCID_Loop();

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_CTAPHID);
  assert_int_equal(release_apdu_buffer(BUFFER_OWNER_CTAPHID), 0);
  device_applet_session_release(DEVICE_APPLET_SESSION_CTAPHID);
}

static void test_ccid_power_on_preempts_idle_webusb_session(void **state) {
  (void)state;

  static const uint8_t power_on[] = {
      PC_TO_RDR_ICCPOWERON, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  };

  init_apdu_buffer();
  device_init();
  CCID_Init();

  assert_int_equal(device_applet_session_acquire(DEVICE_APPLET_SESSION_WEBUSB), 0);
  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_WEBUSB);

  assert_int_equal(CCID_OutEvent((uint8_t *)power_on, sizeof(power_on)), 0);
  CCID_Loop();

  assert_int_equal(device_applet_session_owner(), DEVICE_APPLET_SESSION_NONE);
}

static uint32_t observed_streaming_le;

static int record_streaming_capdu_le(const CAPDU *capdu, RAPDU *rapdu) {
  observed_streaming_le = capdu->le;
  rapdu->len = 0;
  rapdu->sw = SW_NO_ERROR;
  return 0;
}

static void test_streaming_message_preserves_original_le_for_handler(void **state) {
  (void)state;

  static const uint8_t read_binary_extended[] = {
      0x00, 0xB0, 0x00, 0x00, 0x00, 0x04, 0x01,
  };

  uint8_t c_buf[16], r_buf[16];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  RAPDU_CHAINING rapdu_chaining = {.rapdu.data = r_buf};

  observed_streaming_le = 0;

  assert_int_equal(build_capdu(&capdu, read_binary_extended, sizeof(read_binary_extended)), 0);
  assert_int_equal(capdu.le, 0x0401);
  assert_int_equal(
      apdu_process_streaming_message(&rapdu_chaining, &capdu, &rapdu, 0, APDU_BUFFER_SIZE, record_streaming_capdu_le),
      0);
  assert_int_equal(observed_streaming_le, 0x0401);
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

static void test_fido_chained_make_credential_nfc(void **state) {
  (void)state;

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

  set_nfc_state(1);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, mc_part1, sizeof(mc_part1)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 0);

  assert_int_equal(build_capdu(&capdu, mc_part2, sizeof(mc_part2)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, 0x9100);
  assert_int_equal(rapdu.len, 1);
  assert_int_equal(rapdu.data[0], 0x02);
  assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
  assert_int_equal(ctap_nfc_pending_active(), 1);

  // Simulate a PC/SC PowerICC reconnect between the NFC 0x9100 keepalive and
  // the required NFCCTAP_GETRESPONSE poll. The pending command must survive
  // this non-runtime ctap_install(0), and 80 11 must route back to FIDO even
  // though init_apdu_buffer() cleared the selected applet.
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  assert_int_equal(ctap_nfc_pending_active(), 1);

  static const uint8_t nfc_get_response[] = {
      0x80, 0x11, 0x00, 0x00, 0x00,
  };
  assert_int_equal(build_capdu(&capdu, nfc_get_response, sizeof(nfc_get_response)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_not_equal(rapdu.sw, SW_FILE_NOT_FOUND);
  assert_int_equal(rapdu.sw, 0x9100);
  assert_int_equal(rapdu.len, 1);
  assert_int_equal(rapdu.data[0], 0x02);
  assert_int_equal(ctap_nfc_pending_active(), 1);

  assert_int_equal(build_capdu(&capdu, nfc_get_response, sizeof(nfc_get_response)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_not_equal(rapdu.sw, SW_FILE_NOT_FOUND);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_true(rapdu.len > 0);
  assert_int_equal(ctap_nfc_pending_active(), 0);

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
  while (rapdu.sw != SW_NO_ERROR) {
    assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
    process_apdu(&capdu, &rapdu);
    total += rapdu.len;
  }

  assert_true(total >= rapdu.len);
}

static void test_fido_reset_nfc_returns_keepalive_pending(void **state) {
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

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, reset_apdu, sizeof(reset_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_equal(rapdu.sw, 0x9100);
  assert_int_equal(rapdu.len, 1);
  assert_int_equal(rapdu.data[0], KEEPALIVE_STATUS_UPNEEDED);
  assert_true(ctap_nfc_pending_active());
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
}

static void test_ctap_config_empty_request_is_legacy_unhandled(void **state) {
  (void)state;

  uint8_t config_req[] = {CTAP_CONFIG};
  uint8_t resp[64] = {0};
  size_t resp_len = sizeof(resp);

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(ctap_process_cbor_with_src(config_req, sizeof(config_req), resp, &resp_len, CTAP_SRC_HID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], CTAP2_ERR_UNHANDLED_REQUEST);
}

static void test_ctap_config_toggle_always_uv_without_pin(void **state) {
  (void)state;

  uint8_t config_req[] = {CTAP_CONFIG, 0xA1, 0x01, 0x02};
  uint8_t get_info_req[] = {0x04};
  uint8_t resp[64] = {0};
  size_t resp_len = sizeof(resp);
  uint8_t scratch[64] = {0};
  uint8_t chunk[APPLET_SHARED_BUFFER_LENGTH] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(ctap_process_cbor_with_src(config_req, sizeof(config_req), resp, &resp_len, CTAP_SRC_HID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x00);

  assert_int_equal(ctap_process_cbor_stream_with_src(get_info_req, sizeof(get_info_req), scratch, sizeof(scratch),
                                                     &source, CTAP_SRC_HID),
                   1);
  assert_true(source.total_len <= sizeof(chunk));
  assert_int_equal(source.read(source.ctx, chunk, source.total_len, &written), 0);
  assert_int_equal(written, source.total_len);
  assert_null(find_bytes(chunk, written, "U2F_V2", sizeof("U2F_V2") - 1));

  resp_len = sizeof(resp);
  assert_int_equal(ctap_process_cbor_with_src(config_req, sizeof(config_req), resp, &resp_len, CTAP_SRC_HID), 0);
  assert_int_equal(resp_len, 1);
  assert_int_equal(resp[0], 0x00);
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
  assert_make_credential_auth_data_has_hmac_secret_mc(resp, written, auth_data_buf, sizeof(auth_data_buf));

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
  uint8_t cm_pin_msg[1 + 4 + SHA256_DIGEST_LENGTH] = {0};
  uint8_t pin_auth[PIN_AUTH_SIZE_P1] = {0};
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH] = {0};
  uint8_t fido_private_key[32] = {1};
  uint8_t cert[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  size_t mc_written = 0;
  size_t cm_written = 0;
  size_t mc_req_len;
  size_t cm_req_len;
  CTAPHID_TxSource source = {0};
  test_cbor_view value;
  bool third_party_payment;
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
  cm_pin_msg[0] = CM_CMD_ENUMERATE_CREDENTIALS_BEGIN;
  cm_pin_msg[1] = 0xA1;
  cm_pin_msg[2] = CM_PARAM_RP_ID_HASH;
  cm_pin_msg[3] = 0x58;
  cm_pin_msg[4] = SHA256_DIGEST_LENGTH;
  memcpy(cm_pin_msg + 5, rp_id_hash, SHA256_DIGEST_LENGTH);
  cp_test_authenticate_pin_token(cm_pin_msg, sizeof(cm_pin_msg), pin_auth, 1);
  cm_req_len = build_third_party_payment_credential_management(cm_req, rp_id_hash, pin_auth);

  memset(&source, 0, sizeof(source));
  assert_int_equal(
      ctap_process_cbor_stream_with_src(cm_req, cm_req_len, scratch, sizeof(scratch), &source, CTAP_SRC_HID), 1);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, cm_resp, sizeof(cm_resp), &cm_written), 0);
  assert_int_equal(cm_resp[0], 0x00);
  assert_int_equal(test_cbor_map_lookup_int_key(cm_resp + 1, cm_written - 1, CM_RESP_TOTAL_CREDENTIALS, &value), 0);
  assert_int_equal(test_cbor_get_uint(value, &total_credentials), 0);
  assert_int_equal(total_credentials, 1);
  assert_int_equal(test_cbor_map_lookup_int_key(cm_resp + 1, cm_written - 1, CM_RESP_THIRD_PARTY_PAYMENT, &value), 0);
  assert_int_equal(test_cbor_get_bool(value, &third_party_payment), 0);
  assert_true(third_party_payment);
  if (source.close) source.close(source.ctx);
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

static void test_ctap_get_info_reports_transport_msg_size(void **state) {
  (void)state;

  static uint8_t req[] = {CTAP_GET_INFO};
  uint8_t scratch[64] = {0};
  uint8_t resp[512] = {0};
  CTAPHID_TxSource source = {0};
  size_t written = 0;
  const uint8_t expected[] = {GI_RESP_MAX_MSG_SIZE, 0x19, HI(CTAP_MAX_MSG_SIZE), LO(CTAP_MAX_MSG_SIZE)};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(ctap_process_cbor_stream_with_src(req, sizeof(req), scratch, sizeof(scratch), &source, CTAP_SRC_HID),
                   1);
  assert_non_null(source.read);
  assert_int_equal(read_tx_source_all(&source, resp, sizeof(resp), &written), 0);
  assert_non_null(find_bytes(resp, written, expected, sizeof(expected)));
  if (source.close) source.close(source.ctx);
}

static void test_get_response_after_reset_without_pending_response(void **state) {
  (void)state;

  static const uint8_t get_response[] = {
      0x00, 0xC0, 0x00, 0x00, 0x2D,
  };

  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_COMMAND_NOT_ALLOWED);
}

// ---------------------------------------------------------------------------
// Streaming response source coverage
//
// `apdu_response_source_set` + `apdu_output` are the streaming primitive
// used by PIV / OpenPGP / NFC FIDO to emit responses larger than the APDU
// buffer. The tests below exercise:
//   - the multi-chunk read loop driven by GET RESPONSE
//   - the tail-restore branch that protects bytes the caller will overwrite
//     with the SW trailer when the source is aliased on shared_io_buffer
//   - the read-failure error path (sets sh->sw to SW_UNABLE_TO_PROCESS)
//   - the close callback bookkeeping
//
// Each callback uses static state because the response source API stores raw
// pointers (no per-source allocation) and we want to verify ordering.

typedef struct {
  const uint8_t *data;
  size_t total;
  size_t reads;
  size_t closes;
  int read_should_fail;
} streaming_source_ctx;

static streaming_source_ctx stream_ctx;

static int streaming_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  streaming_source_ctx *s = (streaming_source_ctx *)ctx;
  s->reads++;
  if (s->read_should_fail) return -1;
  if (offset > s->total || len > s->total - offset) return -1;
  memcpy(buf, s->data + offset, len);
  return len;
}

static void streaming_source_close(void *ctx) {
  streaming_source_ctx *s = (streaming_source_ctx *)ctx;
  s->closes++;
}

static void test_response_source_multi_chunk_get_response(void **state) {
  (void)state;
  init_apdu_buffer();

  // 600 bytes is enough to require three GET RESPONSE rounds at the 250-byte
  // streaming chunk size (250 + 250 + 100).
  static uint8_t payload[600];
  for (size_t i = 0; i < sizeof(payload); ++i)
    payload[i] = (uint8_t)(i * 7 + 1);

  stream_ctx = (streaming_source_ctx){.data = payload, .total = sizeof(payload)};
  apdu_response_source_set((uint32_t)sizeof(payload), SW_NO_ERROR, streaming_source_read, streaming_source_close,
                           &stream_ctx);
  assert_int_equal(apdu_response_source_active(), 1);

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  // Round 1: 250 bytes, 0x61FF (more than 0xFF remaining).
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 250);
  assert_int_equal(rapdu.sw, 0x61FF);
  assert_memory_equal(rapdu.data, payload, 250);

  // Round 2: another 250 bytes, still 0x61FF (100 remaining).
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 250);
  assert_int_equal(rapdu.sw, 0x6164);
  assert_memory_equal(rapdu.data, payload + 250, 250);

  // Round 3: final 100 bytes + 0x9000.
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 100);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_memory_equal(rapdu.data, payload + 500, 100);

  // Stream is finalized; close callback must have fired exactly once.
  assert_int_equal(apdu_response_source_active(), 0);
  assert_int_equal(stream_ctx.closes, 1);
  assert_int_equal(stream_ctx.reads, 3);

  // A trailing GET RESPONSE without a pending stream is rejected.
  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_COMMAND_NOT_ALLOWED);
}

// Source that reads directly from shared_io_buffer, exercising the case where
// the source data IS the response buffer (e.g. PIV / OpenPGP staging the
// payload in shared_io_buffer before calling apdu_response_source_set with
// ctx == shared_io_buffer-relative pointer). The interesting bug this guards
// against: after the first chunk, the transport stamps the SW trailer at
// sh->data + sh->len, which lands inside the source's still-pending data;
// apdu_output must save and restore those bytes around the SW stamp so the
// next chunk's read gets the original payload.
static int shared_buffer_source_read(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  (void)ctx;
  // The source data lives in shared_io_buffer at the "source view" offset
  // we set up before kicking the stream. memmove handles the buffer overlap
  // when buf == shared_io_buffer + 0 and the source data starts at the same
  // address (first chunk is a no-op copy; later chunks read from forward
  // offsets and write back near the start).
  memmove(buf, shared_io_buffer + offset, len);
  return len;
}

static void test_response_source_tail_restore_on_shared_buffer(void **state) {
  (void)state;
  init_apdu_buffer();

  // Stage 260 bytes of payload directly into shared_io_buffer. The source
  // reads from shared_io_buffer and writes back to it.
  for (size_t i = 0; i < 260; ++i)
    shared_io_buffer[i] = (uint8_t)(0x40 + (i & 0x3F));
  const uint8_t expected_byte250 = shared_io_buffer[250];
  const uint8_t expected_byte251 = shared_io_buffer[251];
  assert_int_not_equal(expected_byte250, 0x61);
  assert_int_not_equal(expected_byte251, 0x0A);

  stream_ctx = (streaming_source_ctx){.data = NULL, .total = 260};
  apdu_response_source_set(260, SW_NO_ERROR, shared_buffer_source_read, streaming_source_close, &stream_ctx);

  CAPDU capdu = {.data = shared_io_buffer};
  RAPDU rapdu = {.data = shared_io_buffer};
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 250);
  assert_int_equal(rapdu.sw, 0x610A);
  // First chunk content: payload[0..249] which still equals the original
  // staging bytes since memmove covers same-source/dest.
  for (size_t i = 0; i < 250; ++i)
    assert_int_equal(rapdu.data[i], (uint8_t)(0x40 + (i & 0x3F)));

  // Simulate the transport stamping the 2-byte SW trailer right after the
  // chunk data. This corrupts shared_io_buffer[250..251], which is what the
  // source would otherwise return on the next read.
  shared_io_buffer[250] = 0x61;
  shared_io_buffer[251] = 0x0A;

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 10);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  // The tail-restore branch must have written the saved bytes back to
  // shared_io_buffer[250..251] before the source read; otherwise the first
  // two output bytes would be 0x61 0x0A.
  assert_int_equal(rapdu.data[0], expected_byte250);
  assert_int_equal(rapdu.data[1], expected_byte251);
  assert_int_equal(stream_ctx.closes, 1);
}

static void test_response_source_read_failure_clears_state(void **state) {
  (void)state;
  init_apdu_buffer();

  static uint8_t payload[300];
  memset(payload, 0xAA, sizeof(payload));
  stream_ctx = (streaming_source_ctx){.data = payload, .total = sizeof(payload), .read_should_fail = 1};
  apdu_response_source_set((uint32_t)sizeof(payload), SW_NO_ERROR, streaming_source_read, streaming_source_close,
                           &stream_ctx);

  uint8_t c_buf[64], r_buf[1024];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};
  static const uint8_t get_response[] = {0x00, 0xC0, 0x00, 0x00, 0x00};

  assert_int_equal(build_capdu(&capdu, get_response, sizeof(get_response)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_UNABLE_TO_PROCESS);
  assert_int_equal(apdu_response_source_active(), 0);
  // close should still fire so applets release their backing storage.
  assert_int_equal(stream_ctx.closes, 1);
}

// apdu_output non-source path: when ex->rapdu.data aliases sh->data (the
// transport stages and emits from the same shared_io_buffer), the SW trailer
// the caller stamps after each chunk corrupts bytes that later chunks still
// need. The tail-save branch captures those bytes on the first call and
// replays them on subsequent calls.
//
// shared_io_buffer is APDU_COMMAND_BUFFER_SIZE bytes (288 by default), so
// a 280-byte response chunked at 256 bytes lets us exercise the path
// without overflowing the staging buffer.
static void test_apdu_output_chaining_aliased_buffer(void **state) {
  (void)state;
  init_apdu_buffer();

  enum { RESP_LEN = 280 };
  uint8_t expected[RESP_LEN];
  for (size_t i = 0; i < RESP_LEN; ++i)
    expected[i] = (uint8_t)(0x80 + (i & 0x3F));

  memcpy(shared_io_buffer, expected, RESP_LEN);
  RAPDU_CHAINING rc = {
      .rapdu.data = shared_io_buffer,
      .rapdu.len = RESP_LEN,
      .rapdu.sw = SW_NO_ERROR,
      .sent = 0,
  };
  RAPDU sh = {.data = shared_io_buffer, .len = APDU_BUFFER_SIZE};

  // First chunk: 256 bytes, 0x6118 because 24 bytes still pending.
  assert_int_equal(apdu_output(&rc, &sh), 0);
  assert_int_equal(sh.len, 256);
  assert_int_equal(sh.sw, 0x6118);
  assert_memory_equal(sh.data, expected, 256);

  // Simulate the transport stamping the SW trailer right after the chunk
  // data; this corrupts shared_io_buffer[256..257], which originally held
  // expected[256..257]. Tail-save must have copied those bytes out before
  // we did this corruption.
  shared_io_buffer[256] = 0x61;
  shared_io_buffer[257] = 0x18;

  // Second chunk: remaining 24 bytes + 0x9000. Without tail-save the first
  // two output bytes would be 0x61 0x18 (the SW), not the original payload.
  sh.len = APDU_BUFFER_SIZE;
  assert_int_equal(apdu_output(&rc, &sh), 0);
  assert_int_equal(sh.len, 24);
  assert_int_equal(sh.sw, SW_NO_ERROR);
  assert_memory_equal(sh.data, expected + 256, 24);
}

// fido_apdu_input rejects chains whose accumulated length would exceed the
// PKE staging buffer. Send maximum-sized chained APDUs until APDU_CHAINING_OVERFLOW
// fires, which process_apdu maps to SW_WRONG_LENGTH and which must also reset
// the chain so subsequent commands can run.
static void test_fido_apdu_chain_overflow_returns_wrong_length(void **state) {
  (void)state;

  static const uint8_t select_fido[] = {
      0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
  };

  uint8_t c_buf[512], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  set_nfc_state(0);

  assert_int_equal(build_capdu(&capdu, select_fido, sizeof(select_fido)), 0);
  process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // Build a maximally-sized chained APDU (CLA=0x90, INS=0x10, Lc=0xFF=255).
  uint8_t big[5 + 255];
  big[0] = 0x90;
  big[1] = 0x10;
  big[2] = 0x00;
  big[3] = 0x00;
  big[4] = 0xFF;
  memset(big + 5, 0xAB, 255);

  size_t total = 0;
  for (int i = 0; i < 32; ++i) {
    assert_int_equal(build_capdu(&capdu, big, sizeof(big)), 0);
    process_apdu(&capdu, &rapdu);
    if (rapdu.sw == SW_WRONG_LENGTH) {
      // Overflow correctly signaled. fido_capdu_reset was called on this
      // path, releasing PKE; we should now be able to acquire it elsewhere.
      assert_int_equal(pke_buffer_acquire(PKE_BUFFER_OWNER_PIV), 0);
      assert_int_equal(pke_buffer_release(PKE_BUFFER_OWNER_PIV), 0);
      return;
    }
    assert_int_equal(rapdu.sw, SW_NO_ERROR);
    total += 255;
  }
  fail_msg("Expected SW_WRONG_LENGTH after %zu accumulated bytes", total);
}

static void test_response_source_clear_calls_close(void **state) {
  (void)state;
  init_apdu_buffer();

  static const uint8_t payload[16] = {0};
  stream_ctx = (streaming_source_ctx){.data = payload, .total = sizeof(payload)};
  apdu_response_source_set((uint32_t)sizeof(payload), SW_NO_ERROR, streaming_source_read, streaming_source_close,
                           &stream_ctx);
  assert_int_equal(apdu_response_source_active(), 1);
  assert_int_equal(stream_ctx.closes, 0);

  apdu_response_source_clear();
  assert_int_equal(apdu_response_source_active(), 0);
  assert_int_equal(stream_ctx.closes, 1);

  // Clearing again is a no-op; close must not fire twice.
  apdu_response_source_clear();
  assert_int_equal(stream_ctx.closes, 1);
}

static void test_fido_magic_reboot_after_reset_without_select(void **state) {
  (void)state;

  static const uint8_t magic_reboot_apdu[] = {
      0x00, 0xEE, 0x00, 0x00, 0x04, 0x12, 0x56, 0xAB, 0xF0,
  };

  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  assert_int_equal(build_capdu(&capdu, magic_reboot_apdu, sizeof(magic_reboot_apdu)), 0);
  process_apdu(&capdu, &rapdu);

  assert_int_equal(rapdu.len, 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
}

static void admin_send(CAPDU *capdu, RAPDU *rapdu, uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data,
                       uint16_t lc, uint32_t le) {
  capdu->cla = 0x00;
  capdu->ins = ins;
  capdu->p1 = p1;
  capdu->p2 = p2;
  capdu->lc = lc;
  capdu->le = le;
  if (lc > 0) memcpy(capdu->data, data, lc);

  admin_process_apdu(capdu, rapdu);
}

static void admin_verify_default_pin(CAPDU *capdu, RAPDU *rapdu) {
  static const uint8_t default_pin[] = {'1', '2', '3', '4', '5', '6'};

  admin_send(capdu, rapdu, ADMIN_INS_VERIFY, 0x00, 0x00, default_pin, sizeof(default_pin), 0);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  assert_int_equal(rapdu->len, 0);
}

static void admin_set_feature_mask(CAPDU *capdu, RAPDU *rapdu, uint8_t mask) {
  admin_send(capdu, rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_FEATURE, mask, NULL, 0, 0);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  assert_int_equal(rapdu->len, 0);
}

static uint32_t admin_usage_record_bytes(const uint8_t *data, uint8_t id, uint8_t *flags) {
  for (size_t off = 0; off < ADMIN_APPLET_USAGE_RESPONSE_LENGTH; off += ADMIN_APPLET_USAGE_RECORD_LENGTH) {
    if (data[off] != id) continue;
    if (flags) *flags = data[off + 1];
    return ((uint32_t)data[off + 2] << 24) | ((uint32_t)data[off + 3] << 16) | ((uint32_t)data[off + 4] << 8) |
           data[off + 5];
  }
  fail_msg("admin applet usage id %u not found", id);
  return 0;
}

static void test_admin_platform_config_and_serial_apdus(void **state) {
  (void)state;

  uint8_t c_buf[ADMIN_KBD_KEYMAP_LENGTH];
  uint8_t r_buf[ADMIN_KBD_KEYMAP_LENGTH];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(admin_install(1), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_CONFIG, 0x00, 0x00, NULL, 0, 6);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 6);
  assert_int_equal(rapdu.data[0], 1);
  assert_int_equal(rapdu.data[3], 1);
  assert_int_equal(rapdu.data[4], 1);
  assert_int_equal(rapdu.data[5], ADMIN_FEATURE_MASK);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_CONFIG, 0x01, 0x00, NULL, 0, 6);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_CONFIG, 0x00, 0x00, NULL, 0, 5);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_LED_ON, 0x00, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  admin_verify_default_pin(&capdu, &rapdu);

  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_LED_ON, 0x00, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(device_config_is_led_normally_on(), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_NDEF, 0x00, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(device_config_is_ndef_enabled(), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_WEBUSB_LANDING, 0x00, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(device_config_is_webusb_landing_enabled(), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_FEATURE, ADMIN_FEATURE_MASK | 0x80, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  uint8_t feature_value = 0;
  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, ADMIN_P1_CFG_FEATURE, ADMIN_FEATURE_MASK, &feature_value, 1, 0);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_set_feature_mask(&capdu, &rapdu, 0);
  assert_int_equal(device_config_is_pass_enabled(), 0);
  assert_int_equal(device_config_is_openpgp_ccid_enabled(), 0);
  assert_int_equal(device_config_is_openpgp_nfc_enabled(), 0);
  assert_int_equal(device_config_is_piv_ccid_enabled(), 0);
  assert_int_equal(device_config_is_piv_nfc_enabled(), 0);
  assert_int_equal(device_config_is_webauthn_enabled(), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_CONFIG, 0x7F, 0x00, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_CONFIG, 0x00, 0x00, NULL, 0, 6);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 6);
  assert_int_equal(rapdu.data[0], 0);
  assert_int_equal(rapdu.data[3], 0);
  assert_int_equal(rapdu.data[4], 0);
  assert_int_equal(rapdu.data[5], 0);

  uint8_t serial[4];
  device_config_fill_serial(serial);
  assert_memory_equal(serial, "\x00\x00\x00\x00", sizeof(serial));

  const uint8_t expected_serial[] = {0xA1, 0xB2, 0xC3, 0xD4};
  admin_send(&capdu, &rapdu, ADMIN_INS_WRITE_SN, 0x00, 0x00, expected_serial, sizeof(expected_serial), 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_SN, 0x00, 0x00, NULL, 0, sizeof(expected_serial));
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, sizeof(expected_serial));
  assert_memory_equal(rapdu.data, expected_serial, sizeof(expected_serial));

  admin_send(&capdu, &rapdu, ADMIN_INS_WRITE_SN, 0x00, 0x00, expected_serial, sizeof(expected_serial), 0);
  assert_int_equal(rapdu.sw, SW_CONDITIONS_NOT_SATISFIED);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_SN, 0x00, 0x00, NULL, 0, sizeof(expected_serial) - 1);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);
}

static void test_admin_read_core_commit_apdu(void **state) {
  (void)state;

  uint8_t c_buf[64], r_buf[APDU_BUFFER_SIZE];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_VERSION, ADMIN_P1_READ_CORE_COMMIT, 0x00, NULL, 0, sizeof(r_buf));
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  size_t expected_len = sizeof(CANOKEY_CORE_GIT_REV) - 1;
  if (expected_len > APDU_BUFFER_SIZE) expected_len = APDU_BUFFER_SIZE;
  assert_int_equal(rapdu.len, expected_len);
  assert_memory_equal(rapdu.data, CANOKEY_CORE_GIT_REV, expected_len);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_VERSION, ADMIN_P1_READ_CORE_COMMIT, 0x01, NULL, 0, sizeof(r_buf));
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_VERSION, ADMIN_P1_READ_CORE_COMMIT + 1, 0x00, NULL, 0, sizeof(r_buf));
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);
}

static void test_admin_flash_usage_apdus(void **state) {
  (void)state;

  uint8_t c_buf[64], r_buf[ADMIN_APPLET_USAGE_RESPONSE_LENGTH];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_FLASH_USAGE, ADMIN_FLASH_USAGE_TOTAL, 0x00, NULL, 0, 2);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 2);

  admin_send(&capdu, &rapdu, ADMIN_INS_FLASH_USAGE, ADMIN_FLASH_USAGE_TOTAL, 0x01, NULL, 0, 2);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_FLASH_USAGE, ADMIN_FLASH_USAGE_TOTAL, 0x00, NULL, 0, 1);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_FLASH_USAGE, ADMIN_FLASH_USAGE_TOTAL, 0x00, NULL, 0, 2);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 2);

  assert_int_equal(write_file("oath", "abcd", 0, 4, 1), 0);
  assert_int_equal(write_attr("oath", ATTR_KEY, "xy", 2), 0);
  assert_int_equal(write_file("ctap_lb", "12345", 0, 5, 1), 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_FLASH_USAGE, ADMIN_FLASH_USAGE_APPLETS, 0x00, NULL, 0,
             ADMIN_APPLET_USAGE_RESPONSE_LENGTH - 1);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_FLASH_USAGE, ADMIN_FLASH_USAGE_APPLETS, 0x00, NULL, 0,
             ADMIN_APPLET_USAGE_RESPONSE_LENGTH);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, ADMIN_APPLET_USAGE_RESPONSE_LENGTH);

  uint8_t flags = 0;
  assert_true(admin_usage_record_bytes(rapdu.data, ADMIN_APPLET_USAGE_ID_OATH, &flags) >= 6);
  assert_int_equal(flags & ADMIN_APPLET_USAGE_FLAG_MISSING, 0);
  assert_true(admin_usage_record_bytes(rapdu.data, ADMIN_APPLET_USAGE_ID_CTAP, &flags) >= 5);
  (void)admin_usage_record_bytes(rapdu.data, ADMIN_APPLET_USAGE_ID_OPENPGP, &flags);
  assert_true(admin_usage_record_bytes(rapdu.data, ADMIN_APPLET_USAGE_ID_SYSTEM, &flags) > 0);
  assert_int_equal(flags, 0);
}

static void test_admin_kbd_keymap_apdus(void **state) {
  (void)state;

  uint8_t c_buf[ADMIN_KBD_KEYMAP_LENGTH];
  uint8_t r_buf[ADMIN_KBD_KEYMAP_LENGTH];
  uint8_t keymap[ADMIN_KBD_KEYMAP_LENGTH];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(admin_install(1), 0);
  admin_verify_default_pin(&capdu, &rapdu);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, ADMIN_P2_KBD_READ_LAYOUT_ID, NULL, 0, 1);
  assert_int_equal(rapdu.sw, SW_REFERENCE_DATA_NOT_FOUND);

  for (size_t i = 0; i < sizeof(keymap); ++i)
    keymap[i] = (uint8_t)(i ^ 0x5A);

  admin_send(&capdu, &rapdu, ADMIN_INS_WRITE_KBD_KEYMAP, 0x01, 0x33, keymap, sizeof(keymap), 0);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_WRITE_KBD_KEYMAP, 0x00, 0x33, keymap, sizeof(keymap) - 1, 0);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_WRITE_KBD_KEYMAP, 0x00, 0x33, keymap, sizeof(keymap), 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 0);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, ADMIN_P2_KBD_READ_LAYOUT_ID, NULL, 0, 1);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, 1);
  assert_int_equal(rapdu.data[0], 0x33);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, ADMIN_P2_KBD_READ_KEYMAP, NULL, 0,
             ADMIN_KBD_KEYMAP_LENGTH - 1);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, ADMIN_P2_KBD_READ_KEYMAP, keymap, 1,
             ADMIN_KBD_KEYMAP_LENGTH);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, ADMIN_P2_KBD_READ_KEYMAP, NULL, 0,
             ADMIN_KBD_KEYMAP_LENGTH);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(rapdu.len, ADMIN_KBD_KEYMAP_LENGTH);
  assert_memory_equal(rapdu.data, keymap, sizeof(keymap));

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, 0x7F, NULL, 0, 1);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_CLEAR_KBD_KEYMAP, 0x00, 0x01, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_WRONG_P1P2);

  admin_send(&capdu, &rapdu, ADMIN_INS_CLEAR_KBD_KEYMAP, 0x00, 0x00, keymap, 1, 0);
  assert_int_equal(rapdu.sw, SW_WRONG_LENGTH);

  admin_send(&capdu, &rapdu, ADMIN_INS_CLEAR_KBD_KEYMAP, 0x00, 0x00, NULL, 0, 0);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  admin_send(&capdu, &rapdu, ADMIN_INS_READ_KBD_KEYMAP, 0x00, ADMIN_P2_KBD_READ_KEYMAP, NULL, 0,
             ADMIN_KBD_KEYMAP_LENGTH);
  assert_int_equal(rapdu.sw, SW_REFERENCE_DATA_NOT_FOUND);
}

static void test_runtime_feature_apdu_routing(void **state) {
  (void)state;

  static const uint8_t select_openpgp[] = {
      0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
  };
  static const uint8_t select_piv[] = {
      0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08,
  };
  static const uint8_t fido_version[] = {
      0x00, 0x03, 0x00, 0x00, 0x00,
  };
  static const uint8_t openpgp_get_aid[] = {
      0x00, 0xCA, 0x00, 0x4F, 0x00,
  };

  uint8_t c_buf[64], r_buf[64];
  CAPDU capdu = {.data = c_buf};
  RAPDU rapdu = {.data = r_buf};

  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);
  assert_int_equal(admin_install(1), 0);
  admin_verify_default_pin(&capdu, &rapdu);

  admin_set_feature_mask(&capdu, &rapdu, ADMIN_FEATURE_MASK & (uint8_t)~ADMIN_FEATURE_OPENPGP_CCID);
  assert_int_equal(build_capdu(&capdu, select_openpgp, sizeof(select_openpgp)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_CCID);
  assert_int_equal(rapdu.sw, SW_FILE_NOT_FOUND);

  admin_set_feature_mask(&capdu, &rapdu, ADMIN_FEATURE_MASK);
  assert_int_equal(build_capdu(&capdu, select_openpgp, sizeof(select_openpgp)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_CCID);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  assert_int_equal(build_capdu(&capdu, openpgp_get_aid, sizeof(openpgp_get_aid)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_CCID);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_true(rapdu.len > 0);
  assert_int_equal(rapdu.data[0], 0xD2);

  init_apdu_buffer();
  admin_verify_default_pin(&capdu, &rapdu);

  admin_set_feature_mask(&capdu, &rapdu, ADMIN_FEATURE_MASK & (uint8_t)~ADMIN_FEATURE_OPENPGP_NFC);
  assert_int_equal(build_capdu(&capdu, select_openpgp, sizeof(select_openpgp)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  assert_int_equal(rapdu.sw, SW_FILE_NOT_FOUND);

  admin_set_feature_mask(&capdu, &rapdu, ADMIN_FEATURE_MASK & (uint8_t)~ADMIN_FEATURE_PIV_CCID);
  assert_int_equal(build_capdu(&capdu, select_piv, sizeof(select_piv)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_CCID);
  assert_int_equal(rapdu.sw, SW_FILE_NOT_FOUND);

  admin_set_feature_mask(&capdu, &rapdu, ADMIN_FEATURE_MASK & (uint8_t)~ADMIN_FEATURE_PIV_NFC);
  assert_int_equal(build_capdu(&capdu, select_piv, sizeof(select_piv)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_NFC);
  assert_int_equal(rapdu.sw, SW_FILE_NOT_FOUND);

  admin_set_feature_mask(&capdu, &rapdu, ADMIN_FEATURE_MASK & (uint8_t)~ADMIN_FEATURE_WEBAUTHN);
  init_apdu_buffer();
  assert_int_equal(build_capdu(&capdu, fido_version, sizeof(fido_version)), 0);
  process_apdu_from(&capdu, &rapdu, APDU_TRANSPORT_CCID);
  assert_int_equal(rapdu.sw, SW_FILE_NOT_FOUND);
}

int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  struct lfs_filebd_config bdcfg = {.read_size = 1, .prog_size = 512, .erase_size = 512, .erase_count = 256};
  bd.cfg = &bdcfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_filebd_read;
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
  lfs_filebd_create(&cfg, "lfs-root", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  init_apdu_buffer();
  device_init();
  assert_int_equal(applets_install(), 0);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_input_chaining),
      cmocka_unit_test(test_output_chaining),
      cmocka_unit_test(test_acquire_apdu_interface_releases_session_on_buffer_conflict),
      cmocka_unit_test(test_ccid_power_on_does_not_steal_ctaphid_session),
      cmocka_unit_test(test_ccid_power_on_preempts_idle_webusb_session),
      cmocka_unit_test(test_streaming_message_preserves_original_le_for_handler),
      cmocka_unit_test(test_pke_buffer_fallback_for_ctap),
      cmocka_unit_test(test_fido_chained_make_credential_nfc),
      cmocka_unit_test(test_fido_ctap1_register_nfc),
      cmocka_unit_test(test_fido_reset_nfc_returns_keepalive_pending),
      cmocka_unit_test(test_fido_cbor_after_reset_without_select),
      cmocka_unit_test(test_fido_chained_cbor_after_reset_without_select),
      cmocka_unit_test(test_ctap_deselect_clears_get_next_assertion_state),
      cmocka_unit_test(test_ctap_poweroff_keeps_credential_management_state),
      cmocka_unit_test(test_ctap_deselect_clears_credential_management_state),
      cmocka_unit_test(test_ctap_hid_get_info_stream_source),
      cmocka_unit_test(test_ctap_config_empty_request_is_legacy_unhandled),
      cmocka_unit_test(test_ctap_config_toggle_always_uv_without_pin),
      cmocka_unit_test(test_ctap_hid_make_credential_accepts_p9_pub_key_param_order),
      cmocka_unit_test(test_ctap_hid_make_credential_hmac_secret_mc_requires_hmac_secret),
      cmocka_unit_test(test_ctap_hid_make_credential_hmac_secret_mc_output_key_is_separate),
      cmocka_unit_test(test_ctap_hid_make_credential_mldsa_hmac_secret_mc_output_key_is_separate),
      cmocka_unit_test(test_ctap_hid_third_party_payment_round_trip),
      cmocka_unit_test(test_ctap_hid_credential_management_returns_third_party_payment),
      cmocka_unit_test(test_pin_uv_auth_clear_permissions_except_lbw),
      cmocka_unit_test(test_ctap_hid_large_cbor_response_keeps_payload),
      cmocka_unit_test(test_ctap_get_info_reports_transport_msg_size),
      cmocka_unit_test(test_get_response_after_reset_without_pending_response),
      cmocka_unit_test(test_response_source_multi_chunk_get_response),
      cmocka_unit_test(test_response_source_tail_restore_on_shared_buffer),
      cmocka_unit_test(test_response_source_read_failure_clears_state),
      cmocka_unit_test(test_apdu_output_chaining_aliased_buffer),
      cmocka_unit_test(test_fido_apdu_chain_overflow_returns_wrong_length),
      cmocka_unit_test(test_response_source_clear_calls_close),
      cmocka_unit_test(test_fido_magic_reboot_after_reset_without_select),
      cmocka_unit_test(test_admin_platform_config_and_serial_apdus),
      cmocka_unit_test(test_admin_read_core_commit_apdu),
      cmocka_unit_test(test_admin_flash_usage_apdus),
      cmocka_unit_test(test_admin_kbd_keymap_apdus),
      cmocka_unit_test(test_runtime_feature_apdu_routing),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
