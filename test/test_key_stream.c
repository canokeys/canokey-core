// SPDX-License-Identifier: Apache-2.0
// Unit tests for streaming RSA key import (PIV and OpenPGP)
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <bd/lfs_filebd.h>
#include <crypto-util.h>
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <string.h>

extern ck_key_t key_buffer;
extern ck_key_stream_t key_stream;

// ============================================================
// Helpers
// ============================================================

// Build PIV RSA key import data: interleaved [tag][len][data] for 5 components
// Each component filled with (0xA0 + component_index)
static size_t build_piv_rsa_data(uint8_t *buf, size_t buf_size, size_t pri_len) {
  // Fill values must make p and q pass CEIL_DIV_SQRT2 (0xB504F334) check:
  // First 4 bytes of p (index 0) and q (index 1) must be >= 0xB504F334 big-endian.
  const uint8_t fills[] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4};
  size_t pos = 0;
  for (int i = 0; i < 5; i++) {
    assert_true(pos + 3 + pri_len <= buf_size);
    buf[pos++] = (uint8_t)(i + 1); // tag: 01..05
    if (pri_len < 128) {
      buf[pos++] = (uint8_t)pri_len;
    } else if (pri_len < 256) {
      buf[pos++] = 0x81;
      buf[pos++] = (uint8_t)pri_len;
    } else {
      buf[pos++] = 0x82;
      buf[pos++] = (uint8_t)(pri_len >> 8);
      buf[pos++] = (uint8_t)(pri_len & 0xFF);
    }
    memset(buf + pos, fills[i], pri_len);
    pos += pri_len;
  }
  return pos;
}

// Build OpenPGP RSA key import data:
// [7F48][outer_len]{ [91][e_len][92][p_len][93][q_len][94][qinv_len][95][dp_len][96][dq_len] }
// [5F48][data_len]{ e_data | p_data | q_data | qinv_data | dp_data | dq_data }
static size_t build_openpgp_rsa_data(uint8_t *buf, size_t buf_size, size_t pri_len) {
  // Component lengths: e=4, p/q/qinv/dp/dq = pri_len each
  const size_t e_len = 4;
  const size_t comp_lens[] = {e_len, pri_len, pri_len, pri_len, pri_len, pri_len};
  const uint8_t tags[] = {0x91, 0x92, 0x93, 0x94, 0x95, 0x96};
  const uint8_t fills[] = {0x00, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5};

  size_t pos = 0;

  // 7F48 header
  buf[pos++] = 0x7F;
  buf[pos++] = 0x48;

  // Calculate inner header length
  size_t inner_len = 0;
  for (int i = 0; i < 6; i++) {
    inner_len += 1; // tag
    if (comp_lens[i] < 128)
      inner_len += 1;
    else if (comp_lens[i] < 256)
      inner_len += 2;
    else
      inner_len += 3;
  }

  // Encode inner length
  if (inner_len < 128) {
    buf[pos++] = (uint8_t)inner_len;
  } else if (inner_len < 256) {
    buf[pos++] = 0x81;
    buf[pos++] = (uint8_t)inner_len;
  } else {
    buf[pos++] = 0x82;
    buf[pos++] = (uint8_t)(inner_len >> 8);
    buf[pos++] = (uint8_t)(inner_len & 0xFF);
  }

  // Component tag+length declarations
  for (int i = 0; i < 6; i++) {
    buf[pos++] = tags[i];
    if (comp_lens[i] < 128) {
      buf[pos++] = (uint8_t)comp_lens[i];
    } else if (comp_lens[i] < 256) {
      buf[pos++] = 0x81;
      buf[pos++] = (uint8_t)comp_lens[i];
    } else {
      buf[pos++] = 0x82;
      buf[pos++] = (uint8_t)(comp_lens[i] >> 8);
      buf[pos++] = (uint8_t)(comp_lens[i] & 0xFF);
    }
  }

  // 5F48 + total data length
  size_t total_data = 0;
  for (int i = 0; i < 6; i++)
    total_data += comp_lens[i];

  buf[pos++] = 0x5F;
  buf[pos++] = 0x48;
  if (total_data < 128) {
    buf[pos++] = (uint8_t)total_data;
  } else if (total_data < 256) {
    buf[pos++] = 0x81;
    buf[pos++] = (uint8_t)total_data;
  } else {
    buf[pos++] = 0x82;
    buf[pos++] = (uint8_t)(total_data >> 8);
    buf[pos++] = (uint8_t)(total_data & 0xFF);
  }

  // Data: e (big-endian 65537 = 0x00010001)
  assert_true(pos + total_data <= buf_size);
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;
  buf[pos++] = 0x00;
  buf[pos++] = 0x01;

  // p, q, qinv, dp, dq
  for (int i = 1; i < 6; i++) {
    memset(buf + pos, fills[i], pri_len);
    pos += pri_len;
  }

  return pos;
}

// Simulate chunked feed: init with first chunk, feed remaining in chunk_size pieces
static int stream_piv_chunked(const uint8_t *data, size_t data_len, size_t chunk_size, key_type_t type) {
  memset(&key_buffer, 0, sizeof(key_buffer));
  key_buffer.meta.type = type;

  size_t first_chunk = chunk_size < data_len ? chunk_size : data_len;
  int ret = ck_parse_piv_stream_init(&key_buffer, data, first_chunk);
  if (ret < 0) return ret;

  size_t sent = first_chunk;
  while (sent < data_len) {
    size_t chunk = data_len - sent;
    if (chunk > chunk_size) chunk = chunk_size;
    ret = ck_key_stream_feed(&key_buffer, data + sent, chunk);
    if (ret < 0) return ret;
    sent += chunk;
  }

  return ck_key_stream_finalize(&key_buffer);
}

static int stream_openpgp_chunked(const uint8_t *data, size_t data_len, size_t chunk_size, key_type_t type) {
  memset(&key_buffer, 0, sizeof(key_buffer));
  key_buffer.meta.type = type;

  size_t first_chunk = chunk_size < data_len ? chunk_size : data_len;
  int ret = ck_parse_openpgp_stream_init(&key_buffer, data, first_chunk);
  if (ret < 0) return ret;

  size_t sent = (size_t)ret; // header_consumed from first chunk
  // Feed remaining bytes of first chunk
  if (sent < first_chunk) {
    ret = ck_key_stream_feed(&key_buffer, data + sent, first_chunk - sent);
    if (ret < 0) return ret;
  }
  sent = first_chunk;

  while (sent < data_len) {
    size_t chunk = data_len - sent;
    if (chunk > chunk_size) chunk = chunk_size;
    ret = ck_key_stream_feed(&key_buffer, data + sent, chunk);
    if (ret < 0) return ret;
    sent += chunk;
  }

  return ck_key_stream_finalize(&key_buffer);
}

// Verify PIV key components: data is written at offset (pri_len - comp_len)
// within the PQ_LENGTH_MAX-sized field. For full-size components, offset = 0.
static void verify_piv_components(size_t pri_len) {
  const uint8_t *fields[] = {key_buffer.rsa.p, key_buffer.rsa.q, key_buffer.rsa.dp, key_buffer.rsa.dq,
                             key_buffer.rsa.qinv};
  const uint8_t fills[] = {0xC0, 0xC1, 0xC2, 0xC3, 0xC4};

  for (int i = 0; i < 5; i++) {
    // Data at offset 0..pri_len-1 (component same size as pri_len)
    for (size_t j = 0; j < pri_len; j++) {
      assert_int_equal(fields[i][j], fills[i]);
    }
    // Trailing zeros (unused portion of PQ_LENGTH_MAX field)
    for (size_t j = pri_len; j < PQ_LENGTH_MAX; j++) {
      assert_int_equal(fields[i][j], 0);
    }
  }
}

// ============================================================
// PIV streaming tests
// ============================================================

static void test_piv_stream_rsa2048_chunk255(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_piv_chunked(data, len, 255, RSA2048), 0);
  verify_piv_components(128);
}

static void test_piv_stream_rsa2048_chunk128(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_piv_chunked(data, len, 128, RSA2048), 0);
  verify_piv_components(128);
}

static void test_piv_stream_rsa2048_chunk64(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_piv_chunked(data, len, 64, RSA2048), 0);
  verify_piv_components(128);
}

static void test_piv_stream_rsa2048_chunk1(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_piv_chunked(data, len, 1, RSA2048), 0);
  verify_piv_components(128);
}

static void test_piv_stream_rsa2048_single(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  // All data in one shot
  assert_int_equal(stream_piv_chunked(data, len, len, RSA2048), 0);
  verify_piv_components(128);
}

static void test_piv_stream_rsa4096_chunk255(void **state) {
  (void)state;
  uint8_t data[8192];
  size_t len = build_piv_rsa_data(data, sizeof(data), 256);
  assert_int_equal(stream_piv_chunked(data, len, 255, RSA4096), 0);
  verify_piv_components(256);
}

static void test_piv_stream_rsa4096_chunk1(void **state) {
  (void)state;
  uint8_t data[8192];
  size_t len = build_piv_rsa_data(data, sizeof(data), 256);
  assert_int_equal(stream_piv_chunked(data, len, 1, RSA4096), 0);
  verify_piv_components(256);
}

static void test_piv_stream_rsa3072_chunk200(void **state) {
  (void)state;
  uint8_t data[6144];
  size_t len = build_piv_rsa_data(data, sizeof(data), 192);
  assert_int_equal(stream_piv_chunked(data, len, 200, RSA3072), 0);
  verify_piv_components(192);
}

// Edge case: chunk boundary falls exactly on a TLV header
static void test_piv_stream_rsa2048_chunk131(void **state) {
  (void)state;
  // Component 1: tag(1) + len(2) + data(128) = 131 bytes
  // So chunk_size=131 means each chunk is exactly one component + header
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_piv_chunked(data, len, 131, RSA2048), 0);
  verify_piv_components(128);
}

// Edge case: chunk boundary splits a TLV header (tag in one chunk, length in next)
static void test_piv_stream_rsa2048_chunk132(void **state) {
  (void)state;
  // Component 1: 131 bytes. chunk=132 means: component 1 (131) + tag of component 2 (1)
  // Next chunk starts with the length byte of component 2
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_piv_chunked(data, len, 132, RSA2048), 0);
  verify_piv_components(128);
}

// PIV RSA-2048 with trailing policy tags (AA pin_policy, AB touch_policy)
static void test_piv_stream_rsa2048_with_policy(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_piv_rsa_data(data, sizeof(data), 128);
  // Append policy tags: AA 01 02 (PIN_POLICY_ONCE) AB 01 02 (TOUCH_POLICY_ALWAYS)
  data[len++] = 0xAA;
  data[len++] = 0x01;
  data[len++] = 0x02; // PIN_POLICY_ONCE
  data[len++] = 0xAB;
  data[len++] = 0x01;
  data[len++] = 0x02; // TOUCH_POLICY_ALWAYS
  // Chunk size 255 simulates piv-go chaining
  assert_int_equal(stream_piv_chunked(data, len, 255, RSA2048), 0);
  verify_piv_components(128);
  assert_int_equal(key_buffer.meta.pin_policy, 0x02);
  assert_int_equal(key_buffer.meta.touch_policy, 0x02);
}

// ECC key: should return KEY_ERR_DATA (not RSA)
static void test_piv_stream_ecc_fallback(void **state) {
  (void)state;
  uint8_t data[] = {0x06, 0x20}; // ECC P-256 tag + length
  memset(&key_buffer, 0, sizeof(key_buffer));
  key_buffer.meta.type = SECP256R1;
  int ret = ck_parse_piv_stream_init(&key_buffer, data, sizeof(data));
  assert_int_equal(ret, KEY_ERR_DATA); // non-RSA → fallback
}

// ============================================================
// OpenPGP streaming tests
// ============================================================

static void test_openpgp_stream_rsa2048_chunk255(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_openpgp_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_openpgp_chunked(data, len, 255, RSA2048), 0);
  // Verify p is filled with 0xC1 at offset 0..127 (pri_len - clen = 0)
  for (size_t j = 0; j < 128; j++)
    assert_int_equal(key_buffer.rsa.p[j], 0xC1);
}

static void test_openpgp_stream_rsa2048_chunk64(void **state) {
  (void)state;
  uint8_t data[4096];
  size_t len = build_openpgp_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_openpgp_chunked(data, len, 64, RSA2048), 0);
  for (size_t j = 0; j < 128; j++)
    assert_int_equal(key_buffer.rsa.p[j], 0xC1);
}

static void test_openpgp_stream_rsa2048_chunk1(void **state) {
  (void)state;
  // chunk=1 is too small to contain the OpenPGP header (minimum ~25 bytes).
  // stream_init requires buf_len >= 4, so this returns KEY_ERR_LENGTH.
  uint8_t data[4096];
  size_t len = build_openpgp_rsa_data(data, sizeof(data), 128);
  assert_int_equal(stream_openpgp_chunked(data, len, 1, RSA2048), KEY_ERR_LENGTH);
}

static void test_openpgp_stream_rsa4096_chunk255(void **state) {
  (void)state;
  uint8_t data[8192];
  size_t len = build_openpgp_rsa_data(data, sizeof(data), 256);
  assert_int_equal(stream_openpgp_chunked(data, len, 255, RSA4096), 0);
  for (size_t j = 0; j < PQ_LENGTH_MAX; j++)
    assert_int_equal(key_buffer.rsa.p[j], 0xC1);
}

static void test_openpgp_stream_ecc_fallback(void **state) {
  (void)state;
  // Not a valid OpenPGP RSA key template — should return negative error
  uint8_t data[] = {0x00, 0x00};
  memset(&key_buffer, 0, sizeof(key_buffer));
  key_buffer.meta.type = SECP256R1;
  int ret = ck_parse_openpgp_stream_init(&key_buffer, data, sizeof(data));
  assert_true(ret < 0);
}

// ============================================================
// Test runner
// ============================================================

int main(void) {
  const struct CMUnitTest tests[] = {
      // PIV streaming
      cmocka_unit_test(test_piv_stream_rsa2048_chunk255),
      cmocka_unit_test(test_piv_stream_rsa2048_chunk128),
      cmocka_unit_test(test_piv_stream_rsa2048_chunk64),
      cmocka_unit_test(test_piv_stream_rsa2048_chunk1),
      cmocka_unit_test(test_piv_stream_rsa2048_single),
      cmocka_unit_test(test_piv_stream_rsa4096_chunk255),
      cmocka_unit_test(test_piv_stream_rsa4096_chunk1),
      cmocka_unit_test(test_piv_stream_rsa3072_chunk200),
      cmocka_unit_test(test_piv_stream_rsa2048_chunk131),
      cmocka_unit_test(test_piv_stream_rsa2048_chunk132),
      cmocka_unit_test(test_piv_stream_rsa2048_with_policy),
      cmocka_unit_test(test_piv_stream_ecc_fallback),
      // OpenPGP streaming
      cmocka_unit_test(test_openpgp_stream_rsa2048_chunk255),
      cmocka_unit_test(test_openpgp_stream_rsa2048_chunk64),
      cmocka_unit_test(test_openpgp_stream_rsa2048_chunk1),
      cmocka_unit_test(test_openpgp_stream_rsa4096_chunk255),
      cmocka_unit_test(test_openpgp_stream_ecc_fallback),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
