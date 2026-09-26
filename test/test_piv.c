// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <apdu.h>
#include <aes.h>
#include <bd/lfs_filebd.h>
#include <cmocka.h>
#include <crypto-util.h>
#include <device.h>
#include <device-config.h>
#include <firmware-version.h>
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <memzero.h>
#include <ml-kem-768.h>
#include <piv.h>
#include <platform-config.h>
#include <rsa.h>
#include <sha.h>
#include <sm2_ke.h>
#include <sm3.h>
#include <string.h>

#include "ecdsa-generic.h"
#include "nist256p1.h"
#include "piv_attestation_fixture.h"

extern void set_admin_status(int status);


static void test_helper_resp(uint8_t *data, size_t data_len, uint8_t ins, uint8_t p1, uint8_t p2,
                             uint16_t expected_error, uint8_t *expected_resp, size_t resp_len) {
  uint8_t c_buf[1024], r_buf[1024];
  // only tag, no length nor data
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  capdu->ins = ins;
  capdu->p1 = p1;
  capdu->p2 = p2;
  capdu->lc = data_len;
  if (data_len > 0) {
    // re alloc to help asan find overflow error
    capdu->data = malloc(data_len);
    memcpy(capdu->data, data, data_len);
  } else {
    // when lc = 0, data should never be read
    capdu->data = NULL;
  }

  piv_process_apdu(capdu, rapdu);
  if (data_len > 0) {
    free(capdu->data);
  }
  assert_int_equal(rapdu->sw, expected_error);
  print_hex(RDATA, LL);
  if (expected_resp != NULL) {
    assert_int_equal(rapdu->len, resp_len);
    assert_memory_equal(RDATA, expected_resp, resp_len);
  }
}

static void test_helper(uint8_t *data, size_t data_len, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t expected_error) {
  // don't check resp
  test_helper_resp(data, data_len, ins, p1, p2, expected_error, NULL, 0);
}

typedef struct {
  const uint8_t *value;
  size_t value_len;
  size_t total_len;
  uint8_t tag;
} test_der_tlv_t;

static int test_der_read(const uint8_t *data, size_t len, test_der_tlv_t *tlv) {
  if (len < 2) return -1;
  size_t header_len = 2;
  size_t value_len = 0;
  if ((data[1] & 0x80u) == 0) {
    value_len = data[1];
  } else {
    const uint8_t count = data[1] & 0x7Fu;
    if (count == 0 || count > 2 || len < 2u + count) return -1;
    header_len += count;
    for (uint8_t i = 0; i < count; ++i)
      value_len = (value_len << 8u) | data[2 + i];
    if (value_len < 0x80) return -1;
  }
  if (value_len > len - header_len) return -1;
  *tlv = (test_der_tlv_t){
      .value = data + header_len, .value_len = value_len, .total_len = header_len + value_len, .tag = data[0]};
  return 0;
}

static const uint8_t *test_find_bytes(const uint8_t *haystack, size_t haystack_len, const uint8_t *needle,
                                      size_t needle_len) {
  if (needle_len == 0 || needle_len > haystack_len) return NULL;
  for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
    if (memcmp(haystack + i, needle, needle_len) == 0) return haystack + i;
  }
  return NULL;
}

static void piv_test_remove_attestation_data(void) {
  if (get_file_size("piv-kf9") >= 0) assert_int_equal(remove_file("piv-kf9"), 0);
  if (get_file_size("piv-cf9") >= 0) assert_int_equal(remove_file("piv-cf9"), 0);
}

static void piv_test_provision_attestation_key(void) {
  ck_key_t key = {.meta = {.type = SECP256R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  memcpy(key.ecc.pri, piv_test_f9_private_key, sizeof(piv_test_f9_private_key));
  memcpy(key.ecc.pub, piv_test_f9_public_key, sizeof(piv_test_f9_public_key));
  assert_int_equal(ck_write_key("piv-kf9", &key), 0);
}

static void piv_test_provision_attestation_cert(void) {
  enum { CERT_LEN = sizeof(piv_test_f9_certificate), OBJECT_CONTENT_LEN = 4 + CERT_LEN + 3 + 2 };
  uint8_t object[4 + OBJECT_CONTENT_LEN];
  size_t off = 0;
  object[off++] = 0x53;
  object[off++] = 0x82;
  object[off++] = (uint8_t)(OBJECT_CONTENT_LEN >> 8);
  object[off++] = (uint8_t)OBJECT_CONTENT_LEN;
  object[off++] = 0x70;
  object[off++] = 0x82;
  object[off++] = (uint8_t)(CERT_LEN >> 8);
  object[off++] = (uint8_t)CERT_LEN;
  memcpy(object + off, piv_test_f9_certificate, CERT_LEN);
  off += CERT_LEN;
  memcpy(object + off, ((const uint8_t[]){0x71, 0x01, 0x00, 0xFE, 0x00}), 5);
  off += 5;
  assert_int_equal(off, sizeof(object));
  assert_int_equal(write_file("piv-cf9", object, 0, sizeof(object), 1), 0);
}

static size_t piv_test_collect_attestation(uint8_t slot, uint8_t *certificate, size_t capacity, uint16_t *sw) {
  uint8_t chunk[APDU_BUFFER_SIZE];
  RAPDU rapdu = {.data = chunk};
  RAPDU_CHAINING chaining = {.rapdu.data = chunk};
  CAPDU command = {
      .data = NULL, .cla = 0x00, .ins = PIV_INS_ATTEST, .p1 = slot, .p2 = 0x00, .lc = 0, .le = APDU_BUFFER_SIZE};

  piv_process_apdu_message(&chaining, &command, &rapdu);
  size_t total = 0;
  while (rapdu.sw == SW_NO_ERROR || (rapdu.sw & 0xFF00u) == 0x6100u) {
    assert_true(total + rapdu.len <= capacity);
    memcpy(certificate + total, rapdu.data, rapdu.len);
    total += rapdu.len;
    if (rapdu.sw == SW_NO_ERROR) break;
    command = (CAPDU){.data = NULL, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .lc = 0, .le = APDU_BUFFER_SIZE};
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu_message(&chaining, &command, &rapdu);
  }
  *sw = rapdu.sw;
  return total;
}


static uint16_t piv_test_send_chained(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t data_len,
                                      uint8_t *response, uint16_t *response_len) {
  size_t offset = 0;
  RAPDU rapdu = {.data = response};
  while (offset < data_len) {
    const uint16_t n = (uint16_t)MIN((size_t)240, data_len - offset);
    CAPDU command = {.data = (uint8_t *)data + offset,
                     .cla = offset + n < data_len ? 0x10 : 0x00,
                     .ins = ins,
                     .p1 = p1,
                     .p2 = p2,
                     .lc = n,
                     .le = APDU_BUFFER_SIZE};
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu(&command, &rapdu);
    if (offset + n < data_len) assert_int_equal(rapdu.sw, SW_NO_ERROR);
    offset += n;
  }
  *response_len = rapdu.len;
  return rapdu.sw;
}













static test_der_tlv_t piv_test_der_take(const uint8_t **cursor, size_t *remaining, uint8_t tag) {
  test_der_tlv_t tlv;
  assert_int_equal(test_der_read(*cursor, *remaining, &tlv), 0);
  assert_int_equal(tlv.tag, tag);
  *cursor += tlv.total_len;
  *remaining -= tlv.total_len;
  return tlv;
}

static void piv_test_der_integer_to_p256(const test_der_tlv_t *integer, uint8_t out[32]) {
  assert_int_equal(integer->tag, 0x02);
  assert_true(integer->value_len > 0 && integer->value_len <= 33);
  const uint8_t *value = integer->value;
  size_t value_len = integer->value_len;
  if (value_len == 33) {
    assert_int_equal(value[0], 0);
    assert_true((value[1] & 0x80u) != 0);
    ++value;
    --value_len;
  } else {
    assert_int_equal(value[0] & 0x80u, 0);
    if (value_len > 1) assert_true(value[0] != 0);
  }
  memset(out, 0, 32);
  memcpy(out + 32 - value_len, value, value_len);
}

static void piv_test_assert_attestation_signature(const uint8_t *tbs, size_t tbs_len,
                                                  const test_der_tlv_t *signature_value) {
  assert_true(signature_value->value_len > 1);
  assert_int_equal(signature_value->value[0], 0);

  test_der_tlv_t signature;
  assert_int_equal(test_der_read(signature_value->value + 1, signature_value->value_len - 1, &signature), 0);
  assert_int_equal(signature.tag, 0x30);
  assert_int_equal(signature.total_len, signature_value->value_len - 1);

  const uint8_t *cursor = signature.value;
  size_t remaining = signature.value_len;
  const test_der_tlv_t r = piv_test_der_take(&cursor, &remaining, 0x02);
  const test_der_tlv_t s = piv_test_der_take(&cursor, &remaining, 0x02);
  assert_int_equal(remaining, 0);

  uint8_t raw_signature[64], digest[SHA256_DIGEST_LENGTH];
  piv_test_der_integer_to_p256(&r, raw_signature);
  piv_test_der_integer_to_p256(&s, raw_signature + 32);
  sha256_raw(tbs, tbs_len, digest);
  assert_int_equal(ecdsa_verify_digest(&nist256p1, piv_test_f9_public_key, raw_signature, digest), 0);
}

static void piv_test_assert_attestation_spki(const test_der_tlv_t *spki, ck_key_t *target,
                                             const uint8_t *expected_oid, size_t expected_oid_len) {
  static const uint8_t oid_ec_public_key[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
  static const uint8_t oid_rsa[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

  const uint8_t *cursor = spki->value;
  size_t remaining = spki->value_len;
  const test_der_tlv_t algorithm = piv_test_der_take(&cursor, &remaining, 0x30);
  const test_der_tlv_t public_key = piv_test_der_take(&cursor, &remaining, 0x03);
  assert_int_equal(remaining, 0);

  const uint8_t *algorithm_cursor = algorithm.value;
  size_t algorithm_remaining = algorithm.value_len;
  const test_der_tlv_t algorithm_oid = piv_test_der_take(&algorithm_cursor, &algorithm_remaining, 0x06);

  assert_true(public_key.value_len > 1);
  assert_int_equal(public_key.value[0], 0);
  if (IS_RSA(target->meta.type)) {
    assert_int_equal(algorithm_oid.total_len, sizeof(oid_rsa));
    assert_memory_equal(algorithm.value, oid_rsa, sizeof(oid_rsa));
    const test_der_tlv_t null_parameter = piv_test_der_take(&algorithm_cursor, &algorithm_remaining, 0x05);
    assert_int_equal(null_parameter.value_len, 0);
    assert_int_equal(algorithm_remaining, 0);

    test_der_tlv_t rsa_public;
    assert_int_equal(test_der_read(public_key.value + 1, public_key.value_len - 1, &rsa_public), 0);
    assert_int_equal(rsa_public.tag, 0x30);
    assert_int_equal(rsa_public.total_len, public_key.value_len - 1);
    const uint8_t *rsa_cursor = rsa_public.value;
    size_t rsa_remaining = rsa_public.value_len;
    const test_der_tlv_t modulus = piv_test_der_take(&rsa_cursor, &rsa_remaining, 0x02);
    const test_der_tlv_t exponent = piv_test_der_take(&rsa_cursor, &rsa_remaining, 0x02);
    assert_int_equal(rsa_remaining, 0);

    uint8_t expected_modulus[RSA_N_BIT_MAX / 8];
    const size_t modulus_len = PUBLIC_KEY_LENGTH[target->meta.type];
    assert_int_equal(rsa_get_public_key(&target->rsa, expected_modulus), 0);
    const uint8_t *encoded_modulus = modulus.value;
    size_t encoded_modulus_len = modulus.value_len;
    if (encoded_modulus_len == modulus_len + 1) {
      assert_int_equal(encoded_modulus[0], 0);
      ++encoded_modulus;
      --encoded_modulus_len;
    }
    assert_int_equal(encoded_modulus_len, modulus_len);
    assert_memory_equal(encoded_modulus, expected_modulus, modulus_len);

    size_t exponent_off = 0;
    while (exponent_off + 1 < E_LENGTH && target->rsa.e[exponent_off] == 0)
      ++exponent_off;
    assert_int_equal(exponent.value_len, E_LENGTH - exponent_off);
    assert_memory_equal(exponent.value, target->rsa.e + exponent_off, exponent.value_len);
  } else if (IS_SHORT_WEIERSTRASS(target->meta.type)) {
    assert_int_equal(algorithm_oid.total_len, sizeof(oid_ec_public_key));
    assert_memory_equal(algorithm.value, oid_ec_public_key, sizeof(oid_ec_public_key));
    const test_der_tlv_t curve_oid = piv_test_der_take(&algorithm_cursor, &algorithm_remaining, 0x06);
    assert_int_equal(curve_oid.total_len, expected_oid_len);
    assert_memory_equal(curve_oid.value - 2, expected_oid, expected_oid_len);
    assert_int_equal(algorithm_remaining, 0);
    assert_int_equal(public_key.value_len, 2 + PUBLIC_KEY_LENGTH[target->meta.type]);
    assert_int_equal(public_key.value[1], 0x04);
    assert_memory_equal(public_key.value + 2, target->ecc.pub, PUBLIC_KEY_LENGTH[target->meta.type]);
  } else if (IS_MLDSA(target->meta.type)) {
    static uint8_t expected_public[MLDSA_PK_BYTES];
    assert_int_equal(algorithm_oid.total_len, expected_oid_len);
    assert_memory_equal(algorithm.value, expected_oid, expected_oid_len);
    assert_int_equal(algorithm_remaining, 0);
    assert_int_equal(public_key.value_len, 1 + MLDSA_PK_BYTES);
    assert_int_equal(ml_dsa_65_keygen(expected_public, NULL, NULL, target->mldsa.seed), 0);
    assert_memory_equal(public_key.value + 1, expected_public, sizeof(expected_public));
    memzero(expected_public, sizeof(expected_public));
  } else {
    assert_int_equal(algorithm_oid.total_len, expected_oid_len);
    assert_memory_equal(algorithm.value, expected_oid, expected_oid_len);
    assert_int_equal(algorithm_remaining, 0);
    assert_int_equal(public_key.value_len, 1 + PUBLIC_KEY_LENGTH[target->meta.type]);
    uint8_t expected_public[32];
    memcpy(expected_public, target->ecc.pub, sizeof(expected_public));
    if (target->meta.type == X25519) swap_big_number_endian(expected_public);
    assert_memory_equal(public_key.value + 1, expected_public, sizeof(expected_public));
  }
}

static void piv_test_assert_attestation_certificate(const uint8_t *certificate, size_t certificate_len,
                                                    ck_key_t *target, const uint8_t *expected_oid,
                                                    size_t expected_oid_len) {
  static const uint8_t ecdsa_with_sha256[] = {0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
                                              0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
  test_der_tlv_t cert;
  assert_int_equal(test_der_read(certificate, certificate_len, &cert), 0);
  assert_int_equal(cert.tag, 0x30);
  assert_int_equal(cert.total_len, certificate_len);

  const uint8_t *cursor = cert.value;
  size_t remaining = cert.value_len;
  const uint8_t *tbs_start = cursor;
  const test_der_tlv_t tbs = piv_test_der_take(&cursor, &remaining, 0x30);
  const test_der_tlv_t signature_algorithm = piv_test_der_take(&cursor, &remaining, 0x30);
  assert_int_equal(signature_algorithm.total_len, sizeof(ecdsa_with_sha256));
  assert_memory_equal(signature_algorithm.value - 2, ecdsa_with_sha256, sizeof(ecdsa_with_sha256));
  const test_der_tlv_t signature_value = piv_test_der_take(&cursor, &remaining, 0x03);
  assert_int_equal(remaining, 0);

  cursor = tbs.value;
  remaining = tbs.value_len;
  (void)piv_test_der_take(&cursor, &remaining, 0xA0);
  (void)piv_test_der_take(&cursor, &remaining, 0x02);
  const test_der_tlv_t tbs_signature_algorithm = piv_test_der_take(&cursor, &remaining, 0x30);
  assert_int_equal(tbs_signature_algorithm.total_len, sizeof(ecdsa_with_sha256));
  assert_memory_equal(tbs_signature_algorithm.value - 2, ecdsa_with_sha256, sizeof(ecdsa_with_sha256));
  (void)piv_test_der_take(&cursor, &remaining, 0x30);
  (void)piv_test_der_take(&cursor, &remaining, 0x30);
  (void)piv_test_der_take(&cursor, &remaining, 0x30);
  const test_der_tlv_t spki = piv_test_der_take(&cursor, &remaining, 0x30);
  (void)piv_test_der_take(&cursor, &remaining, 0xA3);
  assert_int_equal(remaining, 0);

  piv_test_assert_attestation_spki(&spki, target, expected_oid, expected_oid_len);
  piv_test_assert_attestation_signature(tbs_start, tbs.total_len, &signature_value);
}






static void test_piv_migrates_legacy_management_key_types(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  enum { LEGACY_TDEA = 11, LEGACY_AES128 = 12, LEGACY_AES256 = 13 };
  static const struct {
    unsigned legacy_type;
    key_type_t current_type;
    size_t key_len;
  } cases[] = {
      {LEGACY_TDEA, TDEA, 24},
      {LEGACY_AES128, AES128, 16},
      {LEGACY_AES256, AES256, 32},
  };
  uint8_t key_material[32] = {0};
  key_meta_t meta;
  assert_true(ck_read_key_metadata("piv-k9b", &meta) >= 0);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    meta.type = (key_type_t)cases[i].legacy_type;
    assert_int_equal(write_file("piv-k9b", key_material, 0, cases[i].key_len, 1), 0);
    assert_true(ck_write_key_metadata("piv-k9b", &meta) >= 0);
    assert_int_equal(piv_install(0), 0);
    assert_true(ck_read_key_metadata("piv-k9b", &meta) >= 0);
    assert_int_equal(meta.type, cases[i].current_type);
  }

  assert_int_equal(piv_install(1), 0);
}

static void test_piv_startup_preserves_state_when_platform_config_is_invalid(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  static const uint8_t key_sentinel[] = {0x4B, 0x45, 0x59};
  static const uint8_t cert_sentinel[] = {0x43, 0x45, 0x52, 0x54};
  assert_int_equal(write_file("piv-k9a", key_sentinel, 0, sizeof(key_sentinel), 1), 0);
  assert_int_equal(write_file("piv-c9a", cert_sentinel, 0, sizeof(cert_sentinel), 1), 0);

  uint8_t valid_config[PLATFORM_CONFIG_PAGE_SIZE];
  uint8_t invalid_config[PLATFORM_CONFIG_PAGE_SIZE];
  assert_int_equal(platform_config_page_read(0, valid_config, sizeof(valid_config)), 0);
  memcpy(invalid_config, valid_config, sizeof(invalid_config));
  invalid_config[sizeof(invalid_config) - 1] ^= 0x01;
  assert_int_equal(platform_config_page_write(invalid_config, sizeof(invalid_config)), 0);

  assert_int_equal(piv_install(0), -1);
  uint8_t actual[sizeof(cert_sentinel)];
  assert_int_equal(read_file("piv-k9a", actual, 0, sizeof(key_sentinel)), sizeof(key_sentinel));
  assert_memory_equal(actual, key_sentinel, sizeof(key_sentinel));
  assert_int_equal(read_file("piv-c9a", actual, 0, sizeof(cert_sentinel)), sizeof(cert_sentinel));
  assert_memory_equal(actual, cert_sentinel, sizeof(cert_sentinel));

  assert_int_equal(platform_config_page_write(valid_config, sizeof(valid_config)), 0);
  assert_int_equal(piv_install(1), 0);
}









static void test_piv_get_metadata_directory(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  ck_key_t key;
  ck_key_init_empty(&key, SECP256R1, SIGN, PIN_POLICY_ONCE, TOUCH_POLICY_NEVER);
  key.meta.origin = KEY_ORIGIN_GENERATED;
  assert_int_equal(ck_write_key("piv-k9a", &key), 0);

  const uint8_t cert = 0x53;
  assert_int_equal(write_file("piv-c9c", &cert, 0, sizeof(cert), 1), 0);
  assert_int_equal(write_file("piv-c9d", NULL, 0, 0, 1), 0); // Empty certificate files do not count.

  ck_key_init_empty(&key, SECP384R1, KEY_USAGE_ANY, PIN_POLICY_ALWAYS, TOUCH_POLICY_CACHED);
  key.meta.origin = KEY_ORIGIN_IMPORTED;
  assert_int_equal(ck_write_key("piv-k82", &key), 0);
  assert_int_equal(write_file("piv-c82", &cert, 0, sizeof(cert), 1), 0);
  memzero(&key, sizeof(key));

  uint8_t response[APDU_BUFFER_SIZE];
  RAPDU R = {.data = response};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x01, .p2 = 0x00, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  static const uint8_t expected[] = {
      0x01, 0x01, 0x01, 0x02, 18,
      0x9A, 0x01, 0x11, KEY_ORIGIN_GENERATED, PIN_POLICY_ONCE, TOUCH_POLICY_NEVER,
      0x9C, 0x02, 0x00, 0x00, 0x00, 0x00,
      0x82, 0x03, 0x14, KEY_ORIGIN_IMPORTED, PIN_POLICY_ALWAYS, TOUCH_POLICY_CACHED,
  };
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, expected, sizeof(expected));

  // The maximum 24-entry directory still uses a single-byte length and fits in one response.
  assert_int_equal(piv_install(1), 0);
  static const uint8_t slots[] = {0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x83, 0x84, 0x85,
                                  0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
                                  0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95};
  static const char hex[] = "0123456789abcdef";
  char cert_path[] = "piv-c00";
  for (size_t i = 0; i < sizeof(slots); ++i) {
    cert_path[5] = hex[slots[i] >> 4u];
    cert_path[6] = hex[slots[i] & 0x0Fu];
    assert_int_equal(write_file(cert_path, &cert, 0, sizeof(cert), 1), 0);
  }

  R.len = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 5 + sizeof(slots) * 6);
  assert_memory_equal(R.data, ((const uint8_t[]){0x01, 0x01, 0x01, 0x02, 0x90}), 5);
  for (size_t i = 0; i < sizeof(slots); ++i) {
    const uint8_t expected_entry[] = {slots[i], 0x02, 0x00, 0x00, 0x00, 0x00};
    assert_memory_equal(R.data + 5 + i * sizeof(expected_entry), expected_entry, sizeof(expected_entry));
  }

  C.p2 = 0x01;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);
  C.p2 = 0x00;
  C.data = (uint8_t *)&cert;
  C.lc = 1;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);
  C.data = NULL;
  C.lc = 0;
  C.p1 = 0x02;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  assert_int_equal(piv_install(1), 0);
}


static void test_piv_move_delete_key_extension(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  ck_key_t key = {.meta = {.type = SECP256R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-k9a", &key), 0);
  ck_key_t original_key = key;

  uint8_t cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xA5};
  set_admin_status(1);
  test_helper(cert, sizeof(cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  set_admin_status(0);

  uint8_t r_buf[256];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9A, .lc = 0};

  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  set_admin_status(1);

  C = (CAPDU){.data = r_buf, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9A, .lc = 1};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9B, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9B, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9D, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9A, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  assert_int_equal(ck_write_key("piv-k9c", &key), 0);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9C, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9C, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  ck_key_t moved_key;
  assert_true(ck_read_key("piv-k9c", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));

  assert_int_equal(get_file_size("piv-k9a"), LFS_ERR_NOENT);

  // Simulate reboot: an absent ordinary key slot is valid initialized state.
  assert_int_equal(piv_install(0), 0);
  assert_true(ck_read_key("piv-k9c", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));
  assert_int_equal(get_file_size("piv-k9a"), LFS_ERR_NOENT);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  set_admin_status(1);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x95, .p2 = 0x9C, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key("piv-k95", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));
  assert_int_equal(get_file_size("piv-k9c"), LFS_ERR_NOENT);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9D, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-k95") < 0);
  assert_true(ck_read_key("piv-k9d", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x9D, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  uint8_t get_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05};
  uint8_t expected_cert[] = {0x53, 0x01, 0xA5};
  C = (CAPDU){.data = get_cert,
              .cla = 0x00,
              .ins = PIV_INS_GET_DATA,
              .p1 = 0x3F,
              .p2 = 0xFF,
              .lc = sizeof(get_cert),
              .le = 256};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected_cert));
  assert_memory_equal(R.data, expected_cert, sizeof(expected_cert));

  piv_install(1);
}

static void test_piv_attestation_certificate(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  piv_test_remove_attestation_data();

  ck_key_t target = {.meta = {.type = SECP256R1,
                              .origin = KEY_ORIGIN_GENERATED,
                              .usage = SIGN,
                              .pin_policy = PIN_POLICY_ALWAYS,
                              .touch_policy = TOUCH_POLICY_CACHED}};
  assert_int_equal(ck_generate_key(&target), 0);
  assert_int_equal(ck_write_key("piv-k9a", &target), 0);

  uint8_t certificate[1536];
  uint16_t sw;
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);

  piv_test_provision_attestation_key();
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);

  piv_test_provision_attestation_cert();
  assert_int_equal(remove_file("piv-kf9"), 0);
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);
  piv_test_provision_attestation_key();
  const size_t certificate_len = piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw);
  assert_int_equal(sw, SW_NO_ERROR);
  assert_true(certificate_len > 256);
  static const uint8_t oid_p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  piv_test_assert_attestation_certificate(certificate, certificate_len, &target, oid_p256, sizeof(oid_p256));

  test_der_tlv_t cert;
  assert_int_equal(test_der_read(certificate, certificate_len, &cert), 0);
  assert_int_equal(cert.tag, 0x30);
  assert_int_equal(cert.total_len, certificate_len);

  test_der_tlv_t tbs;
  assert_int_equal(test_der_read(cert.value, cert.value_len, &tbs), 0);
  assert_int_equal(tbs.tag, 0x30);
  const uint8_t *cursor = tbs.value;
  size_t remaining = tbs.value_len;
  test_der_tlv_t field;
  for (unsigned i = 0; i < 6; ++i) {
    assert_int_equal(test_der_read(cursor, remaining, &field), 0);
    if (i == 0) assert_int_equal(field.tag, 0xA0); // version
    if (i == 1) assert_int_equal(field.tag, 0x02); // serial
    if (i == 2) assert_int_equal(field.tag, 0x30); // signature algorithm
    if (i == 3) {                                  // issuer: F9 certificate subject
      static const uint8_t issuer_cn[] = "CanoKey PIV F9 Test";
      assert_non_null(test_find_bytes(cursor, field.total_len, issuer_cn, sizeof(issuer_cn) - 1));
    }
    if (i == 4) { // validity copied from the F9 certificate
      static const uint8_t not_before[] = "260817121509Z";
      static const uint8_t not_after[] = "360814121509Z";
      assert_non_null(test_find_bytes(cursor, field.total_len, not_before, sizeof(not_before) - 1));
      assert_non_null(test_find_bytes(cursor, field.total_len, not_after, sizeof(not_after) - 1));
    }
    if (i == 5) { // generated subject
      static const uint8_t subject_cn[] = "CanoKey PIV Attestation 9a";
      assert_non_null(test_find_bytes(cursor, field.total_len, subject_cn, sizeof(subject_cn) - 1));
    }
    cursor += field.total_len;
    remaining -= field.total_len;
  }

  // SubjectPublicKeyInfo contains the generated target key, not the F9 key.
  assert_int_equal(test_der_read(cursor, remaining, &field), 0);
  assert_int_equal(field.tag, 0x30);
  uint8_t uncompressed_target[1 + PUBLIC_KEY_LENGTH[SECP256R1]];
  uncompressed_target[0] = 0x04;
  memcpy(uncompressed_target + 1, target.ecc.pub, PUBLIC_KEY_LENGTH[SECP256R1]);
  assert_non_null(test_find_bytes(cursor, field.total_len, uncompressed_target, sizeof(uncompressed_target)));
  cursor += field.total_len;
  remaining -= field.total_len;

  // Only the registered CanoKey PIV serial and policy extensions are emitted.
  assert_int_equal(test_der_read(cursor, remaining, &field), 0);
  assert_int_equal(field.tag, 0xA3);
  static const uint8_t serial_oid[] = {
      0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x84, 0x88, 0x2A, 0x01, 0x01};
  static const uint8_t policy_extension[] = {0x06,
                                             0x0A,
                                             0x2B,
                                             0x06,
                                             0x01,
                                             0x04,
                                             0x01,
                                             0x84,
                                             0x88,
                                             0x2A,
                                             0x01,
                                             0x02,
                                             0x04,
                                             0x02,
                                             PIN_POLICY_ALWAYS,
                                             TOUCH_POLICY_CACHED};
  assert_non_null(test_find_bytes(cursor, field.total_len, serial_oid, sizeof(serial_oid)));
  assert_non_null(test_find_bytes(cursor, field.total_len, policy_extension, sizeof(policy_extension)));
  uint8_t device_serial[4];
  device_config_fill_serial(device_serial);
  assert_non_null(test_find_bytes(cursor, field.total_len, device_serial, sizeof(device_serial)));

  // Imported target keys are intentionally not attestable.
  target.meta.origin = KEY_ORIGIN_IMPORTED;
  assert_int_equal(ck_write_key("piv-k9a", &target), 0);
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);

  // F9 key and certificate survive a PIV reset, while ordinary target keys do not.
  assert_int_equal(piv_install(1), 0);
  assert_true(get_file_size("piv-kf9") > 0);
  assert_true(get_file_size("piv-cf9") > 0);
  target.meta.origin = KEY_ORIGIN_GENERATED;
  assert_int_equal(ck_generate_key(&target), 0);
  assert_int_equal(ck_write_key("piv-k9a", &target), 0);
  assert_true(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw) > 256);
  assert_int_equal(sw, SW_NO_ERROR);
}

static void test_piv_attestation_f9_policy(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  piv_test_remove_attestation_data();

  uint8_t response[512];
  RAPDU R = {.data = response};
  uint8_t generate_p384[] = {0xAC, 0x03, 0x80, 0x01, 0x14};
  CAPDU C = {.data = generate_p384,
             .cla = 0x00,
             .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
             .p1 = 0x00,
             .p2 = 0xF9,
             .lc = sizeof(generate_p384)};

  set_admin_status(0);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_IMPORT_ASYMMETRIC_KEY, .p1 = 0x14, .p2 = 0xF9, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  uint8_t generate_p256[] = {0xAC, 0x03, 0x80, 0x01, 0x11};
  C = (CAPDU){.data = generate_p256,
              .cla = 0x00,
              .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
              .p1 = 0x00,
              .p2 = 0xF9,
              .lc = sizeof(generate_p256)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  key_meta_t f9_meta;
  assert_true(ck_read_key_metadata("piv-kf9", &f9_meta) >= 0);
  assert_int_equal(f9_meta.type, SECP256R1);
  assert_int_equal(f9_meta.origin, KEY_ORIGIN_GENERATED);
  assert_int_equal(f9_meta.usage, SIGN);

  uint8_t import_p256[2 + sizeof(piv_test_f9_private_key)] = {0x06, sizeof(piv_test_f9_private_key)};
  memcpy(import_p256 + 2, piv_test_f9_private_key, sizeof(piv_test_f9_private_key));
  C = (CAPDU){.data = import_p256,
              .cla = 0x00,
              .ins = PIV_INS_IMPORT_ASYMMETRIC_KEY,
              .p1 = 0x11,
              .p2 = 0xF9,
              .lc = sizeof(import_p256)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key_metadata("piv-kf9", &f9_meta) >= 0);
  assert_int_equal(f9_meta.origin, KEY_ORIGIN_IMPORTED);
  assert_int_equal(remove_file("piv-kf9"), 0);

  ck_key_t source = {.meta = {.type = SECP384R1,
                              .origin = KEY_ORIGIN_GENERATED,
                              .usage = SIGN,
                              .pin_policy = PIN_POLICY_ONCE,
                              .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&source), 0);
  assert_int_equal(ck_write_key("piv-k9a", &source), 0);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xF9, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  source.meta.type = SECP256R1;
  assert_int_equal(ck_generate_key(&source), 0);
  assert_int_equal(ck_write_key("piv-k9a", &source), 0);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);
  assert_int_equal(get_file_size("piv-kf9"), LFS_ERR_NOENT);

  // The F9 certificate object is writable only with management authentication.
  uint8_t delete_cert[] = {0x5C, 0x03, 0x5F, 0xFF, 0x01, 0x53, 0x00};
  set_admin_status(0);
  test_helper(delete_cert, sizeof(delete_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);
  set_admin_status(1);
  test_helper(delete_cert, sizeof(delete_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
}

static void test_piv_attestation_all_target_algorithms(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  piv_test_remove_attestation_data();
  piv_test_provision_attestation_key();
  piv_test_provision_attestation_cert();

  static const uint8_t oid_rsa[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
  static const uint8_t oid_p256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
  static const uint8_t oid_k256[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};
  static const uint8_t oid_p384[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22};
  static const uint8_t oid_p521[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23};
  static const uint8_t oid_sm2[] = {0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D};
  static const uint8_t oid_ed25519[] = {0x06, 0x03, 0x2B, 0x65, 0x70};
  static const uint8_t oid_x25519[] = {0x06, 0x03, 0x2B, 0x65, 0x6E};
  static const uint8_t oid_mldsa65[] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
  static const struct {
    key_type_t type;
    const uint8_t *oid;
    size_t oid_len;
  } cases[] = {
      {RSA2048, oid_rsa, sizeof(oid_rsa)},      {RSA3072, oid_rsa, sizeof(oid_rsa)},
      {RSA4096, oid_rsa, sizeof(oid_rsa)},      {SECP256R1, oid_p256, sizeof(oid_p256)},
      {SECP384R1, oid_p384, sizeof(oid_p384)},  {ED25519, oid_ed25519, sizeof(oid_ed25519)},
      {X25519, oid_x25519, sizeof(oid_x25519)}, {SECP256K1, oid_k256, sizeof(oid_k256)},
      {SECP521R1, oid_p521, sizeof(oid_p521)},  {SM2, oid_sm2, sizeof(oid_sm2)},
      {MLDSA65, oid_mldsa65, sizeof(oid_mldsa65)},
  };

  static uint8_t certificate[3072];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    ck_key_t target = {.meta = {.type = cases[i].type,
                                .origin = KEY_ORIGIN_GENERATED,
                                .usage = SIGN,
                                .pin_policy = PIN_POLICY_ONCE,
                                .touch_policy = TOUCH_POLICY_NEVER}};
    assert_int_equal(ck_generate_key(&target), 0);
    assert_int_equal(ck_write_key("piv-k9a", &target), 0);
    uint16_t sw;
    if (cases[i].type == MLDSA65) {
      assert_int_equal(remove_file("piv-kf9"), 0);
      assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
      assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);
      piv_test_provision_attestation_key();
    }
    const size_t certificate_len = piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw);
    assert_int_equal(sw, SW_NO_ERROR);
    piv_test_assert_attestation_certificate(certificate, certificate_len, &target, cases[i].oid, cases[i].oid_len);
  }
}











// ---- SM2 key agreement (GM/T 0003.2) ----

// Static and ephemeral key material from the official GM/T 0003.5-2012 Annex A
// example (same constants as canokey-crypto/test/test_sm2_ke.c). The PIV GA
// always generates the card-side ephemeral itself, so the fixed session key of
// the Annex A example cannot be reproduced through this interface; instead the
// tests below verify the card against the host-side sm2_key_exchange()
// reference using these fixed keys for the host-played roles.
static const uint8_t piv_sm2ka_da[32] = "\x81\xEB\x26\xE9\x41\xBB\x5A\xF1\x6D\xF1\x16\x49\x5F\x90\x69\x52"
                                       "\x72\xAE\x2C\xD6\x3D\x6C\x4A\xE1\x67\x84\x18\xBE\x48\x23\x00\x29";
static const uint8_t piv_sm2ka_pa[64] = "\x16\x0E\x12\x89\x7D\xF4\xED\xB6\x1D\xD8\x12\xFE\xB9\x67\x48\xFB"
                                       "\xD3\xCC\xF4\xFF\xE2\x6A\xA6\xF6\xDB\x95\x40\xAF\x49\xC9\x42\x32"
                                       "\x4A\x7D\xAD\x08\xBB\x9A\x45\x95\x31\x69\x4B\xEB\x20\xAA\x48\x9D"
                                       "\x66\x49\x97\x5E\x1B\xFC\xF8\xC4\x74\x1B\x78\xB4\xB2\x23\x00\x7F";
static const uint8_t piv_sm2ka_db[32] = "\x78\x51\x29\x91\x7D\x45\xA9\xEA\x54\x37\xA5\x93\x56\xB8\x23\x38"
                                       "\xEA\xAD\xDA\x6C\xEB\x19\x90\x88\xF1\x4A\xE1\x0D\xEF\xA2\x29\xB5";
static const uint8_t piv_sm2ka_pb[64] = "\x6A\xE8\x48\xC5\x7C\x53\xC7\xB1\xB5\xFA\x99\xEB\x22\x86\xAF\x07"
                                       "\x8B\xA6\x4C\x64\x59\x1B\x8B\x56\x6F\x73\x57\xD5\x76\xF1\x6D\xFB"
                                       "\xEE\x48\x9D\x77\x16\x21\xA2\x7B\x36\xC5\xC7\x99\x20\x62\xE9\xCD"
                                       "\x09\xA9\x26\x43\x86\xF3\xFB\xEA\x54\xDF\xF6\x93\x05\x62\x1C\x4D";

static const uint8_t piv_sm2ka_eph_a[64] = "\x64\xCE\xD1\xBD\xBC\x99\xD5\x90\x04\x9B\x43\x4D\x0F\xD7\x34\x28"
                                           "\xCF\x60\x8A\x5D\xB8\xFE\x5C\xE0\x7F\x15\x02\x69\x40\xBA\xE4\x0E"
                                           "\x37\x66\x29\xC7\xAB\x21\xE7\xDB\x26\x09\x22\x49\x9D\xDB\x11\x8F"
                                           "\x07\xCE\x8E\xAA\xE3\xE7\x72\x0A\xFE\xF6\xA5\xCC\x06\x20\x70\xC0";





static void piv_test_write_sm2_key_full(const char *path, const uint8_t pri[32], pin_policy_t pin_policy) {
  ck_key_t key = {.meta = {.type = SM2,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = KEY_USAGE_ANY,
                           .pin_policy = pin_policy,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  memcpy(key.ecc.pri, pri, 32);
  assert_int_equal(ecc_complete_key(SM2, &key.ecc), 0);
  assert_int_equal(ck_write_key(path, &key), 0);
  memzero(&key, sizeof(key));
}

// Build 7C { [80 <id_len> <id>] 82 00 [85 <inner...>] }.
static size_t piv_test_build_sm2_ka_request(uint8_t *request, const uint8_t *id, uint8_t id_len,
                                            const uint8_t *inner, uint16_t inner_len) {
  const uint16_t inner_tlv_len = inner == NULL ? 0 : (uint16_t)((inner_len < 128 ? 2 : 3) + inner_len);
  const uint16_t outer = (uint16_t)((id == NULL ? 0 : 2 + id_len) + 2 + inner_tlv_len);
  size_t off = 0;
  request[off++] = 0x7C;
  if (outer < 128) {
    request[off++] = (uint8_t)outer;
  } else {
    request[off++] = 0x81;
    request[off++] = (uint8_t)outer;
  }
  if (id != NULL) {
    request[off++] = 0x80;
    request[off++] = id_len;
    memcpy(request + off, id, id_len);
    off += id_len;
  }
  request[off++] = 0x82;
  request[off++] = 0x00;
  if (inner != NULL) {
    request[off++] = 0x85;
    if (inner_len < 128) {
      request[off++] = (uint8_t)inner_len;
    } else {
      request[off++] = 0x81;
      request[off++] = (uint8_t)inner_len;
    }
    memcpy(request + off, inner, inner_len);
    off += inner_len;
  }
  return off;
}

// Build the 0x85 inner TLVs: 86/87 peer public keys (raw X || Y, the 0x04
// prefix is added here), optional 88 peer ID, optional 89 klen (-1 = absent).
static size_t piv_test_build_sm2_ka_inner(uint8_t *inner, const uint8_t peer_static[64], const uint8_t peer_eph[64],
                                          const uint8_t *peer_id, uint8_t peer_id_len, int klen) {
  size_t off = 0;
  inner[off++] = 0x86;
  inner[off++] = 0x41;
  inner[off++] = 0x04;
  memcpy(inner + off, peer_static, 64);
  off += 64;
  inner[off++] = 0x87;
  inner[off++] = 0x41;
  inner[off++] = 0x04;
  memcpy(inner + off, peer_eph, 64);
  off += 64;
  if (peer_id != NULL) {
    inner[off++] = 0x88;
    inner[off++] = peer_id_len;
    memcpy(inner + off, peer_id, peer_id_len);
    off += peer_id_len;
  }
  if (klen >= 0) {
    inner[off++] = 0x89;
    inner[off++] = 0x02;
    inner[off++] = (uint8_t)(klen >> 8);
    inner[off++] = (uint8_t)klen;
  }
  return off;
}

// Locate a top-level inner tag inside a 7C response.
// Returns the value length, 0 when absent.
static size_t piv_test_7c_find(const uint8_t *resp, size_t resp_len, uint8_t want_tag, const uint8_t **value) {
  assert_true(resp_len >= 4);
  assert_int_equal(resp[0], 0x7C);
  size_t off;
  if (resp[1] == 0x81) {
    assert_int_equal((size_t)resp[2] + 3, resp_len);
    off = 3;
  } else if (resp[1] == 0x82) {
    assert_true(resp_len >= 4);
    assert_int_equal(((size_t)resp[2] << 8) + resp[3] + 4, resp_len);
    off = 4;
  } else {
    assert_true(resp[1] < 0x80);
    assert_int_equal((size_t)resp[1] + 2, resp_len);
    off = 2;
  }
  while (off + 2 <= resp_len) {
    const uint8_t tag = resp[off];
    size_t l = resp[off + 1];
    size_t hdr = 2;
    if (l == 0x81) { // one-byte long form (inner value >= 128 bytes)
      assert_true(off + 3 <= resp_len);
      l = resp[off + 2];
      hdr = 3;
    } else if (l == 0x82) {
      assert_true(off + 4 <= resp_len);
      l = ((size_t)resp[off + 2] << 8) | resp[off + 3];
      hdr = 4;
    } else {
      assert_true(l < 0x80);
    }
    assert_true(off + hdr + l <= resp_len);
    if (tag == want_tag) {
      *value = resp + off + hdr;
      return l;
    }
    off += hdr + l;
  }
  *value = NULL;
  return 0;
}

static uint16_t piv_test_sm2_ka(uint8_t slot, const uint8_t *request, size_t request_len, uint8_t *response,
                                uint16_t *response_len) {
  return piv_test_send_chained(PIV_INS_GENERAL_AUTHENTICATE, 0x54, slot, request, request_len, response,
                               response_len);
}

// On-card roundtrip: slot 9A acts as initiator, slot 9C as responder, both
// with default IDs and the default key length (16). The responder call on 9C
// must not disturb the in-flight initiator state on 9A.
static void test_piv_sm2_key_agreement_roundtrip(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  piv_test_write_sm2_key_full("piv-k9a", piv_sm2ka_da, PIN_POLICY_NEVER);
  piv_test_write_sm2_key_full("piv-k9c", piv_sm2ka_db, PIN_POLICY_NEVER);

  uint8_t request[192];
  uint8_t inner[172];
  uint8_t response[160];
  uint16_t response_len;
  const uint8_t *value;
  uint8_t eph_a_pub[64], eph_b_pub[64], k_a[16], k_b[16];

  // Initiator step 1 on 9A.
  size_t request_len = piv_test_build_sm2_ka_request(request, NULL, 0, NULL, 0);
  assert_int_equal(piv_test_sm2_ka(0x9A, request, request_len, response, &response_len), SW_NO_ERROR);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x82, &value), 65);
  assert_int_equal(value[0], 0x04);
  memcpy(eph_a_pub, value + 1, 64);

  // Stateless responder call on 9C while 9A has an agreement in flight.
  size_t inner_len = piv_test_build_sm2_ka_inner(inner, piv_sm2ka_pa, eph_a_pub, NULL, 0, -1);
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, inner, inner_len);
  assert_int_equal(piv_test_sm2_ka(0x9C, request, request_len, response, &response_len), SW_NO_ERROR);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x82, &value), 65);
  assert_int_equal(value[0], 0x04);
  memcpy(eph_b_pub, value + 1, 64);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x85, &value), sizeof(k_b));
  memcpy(k_b, value, sizeof(k_b));

  // Initiator step 2 on 9A.
  inner_len = piv_test_build_sm2_ka_inner(inner, piv_sm2ka_pb, eph_b_pub, NULL, 0, -1);
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, inner, inner_len);
  assert_int_equal(piv_test_sm2_ka(0x9A, request, request_len, response, &response_len), SW_NO_ERROR);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x82, &value), sizeof(k_a));
  memcpy(k_a, value, sizeof(k_a));

  assert_memory_equal(k_a, k_b, sizeof(k_a));

  // The agreement is complete: another step 2 attempt on 9A is now a fresh
  // (valid) responder call, and step 1 may start over.
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, NULL, 0);
  assert_int_equal(piv_test_sm2_ka(0x9A, request, request_len, response, &response_len), SW_NO_ERROR);

  memzero(k_a, sizeof(k_a));
  memzero(k_b, sizeof(k_b));
}

static void test_piv_sm2_key_agreement_pin_policy(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  piv_test_write_sm2_key_full("piv-k9a", piv_sm2ka_da, PIN_POLICY_ALWAYS);
  piv_test_write_sm2_key_full("piv-k9c", piv_sm2ka_da, PIN_POLICY_ONCE);
  piv_test_write_sm2_key_full("piv-k9d", piv_sm2ka_db, PIN_POLICY_ONCE);

  uint8_t request[192];
  uint8_t inner[172];
  uint8_t response[160];
  uint16_t response_len;

  // Unauthenticated PIN_POLICY_ALWAYS slot: both step 1 and the one-shot
  // responder require the PIN.
  size_t request_len = piv_test_build_sm2_ka_request(request, NULL, 0, NULL, 0);
  assert_int_equal(piv_test_sm2_ka(0x9A, request, request_len, response, &response_len),
                   SW_SECURITY_STATUS_NOT_SATISFIED);
  size_t inner_len = piv_test_build_sm2_ka_inner(inner, piv_sm2ka_pa, piv_sm2ka_eph_a, NULL, 0, -1);
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, inner, inner_len);
  assert_int_equal(piv_test_sm2_ka(0x9A, request, request_len, response, &response_len),
                   SW_SECURITY_STATUS_NOT_SATISFIED);

  // PIN_POLICY_ONCE slots: one VERIFY covers step 1, the interleaved
  // responder call and step 2 (initiator on 9C, responder on 9D).
  uint8_t pin_data[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
  test_helper(pin_data, sizeof(pin_data), PIV_INS_VERIFY, 0x00, 0x80, SW_NO_ERROR);

  const uint8_t *value;
  uint8_t eph_c_pub[64], eph_d_pub[64], k_c[16], k_d[16];
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, NULL, 0);
  assert_int_equal(piv_test_sm2_ka(0x9C, request, request_len, response, &response_len), SW_NO_ERROR);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x82, &value), 65);
  memcpy(eph_c_pub, value + 1, 64);

  inner_len = piv_test_build_sm2_ka_inner(inner, piv_sm2ka_pa, eph_c_pub, NULL, 0, -1);
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, inner, inner_len);
  assert_int_equal(piv_test_sm2_ka(0x9D, request, request_len, response, &response_len), SW_NO_ERROR);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x82, &value), 65);
  memcpy(eph_d_pub, value + 1, 64);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x85, &value), sizeof(k_d));
  memcpy(k_d, value, sizeof(k_d));

  inner_len = piv_test_build_sm2_ka_inner(inner, piv_sm2ka_pb, eph_d_pub, NULL, 0, -1);
  request_len = piv_test_build_sm2_ka_request(request, NULL, 0, inner, inner_len);
  assert_int_equal(piv_test_sm2_ka(0x9C, request, request_len, response, &response_len), SW_NO_ERROR);
  assert_int_equal(piv_test_7c_find(response, response_len, 0x82, &value), sizeof(k_c));
  memcpy(k_c, value, sizeof(k_c));
  assert_memory_equal(k_c, k_d, sizeof(k_c));

  memzero(k_c, sizeof(k_c));
  memzero(k_d, sizeof(k_d));
}

// Observe/fail physical writes without changing production filesystem helpers.




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
  lfs_filebd_create(&cfg, "lfs-root-piv", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);
  piv_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_piv_migrates_legacy_management_key_types),
      cmocka_unit_test(test_piv_startup_preserves_state_when_platform_config_is_invalid),
      cmocka_unit_test(test_piv_get_metadata_directory),
      cmocka_unit_test(test_piv_move_delete_key_extension),
      cmocka_unit_test(test_piv_attestation_certificate),
      cmocka_unit_test(test_piv_attestation_f9_policy),
      cmocka_unit_test(test_piv_attestation_all_target_algorithms),
      cmocka_unit_test(test_piv_sm2_key_agreement_roundtrip),
      cmocka_unit_test(test_piv_sm2_key_agreement_pin_policy),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
