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
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <piv.h>
#include <rsa.h>
#include <sha.h>
#include <string.h>

#include "ecdsa-generic.h"
#include "nist256p1.h"
#include "piv_attestation_fixture.h"

extern void set_admin_status(int status);

static void inject_write_error(const char *path) {
  testmode_inject_error(0, 0, (uint16_t)strlen(path), (const uint8_t *)path);
}

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
  if (get_file_size("piv-atk") >= 0) assert_int_equal(remove_file("piv-atk"), 0);
  if (get_file_size("piv-atc") >= 0) assert_int_equal(remove_file("piv-atc"), 0);
}

static void piv_test_provision_attestation_key(void) {
  ck_key_t key = {.meta = {.type = SECP256R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  memcpy(key.ecc.pri, piv_test_f9_private_key, sizeof(piv_test_f9_private_key));
  memcpy(key.ecc.pub, piv_test_f9_public_key, sizeof(piv_test_f9_public_key));
  assert_int_equal(ck_write_key("piv-atk", &key), 0);
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
  assert_int_equal(write_file("piv-atc", object, 0, sizeof(object), 1), 0);
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

// regression tests for crashes discovered by fuzzing
static void test_regression_fuzz(void **state) {
  (void)state;

  if (1) {
    // zero length data
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x00, SW_WRONG_LENGTH);
  }

  if (1) {
    // only tag
    uint8_t data[] = {0x7C};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // only tag and bad length
    uint8_t data[] = {0x7C, 0x80};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0x00, 0x9B, SW_WRONG_LENGTH);
  }

  if (1) {
    // malformed authenticate payload
    uint8_t data[] = {0x00, 0x00};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0xFF, 0x9B, SW_WRONG_DATA);
  }

  if (1) {
    // valid authenticate payload with unsupported card admin algorithm
    uint8_t data[] = {0x7C, 0x00};
    test_helper(data, sizeof(data), PIV_INS_GENERAL_AUTHENTICATE, 0xFF, 0x9B, SW_WRONG_P1P2);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  // bypass authentication, testing only
  set_admin_status(1);

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, 0x9A, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty input
    uint8_t data[] = {};
    test_helper(data, sizeof(data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty object path
    uint8_t data[] = {0x5C, 0x03, 0x5F, 0xC1};
    test_helper(data, sizeof(data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_WRONG_LENGTH);
  }

  if (1) {
    // empty object path
    uint8_t data[] = {0xAC, 0x00, 0x80, 0x01};
    test_helper(data, sizeof(data), PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, 0x9A, SW_WRONG_LENGTH);
  }

  if (1) {
    // import symmetric key
    // 00FE079C 91
    // 013E4C9CA1020204000000000000005B08020C00000000000000020202020202020202020202020202020202022D0D0202020202020202020202020202020202025050505050505002505050505002020202025002020202020202028202020202E78DE4F3D506F6B7A3F8BD10CB29DADE18B83B6ED7AB37A3B73A9A11348E17B60B65119055DD2497942D363431323734
    uint8_t data[] = {0x01,
                      // TLV
                      0x3E, 0x01, 0x00};
    test_helper(data, sizeof(data), PIV_INS_IMPORT_ASYMMETRIC_KEY, 0x07, 0x9C, SW_WRONG_LENGTH);
  }
}

static void test_delete_certificate_object(void **state) {
  (void)state;

  set_admin_status(1);

  uint8_t put_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xAA};
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-pauc"), 3);

  uint8_t delete_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x00};
  test_helper(delete_cert, sizeof(delete_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_true(get_file_size("piv-pauc") < 0);
}

static const uint8_t default_piv_pin[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
static const uint8_t default_mgmt_key[24] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

static void authenticate_management_key(const uint8_t key[24]) {
  uint8_t init[] = {0x7C, 0x02, 0x81, 0x00};
  uint8_t r_buf[64];
  RAPDU R = {.data = r_buf};
  CAPDU C = {
      .data = init, .cla = 0x00, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0x0A, .p2 = 0x9B, .lc = sizeof(init)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 20);
  assert_memory_equal(R.data, ((uint8_t[]){0x7C, 0x12, 0x81, 0x10}), 4);

  uint8_t complete[20] = {0x7C, 0x12, 0x82, 0x10};
  assert_int_equal(aes192_enc(R.data + 4, complete + 4, key), 0);
  C.data = complete;
  C.lc = sizeof(complete);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 0);
}

static void test_piv_aes192_management_key(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  key_meta_t meta;
  assert_true(ck_read_key_metadata("piv-admk", &meta) >= 0);
  assert_int_equal(meta.type, AES192);
  assert_int_equal(meta.touch_policy, TOUCH_POLICY_NEVER);
  assert_true(ck_read_key_metadata("piv-sigk", &meta) >= 0);
  assert_int_equal(meta.pin_policy, PIN_POLICY_ALWAYS);

  uint8_t r_buf[64];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9B, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[2], 0x0A);
  assert_int_equal(R.data[5], 0x00);
  assert_int_equal(R.data[6], TOUCH_POLICY_NEVER);

  authenticate_management_key(default_mgmt_key);

  static const uint8_t new_key[24] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x20, 0x21, 0x22, 0x23,
                                      0x24, 0x25, 0x26, 0x27, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
  uint8_t set_key[27] = {0x0A, 0x9B, 0x18};
  memcpy(set_key + 3, new_key, sizeof(new_key));
  C = (CAPDU){
      .data = set_key, .cla = 0x00, .ins = PIV_INS_SET_MANAGEMENT_KEY, .p1 = 0xFF, .p2 = 0xFE, .lc = sizeof(set_key)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key_metadata("piv-admk", &meta) >= 0);
  assert_int_equal(meta.touch_policy, TOUCH_POLICY_ALWAYS);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9B, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[5], 0x00);
  assert_int_equal(R.data[6], TOUCH_POLICY_ALWAYS);

  C = (CAPDU){
      .data = set_key, .cla = 0x00, .ins = PIV_INS_SET_MANAGEMENT_KEY, .p1 = 0xFF, .p2 = 0xFD, .lc = sizeof(set_key)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){
      .data = set_key, .cla = 0x00, .ins = PIV_INS_SET_MANAGEMENT_KEY, .p1 = 0xFF, .p2 = 0xFF, .lc = sizeof(set_key)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key_metadata("piv-admk", &meta) >= 0);
  assert_int_equal(meta.touch_policy, TOUCH_POLICY_NEVER);

  piv_poweroff();
  authenticate_management_key(new_key);

  uint8_t init[] = {0x7C, 0x02, 0x81, 0x00};
  C = (CAPDU){
      .data = init, .cla = 0x00, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0x03, .p2 = 0x9B, .lc = sizeof(init)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  assert_int_equal(piv_install(1), 0);
}

static void test_piv_aes192_mutual_authentication(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  uint8_t init[] = {0x7C, 0x02, 0x80, 0x00};
  uint8_t r_buf[64];
  RAPDU R = {.data = r_buf};
  CAPDU C = {
      .data = init, .cla = 0x00, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0x0A, .p2 = 0x9B, .lc = sizeof(init)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 20);
  assert_memory_equal(R.data, ((uint8_t[]){0x7C, 0x12, 0x80, 0x10}), 4);

  uint8_t complete[40] = {0x7C, 0x26, 0x80, 0x10};
  assert_int_equal(aes192_dec(R.data + 4, complete + 4, default_mgmt_key), 0);
  complete[20] = 0x81;
  complete[21] = 0x10;
  for (uint8_t i = 0; i < AES_BLOCK_SIZE; ++i)
    complete[22 + i] = i;
  complete[38] = 0x82;
  complete[39] = 0x00;
  C.data = complete;
  C.lc = sizeof(complete);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 20);
  assert_memory_equal(R.data, ((uint8_t[]){0x7C, 0x12, 0x82, 0x10}), 4);

  uint8_t expected[AES_BLOCK_SIZE];
  assert_int_equal(aes192_enc(complete + 22, expected, default_mgmt_key), 0);
  assert_memory_equal(R.data + 4, expected, sizeof(expected));
}

static void configure_host_managed_admin_data(void) {
  set_admin_status(1);

  uint8_t printed[5 + 30] = {0x5C, 0x03, 0x5F, 0xC1, 0x09, 0x53, 0x1C, 0x88, 0x1A, 0x89, 0x18};
  memcpy(printed + 11, default_mgmt_key, sizeof(default_mgmt_key));
  test_helper(printed, sizeof(printed), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);

  uint8_t admin_data[] = {0x5C, 0x03, 0x5F, 0xFF, 0x00, 0x53, 0x05, 0x80, 0x03, 0x81, 0x01, 0x03};
  test_helper(admin_data, sizeof(admin_data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);

  set_admin_status(0);
}

static void test_piv_host_managed_admin_data_objects(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  const int admin_key_size = get_file_size("piv-admk");
  configure_host_managed_admin_data();
  assert_int_equal(get_file_size("piv-admk"), admin_key_size);
  piv_poweroff();

  uint8_t get_printed[] = {0x5C, 0x03, 0x5F, 0xC1, 0x09};
  test_helper(get_printed, sizeof(get_printed), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);

  test_helper((uint8_t *)default_piv_pin, sizeof(default_piv_pin), PIV_INS_VERIFY, 0x00, 0x80, SW_NO_ERROR);

  uint8_t expected_printed[30] = {0x53, 0x1C, 0x88, 0x1A, 0x89, 0x18};
  memcpy(expected_printed + 6, default_mgmt_key, sizeof(default_mgmt_key));
  test_helper_resp(get_printed, sizeof(get_printed), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_NO_ERROR, expected_printed,
                   sizeof(expected_printed));

  piv_poweroff();
  uint8_t get_admin[] = {0x5C, 0x03, 0x5F, 0xFF, 0x00};
  uint8_t expected_admin[] = {0x53, 0x05, 0x80, 0x03, 0x81, 0x01, 0x03};
  test_helper_resp(get_admin, sizeof(get_admin), PIV_INS_GET_DATA, 0x3F, 0xFF, SW_NO_ERROR, expected_admin,
                   sizeof(expected_admin));
}

static void test_piv_pin_does_not_satisfy_admin(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  configure_host_managed_admin_data();
  piv_poweroff();

  uint8_t put_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xAA};
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);

  test_helper((uint8_t *)default_piv_pin, sizeof(default_piv_pin), PIV_INS_VERIFY, 0x00, 0x80, SW_NO_ERROR);
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_SECURITY_STATUS_NOT_SATISFIED);
  assert_true(get_file_size("piv-pauc") < 0);
}

static void test_piv_retired_cert_lazy_storage(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  assert_true(get_file_size("piv-r20") < 0);

  set_admin_status(1);
  uint8_t put_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x20, 0x53, 0x01, 0x55};
  test_helper(put_cert, sizeof(put_cert), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-r20"), 3);

  uint8_t get_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x20};
  uint8_t expected[] = {0x53, 0x01, 0x55};
  uint8_t r_buf[256];
  CAPDU C = {.data = get_cert, .ins = PIV_INS_GET_DATA, .p1 = 0x3F, .p2 = 0xFF, .lc = sizeof(get_cert), .le = 256};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, expected, sizeof(expected));
}

static void test_piv_metadata_bounded_do_storage(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);
  set_admin_status(1);

  uint8_t inline_printed[5 + 64] = {0x5C, 0x03, 0x5F, 0xC1, 0x09};
  for (size_t i = 5; i < sizeof(inline_printed); ++i) {
    inline_printed[i] = (uint8_t)i;
  }
  test_helper(inline_printed, sizeof(inline_printed), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_true(get_file_size("piv-pi") < 0);

  uint8_t max_admin_data[5 + 128] = {0x5C, 0x03, 0x5F, 0xFF, 0x00};
  for (size_t i = 5; i < sizeof(max_admin_data); ++i) {
    max_admin_data[i] = (uint8_t)(0x80 + i);
  }
  test_helper(max_admin_data, sizeof(max_admin_data), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);

  uint8_t large_printed[5 + 80] = {0x5C, 0x03, 0x5F, 0xC1, 0x09};
  for (size_t i = 5; i < sizeof(large_printed); ++i) {
    large_printed[i] = (uint8_t)i;
  }
  test_helper(large_printed, sizeof(large_printed), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-pi"), 80);

  uint8_t security[] = {0x5C, 0x03, 0x5F, 0xC1, 0x06, 0x53, 0x02, 0x11, 0x22};
  test_helper(security, sizeof(security), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-sec"), 4);

  uint8_t key_history[] = {0x5C, 0x03, 0x5F, 0xC1, 0x0C, 0x53, 0x01, 0x33};
  test_helper(key_history, sizeof(key_history), PIV_INS_PUT_DATA, 0x3F, 0xFF, SW_NO_ERROR);
  assert_int_equal(get_file_size("piv-kh"), 3);

  configure_host_managed_admin_data();
  assert_true(get_file_size("piv-pi") < 0);
}

// piv_get_metadata's key_type_to_algo_id switch maps each supported
// PIV key type to the runtime-configurable algorithm-extension byte.
// Integration tests only exercise the RSA2048 / SECP256R1 / SECP384R1
// arms; the extended types (ED25519, X25519, SECP256K1, SECP521R1, SM2) live
// behind alg_ext_cfg.* defaults that piv_install pre-populates. Drop a
// well-formed asymmetric key in the AUTH slot for each type and read
// metadata back; the second algorithm byte should match the default
// table.
static void test_piv_get_metadata_extended_algo_ids(void **state) {
  (void)state;

  // alg_ext_cfg defaults from piv_install.
  static const struct {
    key_type_t type;
    uint8_t expected_algo_id;
  } cases[] = {
      {ED25519, 0xE0}, {X25519, 0xE1}, {SECP256K1, 0x53}, {SECP521R1, 0x15}, {SM2, 0x54},
  };

  set_admin_status(1);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    ck_key_t key = {.meta = {.type = cases[i].type,
                             .origin = KEY_ORIGIN_GENERATED,
                             .usage = SIGN,
                             .pin_policy = PIN_POLICY_NEVER,
                             .touch_policy = TOUCH_POLICY_NEVER}};
    assert_int_equal(ck_generate_key(&key), 0);
    assert_int_equal(ck_write_key("piv-pauk", &key), 0);

    uint8_t r_buf[256];
    CAPDU C = {.data = NULL, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
    RAPDU R = {.data = r_buf};
    piv_process_apdu(&C, &R);

    assert_int_equal(R.sw, SW_NO_ERROR);
    // Layout: 01 01 <algo> 02 02 <pin> <touch> 03 01 <origin> 04 ...
    assert_true(R.len >= 11);
    assert_int_equal(R.data[0], 0x01);
    assert_int_equal(R.data[1], 0x01);
    assert_int_equal(R.data[2], cases[i].expected_algo_id);
    assert_int_equal(R.data[3], 0x02);
    assert_int_equal(R.data[4], 0x02);
    assert_int_equal(R.data[5], PIN_POLICY_NEVER);
    assert_int_equal(R.data[6], TOUCH_POLICY_NEVER);
    assert_int_equal(R.data[7], 0x03);
    assert_int_equal(R.data[8], 0x01);
    assert_int_equal(R.data[9], KEY_ORIGIN_GENERATED);
    assert_int_equal(R.data[10], 0x04);
  }
}

static void test_piv_rsa4096_metadata_chained_read(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t config = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&config), 0);
  assert_int_equal(piv_install(1), 0);

  ck_key_t key = {.meta = {.type = RSA4096,
                           .origin = KEY_ORIGIN_IMPORTED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_ONCE,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  key.meta.origin = KEY_ORIGIN_IMPORTED;
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);
  memset(&key, 0, sizeof(key));

  uint8_t chunk[APDU_BUFFER_SIZE];
  uint8_t response[536];
  RAPDU rapdu = {.data = chunk};
  RAPDU_CHAINING chaining = {.rapdu.data = chunk};
  CAPDU command = {
      .data = NULL,
      .cla = 0x00,
      .ins = PIV_INS_GET_METADATA,
      .p1 = 0x00,
      .p2 = 0x9A,
      .lc = 0,
      .le = APDU_BUFFER_SIZE,
  };

  piv_process_apdu_message(&chaining, &command, &rapdu);
  assert_int_equal(rapdu.len, APDU_BUFFER_SIZE);
  assert_int_equal(rapdu.sw & 0xFF00, 0x6100);

  size_t total = rapdu.len;
  memcpy(response, rapdu.data, rapdu.len);
  command = (CAPDU){.data = NULL, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .lc = 0, .le = APDU_BUFFER_SIZE};
  while ((rapdu.sw & 0xFF00) == 0x6100) {
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu_message(&chaining, &command, &rapdu);
    assert_true(total + rapdu.len <= sizeof(response));
    memcpy(response + total, rapdu.data, rapdu.len);
    total += rapdu.len;
  }

  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(total, sizeof(response));
  assert_memory_equal(response,
                      ((uint8_t[]){0x01, 0x01, 0x16, 0x02, 0x02, PIN_POLICY_ONCE, TOUCH_POLICY_NEVER, 0x03, 0x01,
                                   KEY_ORIGIN_IMPORTED, 0x04, 0x82, 0x02, 0x0A, 0x81, 0x82, 0x02, 0x00}),
                      18);
  assert_memory_equal(response + sizeof(response) - 6, ((uint8_t[]){0x82, 0x04, 0x00, 0x01, 0x00, 0x01}), 6);
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
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);
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

  assert_int_equal(ck_write_key("piv-sigk", &key), 0);
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
  assert_true(ck_read_key("piv-sigk", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));

  assert_int_equal(get_file_size("piv-pauk"), LFS_ERR_NOENT);

  // Simulate reboot: an absent ordinary key slot is valid initialized state.
  assert_int_equal(piv_install(0), 0);
  assert_true(ck_read_key("piv-sigk", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));
  assert_int_equal(get_file_size("piv-pauk"), LFS_ERR_NOENT);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  set_admin_status(1);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x95, .p2 = 0x9C, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key("piv-95", &moved_key) >= 0);
  assert_memory_equal(&moved_key, &original_key, sizeof(moved_key));
  assert_int_equal(get_file_size("piv-sigk"), LFS_ERR_NOENT);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0x9D, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-95") < 0);
  assert_true(ck_read_key("piv-mntk", &moved_key) >= 0);
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
  assert_int_equal(ck_write_key("piv-pauk", &target), 0);

  uint8_t certificate[1536];
  uint16_t sw;
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);

  piv_test_provision_attestation_key();
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);

  piv_test_provision_attestation_cert();
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

  // Only the agreed Yubico-compatible serial and policy extensions are emitted.
  assert_int_equal(test_der_read(cursor, remaining, &field), 0);
  assert_int_equal(field.tag, 0xA3);
  static const uint8_t serial_oid[] = {0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07};
  static const uint8_t policy_extension[] = {0x06,
                                             0x0A,
                                             0x2B,
                                             0x06,
                                             0x01,
                                             0x04,
                                             0x01,
                                             0x82,
                                             0xC4,
                                             0x0A,
                                             0x03,
                                             0x08,
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
  assert_int_equal(ck_write_key("piv-pauk", &target), 0);
  assert_int_equal(piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw), 0);
  assert_int_equal(sw, SW_REFERENCE_DATA_NOT_FOUND);

  // F9 key and certificate survive a PIV reset, while ordinary target keys do not.
  assert_int_equal(piv_install(1), 0);
  assert_true(get_file_size("piv-atk") > 0);
  assert_true(get_file_size("piv-atc") > 0);
  target.meta.origin = KEY_ORIGIN_GENERATED;
  assert_int_equal(ck_generate_key(&target), 0);
  assert_int_equal(ck_write_key("piv-pauk", &target), 0);
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
  assert_true(ck_read_key_metadata("piv-atk", &f9_meta) >= 0);
  assert_int_equal(f9_meta.type, SECP256R1);
  assert_int_equal(f9_meta.origin, KEY_ORIGIN_GENERATED);

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
  assert_true(ck_read_key_metadata("piv-atk", &f9_meta) >= 0);
  assert_int_equal(f9_meta.origin, KEY_ORIGIN_IMPORTED);
  assert_int_equal(remove_file("piv-atk"), 0);

  ck_key_t source = {.meta = {.type = SECP384R1,
                              .origin = KEY_ORIGIN_GENERATED,
                              .usage = SIGN,
                              .pin_policy = PIN_POLICY_ONCE,
                              .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&source), 0);
  assert_int_equal(ck_write_key("piv-pauk", &source), 0);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xF9, .p2 = 0x9A, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  source.meta.type = SECP256R1;
  assert_int_equal(ck_generate_key(&source), 0);
  assert_int_equal(ck_write_key("piv-pauk", &source), 0);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(ck_read_key_metadata("piv-atk", &f9_meta) >= 0);
  assert_int_equal(f9_meta.type, SECP256R1);

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
  };

  uint8_t certificate[1536];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    ck_key_t target = {.meta = {.type = cases[i].type,
                                .origin = KEY_ORIGIN_GENERATED,
                                .usage = SIGN,
                                .pin_policy = PIN_POLICY_ONCE,
                                .touch_policy = TOUCH_POLICY_NEVER}};
    assert_int_equal(ck_generate_key(&target), 0);
    assert_int_equal(ck_write_key("piv-pauk", &target), 0);
    uint16_t sw;
    const size_t certificate_len = piv_test_collect_attestation(0x9A, certificate, sizeof(certificate), &sw);
    assert_int_equal(sw, SW_NO_ERROR);
    piv_test_assert_attestation_certificate(certificate, certificate_len, &target, cases[i].oid, cases[i].oid_len);
  }
}

static void test_piv_dynamic_retired_key_slots(void **state) {
  (void)state;
  assert_int_equal(piv_install(1), 0);

  uint8_t r_buf[256];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);
  assert_true(get_file_size("piv-95") < 0);

  set_admin_status(1);
  uint8_t generate_p256[] = {0xAC, 0x03, 0x80, 0x01, 0x11};
  C = (CAPDU){.data = generate_p256,
              .cla = 0x00,
              .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
              .p1 = 0x00,
              .p2 = 0x95,
              .lc = sizeof(generate_p256)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-95") >= 0);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len >= 11);
  assert_int_equal(R.data[2], 0x11);
  assert_int_equal(R.data[5], PIN_POLICY_ONCE);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_MOVE_DELETE_KEY, .p1 = 0xFF, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(get_file_size("piv-95") < 0);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x95, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_REFERENCE_DATA_NOT_FOUND);

  piv_install(1);
}

static void test_piv_reset_preserves_platform_algorithm_extension(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t custom = {
      .enabled = 1,
      .ed25519 = 0x22,
      .rsa3072 = 0x05,
      .rsa4096 = 0x51,
      .x25519 = 0x52,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&custom), 0);

  // A PIV reset rebuilds LittleFS-backed applet state, but the algorithm
  // extension record belongs to platform configuration and must survive it.
  assert_int_equal(piv_install(1), 0);

  piv_algorithm_extension_config_t actual;
  assert_int_equal(piv_platform_algorithm_extension_config_read(&actual), 0);
  assert_memory_equal(&actual, &custom, sizeof(custom));

  set_admin_status(1);
  uint8_t generate_ed25519[] = {0xAC, 0x03, 0x80, 0x01, custom.ed25519};
  uint8_t r_buf[128];
  CAPDU C = {.data = generate_ed25519,
             .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
             .p1 = 0x00,
             .p2 = 0x9A,
             .lc = sizeof(generate_ed25519)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  const piv_algorithm_extension_config_t defaults = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x55,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&defaults), 0);
  assert_int_equal(piv_install(1), 0);
}

static void test_piv_algorithm_extension_read_without_admin(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t expected = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&expected), 0);
  assert_int_equal(piv_install(1), 0);

  set_admin_status(0);
  uint8_t r_buf[128];
  CAPDU C = {.data = NULL, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x01, .p2 = 0x00, .lc = 0};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, &expected, sizeof(expected));

  C = (CAPDU){
      .data = (uint8_t *)&expected, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x02, .p2 = 0x00, .lc = sizeof(expected)};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
}

static void test_piv_algorithm_extension_read_after_write(void **state) {
  (void)state;

  piv_algorithm_extension_config_t expected = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };

  set_admin_status(1);
  uint8_t r_buf[128];
  CAPDU C = {
      .data = (uint8_t *)&expected, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x02, .p2 = 0x00, .lc = sizeof(expected)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  set_admin_status(0);
  C = (CAPDU){.data = NULL, .ins = PIV_INS_ALGORITHM_EXTENSION, .p1 = 0x01, .p2 = 0x00, .lc = 0};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, sizeof(expected));
  assert_memory_equal(R.data, &expected, sizeof(expected));
}

static void test_ed25519_general_authenticate_long_message(void **state) {
  (void)state;

  ck_key_t key = {.meta = {.type = ED25519,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);

  enum { MSG_LEN = 130 };
  uint8_t data[8 + MSG_LEN] = {0};
  data[0] = 0x7C;
  data[1] = 0x81;
  data[2] = MSG_LEN + 5;
  data[3] = 0x82;
  data[4] = 0x00;
  data[5] = 0x81;
  data[6] = 0x81;
  data[7] = MSG_LEN;
  for (uint8_t i = 0; i < MSG_LEN; ++i)
    data[8 + i] = i;

  uint8_t r_buf[128];
  CAPDU C = {.data = data, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0xE0, .p2 = 0x9A, .lc = sizeof(data)};
  RAPDU R = {.data = r_buf};

  piv_process_apdu(&C, &R);

  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 68);
  assert_memory_equal(R.data, ((uint8_t[]){0x7C, 0x42, 0x82, 0x40}), 4);
}

static void test_secp521r1_generate_and_authenticate(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t defaults = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&defaults), 0);
  assert_int_equal(piv_install(1), 0);
  set_admin_status(1);

  uint8_t r_buf[512];
  uint8_t generate[] = {0xAC, 0x03, 0x80, 0x01, 0x15};
  CAPDU C = {
      .data = generate, .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR, .p1 = 0x00, .p2 = 0x9A, .lc = sizeof(generate)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 140);
  assert_memory_equal(R.data, ((uint8_t[]){0x7F, 0x49, 0x81, 0x88, 0x86, 0x81, 0x85, 0x04}), 8);

  uint8_t generate_with_policy[] = {0xAC, 0x06, 0x80, 0x01, 0x15, 0xAA, 0x01, 0x02, 0xAB, 0x01, 0x01};
  C = (CAPDU){.data = generate_with_policy,
              .cla = 0x00,
              .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
              .p1 = 0x00,
              .p2 = 0x9A,
              .lc = sizeof(generate_with_policy)};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len > 11);
  assert_int_equal(R.data[2], 0x15);

  ck_key_t key = {.meta = {.type = SECP521R1,
                           .origin = KEY_ORIGIN_GENERATED,
                           .usage = SIGN,
                           .pin_policy = PIN_POLICY_NEVER,
                           .touch_policy = TOUCH_POLICY_NEVER}};
  assert_int_equal(ck_generate_key(&key), 0);
  assert_int_equal(ck_write_key("piv-pauk", &key), 0);

  uint8_t data[6 + 66] = {0};
  data[0] = 0x7C;
  data[1] = 0x46;
  data[2] = 0x82;
  data[3] = 0x00;
  data[4] = 0x81;
  data[5] = 0x42;
  for (uint8_t i = 0; i < 66; ++i)
    data[6 + i] = i;

  C = (CAPDU){
      .data = data, .cla = 0x00, .ins = PIV_INS_GENERAL_AUTHENTICATE, .p1 = 0x15, .p2 = 0x9A, .lc = sizeof(data)};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);

  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len > 8);
  assert_int_equal(R.data[0], 0x7C);
  assert_int_equal(R.data[1], 0x82);
  assert_int_equal(R.data[4], 0x82);
  assert_int_equal(R.data[5], 0x82);
  assert_int_equal(R.data[6], 0x00);
  assert_true(R.data[7] >= 0x89);
  assert_int_equal(R.data[8], 0x30);
  assert_int_equal(R.data[9], 0x81);
  assert_int_equal(R.data[10] + 3, R.data[7]);
}

static void test_secp521r1_custom_algorithm_id(void **state) {
  (void)state;

  const piv_algorithm_extension_config_t custom = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x55,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&custom), 0);
  assert_int_equal(piv_install(1), 0);
  set_admin_status(1);

  uint8_t r_buf[512];
  uint8_t generate_with_policy[] = {0xAC, 0x06, 0x80, 0x01, 0x55, 0xAA, 0x01, 0x02, 0xAB, 0x01, 0x01};
  CAPDU C = {.data = generate_with_policy,
             .cla = 0x00,
             .ins = PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR,
             .p1 = 0x00,
             .p2 = 0x9A,
             .lc = sizeof(generate_with_policy)};
  RAPDU R = {.data = r_buf};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 140);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x9A, .lc = 0};
  R.len = 0;
  R.sw = 0;
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[2], 0x55);

  const piv_algorithm_extension_config_t defaults = {
      .enabled = 1,
      .ed25519 = 0xE0,
      .rsa3072 = 0x05,
      .rsa4096 = 0x16,
      .x25519 = 0xE1,
      .secp256k1 = 0x53,
      .secp521r1 = 0x15,
      .sm2 = 0x54,
  };
  assert_int_equal(piv_platform_algorithm_extension_config_write(&defaults), 0);
  assert_int_equal(piv_install(1), 0);
}

static void test_set_pin_retries(void **state) {
  (void)state;

  uint8_t r_buf[128];
  RAPDU R = {.data = r_buf};
  CAPDU C = {.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};

  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  uint8_t pin_data[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
  C = (CAPDU){.data = pin_data, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(pin_data)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 0, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 16, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_P1P2);

  C = (CAPDU){.data = pin_data, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 1};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x80, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[5], 1);
  assert_int_equal(R.data[8], 4);
  assert_int_equal(R.data[9], 4);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_GET_METADATA, .p1 = 0x00, .p2 = 0x81, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.data[5], 1);
  assert_int_equal(R.data[8], 5);
  assert_int_equal(R.data[9], 5);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, 0x63C4);

  uint8_t old_pin[8] = {'0', '0', '0', '0', '0', '0', 0xFF, 0xFF};
  C = (CAPDU){.data = old_pin, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(old_pin)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, 0x63C3);

  C = (CAPDU){.data = pin_data, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(pin_data)};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  set_admin_status(1);
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 15, .p2 = 15, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  piv_install(1);
}

static void test_set_pin_retries_failure_invalidates_auth(void **state) {
  (void)state;

  uint8_t r_buf[128];
  RAPDU R = {.data = r_buf};
  uint8_t pin_data[8] = {'1', '2', '3', '4', '5', '6', 0xFF, 0xFF};
  CAPDU C = {.data = pin_data, .cla = 0x00, .ins = PIV_INS_VERIFY, .p1 = 0x00, .p2 = 0x80, .lc = sizeof(pin_data)};

  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  inject_write_error("piv-puk");
  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_UNABLE_TO_PROCESS);

  C = (CAPDU){.data = NULL, .cla = 0x00, .ins = PIV_INS_SET_PIN_RETRIES, .p1 = 4, .p2 = 5, .lc = 0};
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  set_admin_status(1);
  piv_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  piv_install(1);
}

// piv_process_apdu_message uses RAPDU_CHAINING + apdu_output to stream
// large responses in 256-byte chunks. Stage a >256-byte certificate via
// chained PUT DATA APDUs (PIV applet handles cross-APDU chaining itself),
// then walk the GET DATA + GET RESPONSE chain and verify byte content +
// SW chain. This covers the PIV chaining dispatcher's GET DATA / GET
// RESPONSE state transitions and the apdu_output non-source chaining
// branch.
static void test_piv_cert_chained_read(void **state) {
  (void)state;
  set_admin_status(1);

  // 600-byte payload large enough to span three 256-byte chunks.
  enum { CERT_LEN = 600 };
  uint8_t cert[CERT_LEN];
  for (size_t i = 0; i < CERT_LEN; ++i)
    cert[i] = (uint8_t)(0xC0 + (i & 0x3F));

  uint8_t r_buf[1024];
  RAPDU rapdu = {.data = r_buf};
  RAPDU_CHAINING rc = {.rapdu.data = r_buf};

  // First PUT DATA chunk: 5C-tag selects PIV Authentication slot, then 53
  // BER-TLV with the cert length, then the first 200 bytes of cert. CLA
  // 0x10 = "more chunks follow"; PIV applet handles the chain itself.
  enum { HDR_LEN = 5 + 4, FIRST_CHUNK = 200 };
  uint8_t first_data[HDR_LEN + FIRST_CHUNK];
  first_data[0] = 0x5C;
  first_data[1] = 0x03;
  first_data[2] = 0x5F;
  first_data[3] = 0xC1;
  first_data[4] = 0x05;
  first_data[5] = 0x53;
  first_data[6] = 0x82;
  first_data[7] = (uint8_t)(CERT_LEN >> 8);
  first_data[8] = (uint8_t)(CERT_LEN & 0xFF);
  memcpy(first_data + HDR_LEN, cert, FIRST_CHUNK);
  CAPDU put_first = {
      .data = first_data,
      .cla = 0x10,
      .ins = PIV_INS_PUT_DATA,
      .p1 = 0x3F,
      .p2 = 0xFF,
      .lc = sizeof(first_data),
      .le = 0,
  };
  rc.rapdu.len = 0;
  rc.sent = 0;
  rapdu.len = 0;
  rapdu.sw = 0;
  piv_process_apdu_message(&rc, &put_first, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // Subsequent chunks: 200 bytes each, last one without the chain bit.
  uint8_t chunk[200];
  for (int round = 0; round < 2; ++round) {
    size_t off = FIRST_CHUNK + (size_t)round * 200;
    memcpy(chunk, cert + off, 200);
    CAPDU put_more = {
        .data = chunk,
        .cla = (round == 1) ? 0x00 : 0x10,
        .ins = PIV_INS_PUT_DATA,
        .p1 = 0x3F,
        .p2 = 0xFF,
        .lc = 200,
        .le = 0,
    };
    rc.rapdu.len = 0;
    rc.sent = 0;
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu_message(&rc, &put_more, &rapdu);
    assert_int_equal(rapdu.sw, SW_NO_ERROR);
  }
  assert_int_equal(get_file_size("piv-pauc"), CERT_LEN + 4); // 53 82 LL HH header + cert

  // Now read it back via GET DATA + GET RESPONSE chain.
  uint8_t get_cert[] = {0x5C, 0x03, 0x5F, 0xC1, 0x05};
  CAPDU get_apdu = {
      .data = get_cert,
      .cla = 0x00,
      .ins = PIV_INS_GET_DATA,
      .p1 = 0x3F,
      .p2 = 0xFF,
      .lc = sizeof(get_cert),
      .le = 0x100,
  };
  rc.rapdu.len = 0;
  rc.sent = 0;
  rapdu.len = 0;
  rapdu.sw = 0;
  piv_process_apdu_message(&rc, &get_apdu, &rapdu);
  // First chunk: 256 bytes, SW indicates more remaining.
  assert_int_equal(rapdu.len, 256);
  assert_int_equal(rapdu.sw & 0xFF00, 0x6100);

  uint8_t reassembled[1024];
  size_t total = rapdu.len;
  memcpy(reassembled, rapdu.data, rapdu.len);

  // Drain via GET RESPONSE until SW_NO_ERROR.
  CAPDU gr_apdu = {.data = NULL, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .lc = 0, .le = 0x100};
  while ((rapdu.sw & 0xFF00) == 0x6100) {
    rapdu.len = 0;
    rapdu.sw = 0;
    piv_process_apdu_message(&rc, &gr_apdu, &rapdu);
    assert_true(rapdu.len > 0);
    assert_true(total + rapdu.len <= sizeof(reassembled));
    memcpy(reassembled + total, rapdu.data, rapdu.len);
    total += rapdu.len;
  }
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // The retrieved object is a 53/82 BER-TLV wrapper around the original
  // cert: 53 82 LL HH || cert bytes.
  assert_true(total >= 4 + CERT_LEN);
  assert_int_equal(reassembled[0], 0x53);
  assert_int_equal(reassembled[1], 0x82);
  assert_int_equal(reassembled[2], (CERT_LEN >> 8) & 0xFF);
  assert_int_equal(reassembled[3], CERT_LEN & 0xFF);
  assert_memory_equal(reassembled + 4, cert, CERT_LEN);
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
  piv_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_regression_fuzz),
      cmocka_unit_test(test_piv_aes192_management_key),
      cmocka_unit_test(test_piv_aes192_mutual_authentication),
      cmocka_unit_test(test_delete_certificate_object),
      cmocka_unit_test(test_piv_host_managed_admin_data_objects),
      cmocka_unit_test(test_piv_pin_does_not_satisfy_admin),
      cmocka_unit_test(test_piv_retired_cert_lazy_storage),
      cmocka_unit_test(test_piv_metadata_bounded_do_storage),
      cmocka_unit_test(test_piv_get_metadata_extended_algo_ids),
      cmocka_unit_test(test_piv_rsa4096_metadata_chained_read),
      cmocka_unit_test(test_piv_move_delete_key_extension),
      cmocka_unit_test(test_piv_attestation_certificate),
      cmocka_unit_test(test_piv_attestation_f9_policy),
      cmocka_unit_test(test_piv_attestation_all_target_algorithms),
      cmocka_unit_test(test_piv_dynamic_retired_key_slots),
      cmocka_unit_test(test_piv_reset_preserves_platform_algorithm_extension),
      cmocka_unit_test(test_piv_algorithm_extension_read_without_admin),
      cmocka_unit_test(test_piv_algorithm_extension_read_after_write),
      cmocka_unit_test(test_ed25519_general_authenticate_long_message),
      cmocka_unit_test(test_secp521r1_generate_and_authenticate),
      cmocka_unit_test(test_secp521r1_custom_algorithm_id),
      cmocka_unit_test(test_set_pin_retries),
      cmocka_unit_test(test_set_pin_retries_failure_invalidates_auth),
      cmocka_unit_test(test_piv_cert_chained_read),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
