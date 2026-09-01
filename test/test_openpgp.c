// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "openpgp.h"
#include <apdu.h>
#include <bd/lfs_filebd.h>
#include <crypto-util.h>
#include <device.h>
#include <fs.h>
#include <lfs.h>
#include <string.h>

static void inject_write_error(const char *path) {
  testmode_inject_error(0, 0, (uint16_t)strlen(path), (const uint8_t *)path);
}

static void test_verify(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_VERIFY;
  capdu->p1 = 0x00;
  capdu->p2 = 0x81;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "123456");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  capdu->lc = 4;
  strcpy((char *)capdu->data, "1234");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);
  capdu->lc = 6;
  strcpy((char *)capdu->data, "123465");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_AUTHENTICATION_BLOCKED);
  openpgp_install(1);
}

static void test_change_reference_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_CHANGE_REFERENCE_DATA;
  capdu->p1 = 0x01;
  capdu->p2 = 0x81;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "123456");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_P1P2);
  capdu->p1 = 0x00;
  capdu->lc = 10;
  strcpy((char *)capdu->data, "1234561234");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);
  capdu->lc = 10;
  strcpy((char *)capdu->data, "1234651234");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  capdu->lc = 12;
  strcpy((char *)capdu->data, "123456654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  openpgp_install(1);
}

static void test_reset_retry_counter(void **state) {
  (void)state;

  write_file("pgp-rc", "abcdefgh", 0, 8, 1);

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_RESET_RETRY_COUNTER;
  capdu->p1 = 0x02;
  capdu->p2 = 0x81;
  capdu->lc = 14;
  strcpy((char *)capdu->data, "abcdefgh654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_SECURITY_STATUS_NOT_SATISFIED);
  capdu->p1 = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->ins = OPENPGP_INS_VERIFY;
  capdu->p1 = 0x00;
  capdu->p2 = 0x82;
  capdu->lc = 6;
  strcpy((char *)capdu->data, "654321");
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  openpgp_install(1);
}

static void test_set_pin_retries(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};

  C.cla = 0x00;
  C.ins = OPENPGP_INS_SET_PIN_RETRIES;
  C.p1 = 0x00;
  C.p2 = 0x00;
  C.lc = 3;
  C.data[0] = 4;
  C.data[1] = 5;
  C.data[2] = 6;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  C.ins = OPENPGP_INS_VERIFY;
  C.p2 = 0x83;
  C.lc = 8;
  memcpy(C.data, "12345678", 8);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C.ins = OPENPGP_INS_SET_PIN_RETRIES;
  C.p2 = 0x00;
  C.lc = 2;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_LENGTH);

  C.lc = 3;
  C.data[0] = 4;
  C.data[1] = 0;
  C.data[2] = 6;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  C.data[1] = 16;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_WRONG_DATA);

  C.data[1] = 5;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C.ins = OPENPGP_INS_GET_DATA;
  C.p1 = 0x00;
  C.p2 = TAG_PW_STATUS;
  C.lc = 0;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_int_equal(R.len, 7);
  assert_int_equal(R.data[4], 4);
  assert_int_equal(R.data[5], 0);
  assert_int_equal(R.data[6], 6);

  C.ins = OPENPGP_INS_VERIFY;
  C.p1 = 0x00;
  C.p2 = 0x81;
  C.lc = 0;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, 0x63C4);

  C.lc = 6;
  memcpy(C.data, "123456", 6);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C.p2 = 0x83;
  C.lc = 8;
  memcpy(C.data, "12345678", 8);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C.ins = OPENPGP_INS_SET_PIN_RETRIES;
  C.p2 = 0x00;
  C.lc = 3;
  C.data[0] = 15;
  C.data[1] = 15;
  C.data[2] = 15;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  openpgp_install(1);
}

static void test_set_pin_retries_failure_invalidates_auth(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf, .cla = 0x00, .ins = OPENPGP_INS_VERIFY, .p1 = 0x00, .p2 = 0x83, .lc = 8};
  RAPDU R = {.data = r_buf};

  memcpy(C.data, "12345678", 8);
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);

  C.ins = OPENPGP_INS_SET_PIN_RETRIES;
  C.p2 = 0x00;
  C.lc = 3;
  C.data[0] = 4;
  C.data[1] = 5;
  C.data[2] = 6;
  inject_write_error("pgp-pw3");
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_UNABLE_TO_PROCESS);

  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_SECURITY_STATUS_NOT_SATISFIED);

  openpgp_install(1);
}

static void test_get_data(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_GET_DATA;
  capdu->p1 = 0x00;
  capdu->p2 = TAG_APPLICATION_RELATED_DATA;
  capdu->lc = 0;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

// GET DATA P2=0xFA returns the algorithm-information DO, which is the
// only callsite that builds the SIG/DEC/AUT supported-algorithm tables
// via add_all_algorithm_info. Walk the response and verify each entry
// is well-formed (tag byte + length + algo-id-prefixed OID) so the
// table builder is properly exercised.
static void test_algorithm_information(void **state) {
  (void)state;

  uint8_t c_buf[16], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  C.cla = 0x00;
  C.ins = OPENPGP_INS_GET_DATA;
  C.p1 = 0x00;
  C.p2 = TAG_ALGORITHM_INFORMATION;
  C.lc = 0;
  openpgp_process_apdu(&C, &R);
  assert_int_equal(R.sw, SW_NO_ERROR);
  assert_true(R.len > 3);
  assert_int_equal(R.data[0], TAG_ALGORITHM_INFORMATION);
  assert_int_equal(R.data[1], 0x81);
  assert_int_equal(R.data[2] + 3, R.len);

  // Walk SIG (0xC1) / DEC (0xC2) / AUT (0xC3) entries: each is
  //   tag(1) || attr_len(1) || algo_id(1) || OID bytes...
  // and the response covers all three slots. Count entries per tag.
  int n_sig = 0, n_dec = 0, n_aut = 0;
  uint16_t off = 3;
  while (off < R.len) {
    uint8_t tag = R.data[off++];
    assert_true(off < R.len);
    uint8_t attr_len = R.data[off++];
    assert_true(off + attr_len <= R.len);
    assert_true(attr_len >= 1);
    if (tag == 0xC1)
      ++n_sig;
    else if (tag == 0xC2)
      ++n_dec;
    else if (tag == 0xC3)
      ++n_aut;
    else
      fail_msg("unexpected algo-info tag 0x%02X", tag);
    off += attr_len;
  }
  assert_int_equal(off, R.len);
  // Static table has SIG=9, DEC=9, AUT=9 entries.
  assert_int_equal(n_sig, 9);
  assert_int_equal(n_dec, 9);
  assert_int_equal(n_aut, 9);
}

static void test_import_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC1\x0A\x16\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01", 15);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC1\x01\x01", 6);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_DATA);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC1\x06\x13\x2A\x86\x48\xCE\x3D", 11);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_DATA);

  // import an ecc key
  build_capdu(
      capdu,
      (uint8_t *)"\x00\xDB\x3F\xFF\x2C\x4D\x2A\xB6\x00\x7F\x48\x02\x92\x20\x5F\x48\x20\x4A\xDB\x8D\x21\xB8\xB7\xF3\xDD"
                 "\x22\xFD\xE3\xB8\xEB\xAD\xDC\xE1\x89\x2A\x24\xA5\x7B\x9E\x35\xD0\x10\x67\xBB\x5A\xF9\x89\x89\xEB",
      49);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // with public key (ignored by card)
  build_capdu(capdu,
              (uint8_t *)"\x00\xDB\x3F\xFF\x4E\x4D\x4C\xB6\x00\x7F\x48\x04\x92\x20\x99\x20\x5F\x48\x40\x4A\xDB\x8D\x21"
                         "\xB8\xB7\xF3\xDD\x22\xFD\xE3\xB8\xEB\xAD\xDC\xE1\x89\x2A\x24\xA5\x7B\x9E\x35\xD0\x10\x67\xBB"
                         "\x5A\xF9\x89\x89\xEB\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
              83);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

static void test_generate_key(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;
  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_GENERATE_ASYMMETRIC_KEY_PAIR;
  capdu->p1 = 0x80;
  capdu->p2 = 0x00;
  capdu->lc = 0x02;
  capdu->data[0] = 0xB8;
  capdu->data[1] = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  print_hex(rapdu->data, rapdu->len);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x82\x06\x31\x32\x33\x34\x35\x36", 11);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  // Decipher with invalid input data
  capdu->ins = OPENPGP_INS_PSO;
  capdu->p1 = 0x80;
  capdu->p2 = 0x86;
  openpgp_process_apdu(capdu, rapdu);
  print_hex(rapdu->data, rapdu->len);
  assert_int_equal(rapdu->sw, SW_WRONG_LENGTH);
}

static void test_decipher_chaining(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x82\x06\x31\x32\x33\x34\x35\x36", 11);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->cla = 0x00;
  capdu->ins = OPENPGP_INS_GENERATE_ASYMMETRIC_KEY_PAIR;
  capdu->p1 = 0x80;
  capdu->p2 = 0x00;
  capdu->lc = 0x02;
  capdu->data[0] = 0xB8;
  capdu->data[1] = 0x00;
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->cla = 0x10;
  capdu->ins = OPENPGP_INS_PSO;
  capdu->p1 = 0x80;
  capdu->p2 = 0x86;
  capdu->lc = 254;
  memset(capdu->data, 0, capdu->lc);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  capdu->cla = 0x00;
  capdu->lc = 3;
  memset(capdu->data, 0, capdu->lc);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_WRONG_DATA);
}

static void test_x25519_public_key_encoding(void **state) {
  (void)state;
  openpgp_install(1);

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\xDA\x00\xC2\x0B\x12\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01", 16);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu,
              (uint8_t *)"\x00\xDB\x3F\xFF\x2C\x4D\x2A\xB8\x00\x7F\x48\x02\x92\x20\x5F\x48\x20\x5A\x83\x40\xFB"
                         "\x62\x3E\x85\x36\xB1\x11\x4E\xD6\xC4\x68\xDC\xA9\x49\x57\x89\x72\xE8\x3C\xB0\x2A"
                         "\xAF\x1C\xE3\x34\x9D\xCA\x0D\x68",
              49);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x02\xB8\x00\x00", 8);
  openpgp_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);

  uint8_t expected[] = {
      0x7F, 0x49, 0x22, 0x86, 0x20, 0xA8, 0x2E, 0x8B, 0x07, 0xB3, 0x5E, 0x0B, 0xFF, 0xB5, 0xD3, 0x3D, 0x7C, 0xA6, 0x53,
      0x4F, 0x0C, 0x2B, 0x03, 0xB0, 0x0F, 0x65, 0xA4, 0x9A, 0xA9, 0x85, 0xF1, 0x16, 0xDE, 0x49, 0x42, 0x15, 0x3D,
  };
  assert_int_equal(rapdu->len, sizeof(expected));
  assert_memory_equal(rapdu->data, expected, sizeof(expected));

  openpgp_install(1);
}

static void test_special(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU C = {.data = c_buf};
  RAPDU R = {.data = r_buf};
  CAPDU *capdu = &C;
  RAPDU *rapdu = &R;

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(capdu, (uint8_t *)"\x00\x20\x00\x83\x08\x31\x32\x33\x34\x35\x36\x37\x38", 13);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x80\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);

  build_capdu(capdu, (uint8_t *)"\x00\x47\x81\x00\x00\x00\x02\xB6\x00\x01\x0F", 11);
  openpgp_process_apdu(capdu, rapdu);
  printf("SW: %X ", SW);
  print_hex(RDATA, LL);
}

// openpgp_process_apdu_message uses RAPDU_CHAINING + apdu_output to stream
// large GET DATA responses. Cert reads also exercise the source-streaming
// path through openpgp_send_cert + openpgp_cert_source_read (file-backed
// source). This test stages a >256-byte cert via chained PUT DATA
// (handled by the OpenPGP applet's own cross-APDU chain state), then
// drains it via GET DATA + GET RESPONSE, verifying the output stream.
static void test_openpgp_cert_chained_read(void **state) {
  (void)state;
  openpgp_install(1);

  // Authenticate as PW3 admin so PUT DATA is allowed.
  uint8_t pin[16];
  uint8_t r_buf[1024];
  CAPDU capdu = {.data = pin};
  RAPDU rapdu = {.data = r_buf};
  capdu.cla = 0x00;
  capdu.ins = OPENPGP_INS_VERIFY;
  capdu.p1 = 0x00;
  capdu.p2 = 0x83;
  capdu.lc = 8;
  memcpy(pin, "12345678", 8);
  openpgp_process_apdu(&capdu, &rapdu);
  assert_int_equal(rapdu.sw, SW_NO_ERROR);

  // 600-byte synthetic cert; spans three 256-byte chunks on read-back.
  enum { CERT_LEN = 600 };
  uint8_t cert[CERT_LEN];
  for (size_t i = 0; i < CERT_LEN; ++i)
    cert[i] = (uint8_t)(0x90 + (i & 0x3F));

  // Chained PUT DATA at TAG_CARDHOLDER_CERTIFICATE (P1P2=7F21). OpenPGP
  // applet handles the cross-APDU chain itself via cert_write_remaining.
  enum { CHUNK = 200 };
  uint8_t chunk[CHUNK];
  for (size_t off = 0; off < CERT_LEN; off += CHUNK) {
    size_t n = (off + CHUNK <= CERT_LEN) ? CHUNK : (CERT_LEN - off);
    bool last = (off + n == CERT_LEN);
    memcpy(chunk, cert + off, n);
    capdu.cla = last ? 0x00 : 0x10;
    capdu.ins = OPENPGP_INS_PUT_DATA;
    capdu.p1 = 0x7F;
    capdu.p2 = 0x21;
    capdu.lc = (uint16_t)n;
    capdu.data = chunk;
    rapdu.len = 0;
    rapdu.sw = 0;
    openpgp_process_apdu(&capdu, &rapdu);
    assert_int_equal(rapdu.sw, SW_NO_ERROR);
  }
  // Cert is stored under SIG_KEY_IDX cert path "pgp-sigc".
  assert_int_equal(get_file_size("pgp-sigc"), CERT_LEN);

  // GET DATA + GET RESPONSE chain via openpgp_process_apdu_message.
  RAPDU_CHAINING rc = {.rapdu.data = r_buf};
  CAPDU get_apdu = {
      .data = NULL, .cla = 0x00, .ins = OPENPGP_INS_GET_DATA, .p1 = 0x7F, .p2 = 0x21, .lc = 0, .le = 0x100};
  rapdu.len = 0;
  rapdu.sw = 0;
  openpgp_process_apdu_message(&rc, &get_apdu, &rapdu);
  assert_int_equal(rapdu.len, 256);
  assert_int_equal(rapdu.sw & 0xFF00, 0x6100);

  uint8_t reassembled[1024];
  size_t total = rapdu.len;
  memcpy(reassembled, rapdu.data, rapdu.len);

  CAPDU gr_apdu = {.data = NULL, .cla = 0x00, .ins = 0xC0, .p1 = 0x00, .p2 = 0x00, .lc = 0, .le = 0x100};
  while ((rapdu.sw & 0xFF00) == 0x6100) {
    rapdu.len = 0;
    rapdu.sw = 0;
    openpgp_process_apdu_message(&rc, &gr_apdu, &rapdu);
    assert_true(rapdu.len > 0);
    assert_true(total + rapdu.len <= sizeof(reassembled));
    memcpy(reassembled + total, rapdu.data, rapdu.len);
    total += rapdu.len;
  }
  assert_int_equal(rapdu.sw, SW_NO_ERROR);
  assert_int_equal(total, CERT_LEN);
  assert_memory_equal(reassembled, cert, CERT_LEN);
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
  openpgp_install(1);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_verify),
      cmocka_unit_test(test_change_reference_data),
      cmocka_unit_test(test_reset_retry_counter),
      cmocka_unit_test(test_set_pin_retries),
      cmocka_unit_test(test_set_pin_retries_failure_invalidates_auth),
      cmocka_unit_test(test_get_data),
      cmocka_unit_test(test_algorithm_information),
      cmocka_unit_test(test_import_key),
      cmocka_unit_test(test_generate_key),
      cmocka_unit_test(test_decipher_chaining),
      cmocka_unit_test(test_x25519_public_key_encoding),
      cmocka_unit_test(test_openpgp_cert_chained_read),
      cmocka_unit_test(test_special),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
