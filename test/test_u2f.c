#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "../u2f/u2f.h"
#include <aes.h>
#include <apdu.h>
#include <ecdsa.h>
#include <emubd/lfs_emubd.h>
#include <fs.h>
#include <lfs.h>
#include <memzero.h>
#include <sha2.h>

uint8_t public_key[] = {
    0x04, 0x7A, 0x59, 0x31, 0x80, 0x86, 0x0C, 0x40, 0x37, 0xC8, 0x3C,
    0x12, 0x74, 0x98, 0x45, 0xC8, 0xEE, 0x14, 0x24, 0xDD, 0x29, 0x7F,
    0xAD, 0xCB, 0x89, 0x5E, 0x35, 0x82, 0x55, 0xD2, 0xC7, 0xD2, 0xB2,
    0xA8, 0xCA, 0x25, 0x58, 0x0F, 0x26, 0x26, 0xFE, 0x57, 0x90, 0x62,
    0xFF, 0x1B, 0x99, 0xFF, 0x91, 0xC2, 0x4A, 0x0D, 0xA0, 0x6F, 0xB3,
    0x2B, 0x5B, 0xE2, 0x01, 0x48, 0xC9, 0x24, 0x9F, 0x56, 0x50};

static void test_u2f_personalization(void **state) {
  (void)state;

  uint8_t c_buf[1024], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;
  capdu->cla = 0x80;
  capdu->ins = U2F_PERSONALIZATION;
  capdu->lc = 0;

  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  assert_int_equal(rapdu->len, 64);

  uint8_t key_buf[112];
  read_file("u2f_key", key_buf, sizeof(key_buf));
  memzero(key_buf + 96, 16);
  write_file("u2f_key", key_buf, sizeof(key_buf));

  capdu->ins = U2F_INSTALL_CERT;
  capdu->lc = 1;
  capdu->data[0] = 0xDD;
  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
}

static void test_u2f_registration(void **state) {
  (void)state;

  uint8_t c_buf[100], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;

  // prepare data
  capdu->cla = 0x00;
  capdu->ins = U2F_REGISTER;
  capdu->lc = 64;
  for (int i = 0; i < 64; ++i) {
    capdu->data[i] = i;
  }

  // without touch
  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_CONDITIONS_NOT_SATISFIED);

  // after touch
  u2f_press();
  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  assert_int_equal(rapdu->len, 266);

  // compare id
  U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)rapdu->data;
  assert_int_equal(resp->registerId, U2F_REGISTER_ID);

  // compare public key
  for (int i = 0; i != 65; ++i) {
    assert_int_equal(((uint8_t *)&resp->pubKey)[i], public_key[i]);
  }

  // compare key handle
  assert_int_equal(resp->keyHandleLen, U2F_KH_SIZE);
  uint8_t expected_keyhandle[U2F_KH_SIZE];
  for (int i = 0; i != 32; ++i) {
    expected_keyhandle[i] = i + 32;
    expected_keyhandle[i + 32] = i;
  }
  for (int i = 0; i != 64; ++i) {
    expected_keyhandle[i + 64] = public_key[i + 1];
  }
  uint8_t raw_aes_key[16], iv[16];
  for (int i = 0; i != 16; ++i) {
    iv[i] = i;
  }
  memzero(raw_aes_key, 16);
  WORD aes_key[44];
  aes_key_setup(raw_aes_key, aes_key, 128);
  aes_encrypt_ctr(expected_keyhandle, sizeof(expected_keyhandle),
                  expected_keyhandle, aes_key, 128, iv);
  for (int i = 0; i != U2F_KH_SIZE; ++i) {
    assert_int_equal(resp->keyHandleCertSig[i], expected_keyhandle[i]);
  }

  // compare cert
  assert_int_equal(resp->keyHandleCertSig[U2F_KH_SIZE], 0xDD);

  // compare signature
  uint8_t sig_buffer[65], priv_key[32];
  sig_buffer[0] = 0;
  for (int i = 0; i != 32; ++i) {
    sig_buffer[i + 1] = i + 32;
    sig_buffer[i + 33] = i;
  }
  for (int i = 0; i != 32; ++i) {
    priv_key[i] = i;
  }
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, sig_buffer, 65);
  sha256_Update(&ctx, expected_keyhandle, U2F_KH_SIZE);
  sha256_Update(&ctx, public_key, sizeof(public_key));
  sha256_Final(&ctx, sig_buffer);
  ecdsa_sign(ECDSA_SECP256R1, priv_key, sig_buffer, expected_keyhandle);
  int sig_len = ecdsa_sig2ansi(expected_keyhandle, expected_keyhandle);
  for (int i = 0; i != sig_len; ++i) {
    assert_int_equal(resp->keyHandleCertSig[i + U2F_KH_SIZE + 1],
                     expected_keyhandle[i]);
  }
}

static void test_u2f_authenicate(void **state) {
  (void)state;

  uint8_t c_buf[1000], r_buf[1024];
  CAPDU *capdu = (CAPDU *)c_buf;
  RAPDU *rapdu = (RAPDU *)r_buf;

  // prepare data
  capdu->cla = 0x00;
  capdu->ins = U2F_AUTHENTICATE;
  capdu->p1 = U2F_AUTH_ENFORCE;
  capdu->lc = 64;
  for (int i = 0; i < 64; ++i) {
    capdu->data[i] = i;
  }
  capdu->data[64] = 128;

  uint8_t keyhandle[U2F_KH_SIZE];
  for (int i = 0; i != 32; ++i) {
    keyhandle[i] = i + 32;
    keyhandle[i + 32] = i;
  }
  for (int i = 0; i != 64; ++i) {
    keyhandle[i + 64] = public_key[i + 1];
  }
  uint8_t raw_aes_key[16], iv[16];
  for (int i = 0; i != 16; ++i) {
    iv[i] = i;
  }
  memzero(raw_aes_key, 16);
  WORD aes_key[44];
  aes_key_setup(raw_aes_key, aes_key, 128);
  aes_encrypt_ctr(keyhandle, sizeof(keyhandle), keyhandle, aes_key, 128, iv);

  for (int i = 0; i < 128; ++i) {
    capdu->data[i + 65] = keyhandle[i];
  }

  u2f_press();
  u2f_process_apdu(capdu, rapdu);
  assert_int_equal(rapdu->sw, SW_NO_ERROR);
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)rapdu->data;
  assert_int_equal(resp->flags, U2F_AUTH_FLAG_TUP);
  assert_int_equal(resp->ctr[0], 0);
  assert_int_equal(resp->ctr[1], 0);
  assert_int_equal(resp->ctr[2], 0);
  assert_int_equal(resp->ctr[3], 1);

  uint8_t sig_buffer[72], priv_key[32];
  sig_buffer[0] = 0;
  for (int i = 0; i != 32; ++i) {
    sig_buffer[i] = i + 32;
    sig_buffer[i + 37] = i;
  }
  sig_buffer[32] = U2F_AUTH_FLAG_TUP;
  sig_buffer[33] = 0;
  sig_buffer[34] = 0;
  sig_buffer[35] = 0;
  sig_buffer[36] = 1;
  for (int i = 0; i != 32; ++i) {
    priv_key[i] = i;
  }
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, sig_buffer, 69);
  sha256_Final(&ctx, sig_buffer);
  ecdsa_sign(ECDSA_SECP256R1, priv_key, sig_buffer, sig_buffer);
  int sig_len = ecdsa_sig2ansi(sig_buffer, sig_buffer);
  for (int i = 0; i != sig_len; ++i) {
    assert_int_equal(resp->sig[i], sig_buffer[i]);
  }
}

int main() {
  struct lfs_config cfg;
  lfs_emubd_t bd;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_emubd_read;
  cfg.prog = &lfs_emubd_prog;
  cfg.erase = &lfs_emubd_erase;
  cfg.sync = &lfs_emubd_sync;
  cfg.read_size = 16;
  cfg.prog_size = 16;
  cfg.block_size = 512;
  cfg.block_count = 400;
  cfg.block_cycles = 50000;
  cfg.cache_size = 128;
  cfg.lookahead_size = 16;
  lfs_emubd_create(&cfg, "lfs-root");

  fs_init(&cfg);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_u2f_personalization),
      cmocka_unit_test(test_u2f_registration),
      cmocka_unit_test(test_u2f_authenicate),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
