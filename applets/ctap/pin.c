// SPDX-License-Identifier: Apache-2.0
#include <stdbool.h>
#include <stdint.h>

#include "device.h"
#include "pin.h"
#include "ctap-internal.h"
#include <aes.h>
#include <ecc.h>
#include <block-cipher.h>
#include <memzero.h>
#include <rand.h>
#include <hmac.h>

static uint8_t pin_token[PIN_TOKEN_SIZE];
static uint8_t ka_keypair[PRI_KEY_SIZE + PUB_KEY_SIZE];
static uint8_t permissions_rp_id[SHA256_DIGEST_LENGTH + 1]; // the first byte indicates nullable (0: null, 1: not null)
static uint8_t permissions;
static bool in_use;
static bool user_verified;
static bool user_present;
static uint32_t timeout_value;

// utility functions

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-beginusingpinuvauthtoken
void cp_begin_using_uv_auth_token(bool user_is_present) {
  user_present = user_is_present;
  user_verified = true;
  timeout_value = device_get_tick() + 30000;
  in_use = true;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-pinuvauthtokenusagetimerobserver
void cp_pin_uv_auth_token_usage_timer_observer(void) {
  // TODO
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-getuserpresentflagvalue
bool cp_get_user_present_flag_value(void) {
  if (in_use) return user_present;
  return false;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-getuserverifiedflagvalue
bool cp_get_user_verified_flag_value(void) {
  if (in_use) return user_verified;
  return false;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-clearuserpresentflag
void cp_clear_user_present_flag(void) {
  if (in_use) user_present = false;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-clearuserpresentflag
void cp_clear_user_verified_flag(void) {
  if (in_use) user_verified = false;
}

void cp_clear_pin_uv_auth_token_permissions_except_lbw(void) {

}

void cp_stop_using_pin_uv_auth_token(void) {

}

// pin auth protocol

void cp_initialize(void) {
  cp_regenerate();
  cp_reset_pin_uv_auth_token();
}

void cp_regenerate(void) {
  ecc_generate(ECC_SECP256R1, ka_keypair, ka_keypair + PRI_KEY_SIZE);
  DBG_MSG("Regenerate: ");
  PRINT_HEX(ka_keypair, PUB_KEY_SIZE + PRI_KEY_SIZE);
  // TODO the return value of ecc_generate
}

void cp_reset_pin_uv_auth_token(void) {
  random_buffer(pin_token, sizeof(pin_token));
  permissions_rp_id[0] = 0;
  permissions = 0;
  in_use = false;
  user_verified = false;
  user_present = false;
}

void cp_get_public_key(uint8_t *buf) {
  memcpy(buf, ka_keypair + PRI_KEY_SIZE, PUB_KEY_SIZE);
}

int cp_decapsulate(uint8_t *buf) {
  int ret = ecdh_decrypt(ECC_SECP256R1, ka_keypair, buf, buf);
  if (ret < 0) return 1;
  sha256_raw(buf, PRI_KEY_SIZE, buf);
  return 0;
}

int cp_encrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out) {
  uint8_t iv[16];
  memzero(iv, sizeof(iv));
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  cfg.key = key;
  cfg.in_size = in_size;
  cfg.in = in;
  cfg.out = out;
  return block_cipher_enc(&cfg);
}

int cp_encrypt_pin_token(const uint8_t *key, uint8_t *out) {
  return cp_encrypt(key, pin_token, PIN_TOKEN_SIZE, out);
}

int cp_decrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out) {
  uint8_t iv[16];
  memzero(iv, sizeof(iv));
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  cfg.key = key;
  cfg.in_size = in_size;
  cfg.in = in;
  cfg.out = out;
  return block_cipher_dec(&cfg);
}

bool cp_verify(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig) {
  uint8_t buf[SHA256_DIGEST_LENGTH];
  hmac_sha256(key, key_len, msg, msg_len, buf);
  return memcmp(buf, sig, PIN_AUTH_SIZE) == 0;
}

bool cp_verify_pin_token(const uint8_t *msg, size_t msg_len, const uint8_t *sig) {
  if (!in_use) return false;
  return cp_verify(pin_token, PIN_TOKEN_SIZE, msg, msg_len, sig);
}


void cp_set_permission(int new_permissions) {
  permissions |= new_permissions;
}

bool pin_has_permission(int permission) {
  return permissions & permission;
}

bool pin_verify_rp_id(const uint8_t *rp_id_hash) {
  // TODO
  return true;
}

void pin_associate_rp_id(const uint8_t *rp_id_hash) {
  // TODO
}
