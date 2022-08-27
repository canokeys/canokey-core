// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "secret.h"
#include <aes.h>
#include <block-cipher.h>
#include <ecc.h>
#include <ed25519.h>
#include <fs.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>
#include <device.h>

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

static void hkdf(uint8_t *salt, size_t salt_len, uint8_t *ikm, size_t ikm_len, uint8_t *out) {
  hmac_sha256(salt, salt_len, ikm, ikm_len, salt);
  hmac_sha256(salt, SHA256_DIGEST_LENGTH, (const uint8_t *) "CTAP2 HMAC key\x01", 15, out);
  hmac_sha256(salt, SHA256_DIGEST_LENGTH, (const uint8_t *) "CTAP2 AES key\x01", 14, out + SHA256_DIGEST_LENGTH);
}

static void cp2_kdf(uint8_t *z, size_t z_len, uint8_t *out) {
  uint8_t salt[32] = {0};
  hkdf(salt, sizeof(salt), z, z_len, out);
}

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

int cp_decapsulate(uint8_t *buf, int pin_protocol) {
  int ret = ecdh_decrypt(ECC_SECP256R1, ka_keypair, buf, buf);
  if (ret < 0) return 1;
  if (pin_protocol == 1)
    sha256_raw(buf, PRI_KEY_SIZE, buf);
  else
    cp2_kdf(buf, PRI_KEY_SIZE, buf);
  return 0;
}

int cp_encrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out, int pin_protocol) {
  uint8_t iv[16];
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  cfg.in_size = in_size;
  cfg.in = in;
  if (pin_protocol == 1) {
    memzero(iv, sizeof(iv));
    cfg.key = key;
    cfg.out = out;
  } else {
    random_buffer(iv, sizeof(iv));
    cfg.key = key + 32;
    cfg.out = out + sizeof(iv);
    memcpy(out, iv, sizeof(iv));
  }
  return block_cipher_enc(&cfg);
}

int cp_encrypt_pin_token(const uint8_t *key, uint8_t *out, int pin_protocol) {
  return cp_encrypt(key, pin_token, PIN_TOKEN_SIZE, out, pin_protocol);
}

int cp_decrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out, int pin_protocol) {
  uint8_t iv[16];
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  if (pin_protocol == 1) {
    memzero(iv, sizeof(iv));
    cfg.key = key;
    cfg.in_size = in_size;
    cfg.in = in;
    cfg.out = out;
  } else {
    if (in_size < sizeof(iv)) return -1;
    memcpy(iv, in, sizeof(iv));
    cfg.key = key + 32;
    cfg.in_size = in_size - sizeof(iv);
    cfg.in = in + sizeof(iv);
    cfg.out = out;
  }
  return block_cipher_dec(&cfg);
}

bool cp_verify(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig,
               int pin_protocol) {
  uint8_t buf[SHA256_DIGEST_LENGTH];
  if (pin_protocol == 2 && key_len > SHA256_DIGEST_LENGTH) key_len = SHA256_DIGEST_LENGTH;
  hmac_sha256(key, key_len, msg, msg_len, buf);
  if (pin_protocol == 1)
    return memcmp(buf, sig, PIN_AUTH_SIZE_P1) == 0;
  else
    return memcmp(buf, sig, SHA256_DIGEST_LENGTH) == 0;
}

bool cp_verify_pin_token(const uint8_t *msg, size_t msg_len, const uint8_t *sig, int pin_protocol) {
  if (!in_use) return false;
  return cp_verify(pin_token, PIN_TOKEN_SIZE, msg, msg_len, sig, pin_protocol);
}


void cp_set_permission(int new_permissions) {
  permissions |= new_permissions;
}

bool cp_has_permission(int permission) {
  return permissions & permission;
}

bool cp_has_associated_rp_id(void) {
  return permissions_rp_id[0] == 1;
}

bool cp_verify_rp_id(const uint8_t *rp_id_hash) {
  if (permissions_rp_id[0] == 0) return true;
  return memcmp(&permissions_rp_id[1], rp_id_hash, SHA256_DIGEST_LENGTH) == 0;
}

void cp_associate_rp_id(const uint8_t *rp_id_hash) {
  permissions_rp_id[0] = 1;
  memcpy(&permissions_rp_id[1], rp_id_hash, SHA256_DIGEST_LENGTH);
}

static int read_pri_key(uint8_t *pri_key) {
  int ret = read_attr(CTAP_CERT_FILE, KEY_ATTR, pri_key, PRI_KEY_SIZE);
  if (ret < 0) return ret;
  return 0;
}

static int read_kh_key(uint8_t *kh_key) {
  int ret = read_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, KH_KEY_SIZE);
  if (ret < 0) return ret;
  return 0;
}

static int read_he_key(uint8_t *he_key) {
  int ret = read_attr(CTAP_CERT_FILE, HE_KEY_ATTR, he_key, HE_KEY_SIZE);
  if (ret < 0) return ret;
  return 0;
}

int increase_counter(uint32_t *counter) {
  int ret = read_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, counter, sizeof(uint32_t));
  if (ret < 0) return ret;
  ++*counter;
  ret = write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, counter, sizeof(uint32_t));
  if (ret < 0) return ret;
  return 0;
}

static void generate_credential_id_nonce_tag(credential_id *kh, uint8_t *pubkey) {
  // works for es256 and ed25519 since their public keys share the same length
  random_buffer(kh->nonce, CREDENTIAL_NONCE_SIZE);
  // private key = hmac-sha256(device private key, nonce), stored in pubkey[0:32)
  hmac_sha256(pubkey, KH_KEY_SIZE, kh->nonce, sizeof(kh->nonce), pubkey);
  // tag = left(hmac-sha256(private key, rp_id_hash or appid), 16), stored in pubkey[32, 64)
  hmac_sha256(pubkey, KH_KEY_SIZE, kh->rp_id_hash, sizeof(kh->rp_id_hash), pubkey + KH_KEY_SIZE);
  memcpy(kh->tag, pubkey + KH_KEY_SIZE, sizeof(kh->tag));
}

int generate_key_handle(credential_id *kh, uint8_t *pubkey, int32_t alg_type) {
  int ret = read_kh_key(pubkey); // use pubkey as key buffer
  if (ret < 0) return ret;

  if (alg_type == COSE_ALG_ES256) {
    kh->alg_type = COSE_ALG_ES256;
    do {
      generate_credential_id_nonce_tag(kh, pubkey);
    } while (ecc_get_public_key(ECC_SECP256R1, pubkey, pubkey) < 0);
    return 0;
  } else if (alg_type == COSE_ALG_EDDSA) {
    kh->alg_type = COSE_ALG_EDDSA;
    generate_credential_id_nonce_tag(kh, pubkey);
    ed25519_publickey(pubkey, pubkey);
    return 0;
  } else {
    return -1;
  }
}

int verify_key_handle(const credential_id *kh, uint8_t *pri_key) {
  uint8_t kh_key[KH_KEY_SIZE];
  int ret = read_kh_key(kh_key);
  if (ret < 0) return ret;

  // get private key
  hmac_sha256(kh_key, KH_KEY_SIZE, kh->nonce, sizeof(kh->nonce), pri_key);
  // get tag, store in kh_key, which should be verified first outside this function
  hmac_sha256(pri_key, KH_KEY_SIZE, kh->rp_id_hash, sizeof(kh->rp_id_hash), kh_key);
  if (memcmp(kh_key, kh->tag, sizeof(kh->tag)) == 0) {
    memzero(kh_key, sizeof(kh_key));
    return 0;
  }
  memzero(kh_key, sizeof(kh_key));
  return 1;
}

size_t sign_with_device_key(const uint8_t *digest, uint8_t *sig) {
  uint8_t key[32];
  int ret = read_pri_key(key);
  if (ret < 0) return ret;
  ecdsa_sign(ECC_SECP256R1, key, digest, sig);
  memzero(key, sizeof(key));
  return ecdsa_sig2ansi(PRI_KEY_SIZE, sig, sig);
}

size_t sign_with_ecdsa_private_key(const uint8_t *key, const uint8_t *digest, uint8_t *sig) {
  ecdsa_sign(ECC_SECP256R1, key, digest, sig);
  return ecdsa_sig2ansi(PRI_KEY_SIZE, sig, sig);
}

size_t sign_with_ed25519_private_key(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *sig) {
  ed25519_public_key pk;
  ed25519_publickey(key, pk);
  ed25519_signature sig_tmp;
  // ed25519_sign(m, mlen, sk, pk, RS)
  // m and RS can not share the same buffer
  // (they are shared outside this func)
  ed25519_sign(data, data_len, key, pk, sig_tmp);
  memcpy(sig, sig_tmp, sizeof(ed25519_signature));
  memzero(pk, sizeof(pk));
  return sizeof(ed25519_signature);
}

int get_cert(uint8_t *buf) { return read_file(CTAP_CERT_FILE, buf, 0, MAX_CERT_SIZE); }

int has_pin(void) {
  uint8_t tmp;
  return read_attr(CTAP_CERT_FILE, PIN_ATTR, &tmp, 1);
}

int set_pin(uint8_t *buf, uint8_t length) {
  int err;
  if (length == 0) {
    err = write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0);
  } else {
    sha256_raw(buf, length, buf);
    err = write_attr(CTAP_CERT_FILE, PIN_ATTR, buf, PIN_HASH_SIZE_P1); // We only compare the first 16 bytes
  }
  if (err < 0) return err;
  uint8_t ctr = 8;
  return write_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &ctr, 1);
}

int verify_pin_hash(uint8_t *buf) {
  uint8_t storedPinHash[PIN_HASH_SIZE_P1]; // We only compare the first 16 bytes
  int err = read_attr(CTAP_CERT_FILE, PIN_ATTR, storedPinHash, PIN_HASH_SIZE_P1);
  if (err < 0) return err;
  if (memcmp(storedPinHash, buf, PIN_HASH_SIZE_P1) == 0) return 0;
  return 1;
}

int get_pin_retries(void) {
  uint8_t ctr;
  int err = read_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &ctr, 1);
  if (err < 0) return err;
  return ctr;
}

int set_pin_retries(uint8_t ctr) { return write_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &ctr, 1); }

int make_hmac_secret_output(uint8_t *nonce, uint8_t *salt, uint8_t len, uint8_t *output) {
  uint8_t hmac_buf[SHA256_DIGEST_LENGTH];
  // use hmac-sha256(HE_KEY, credential_id::nonce) as CredRandom
  int err = read_he_key(hmac_buf);
  if (err < 0) return err;

  hmac_sha256(hmac_buf, HE_KEY_SIZE, nonce, CREDENTIAL_NONCE_SIZE, hmac_buf);
  hmac_sha256(hmac_buf, HE_KEY_SIZE, salt, 32, output);
  if (len == 64) hmac_sha256(hmac_buf, HE_KEY_SIZE, salt + 32, 32, output + 32);
  return 0;
}
