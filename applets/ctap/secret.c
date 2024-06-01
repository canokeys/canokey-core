// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "secret.h"
#include <aes.h>
#include <block-cipher.h>
#include <crypto-util.h>
#include <ecc.h>
#include <fs.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>
#include <device.h>
#include <sm3.h>

extern CTAP_sm2_attr ctap_sm2_attr;

static uint8_t pin_token[PIN_TOKEN_SIZE];
static ecc_key_t ka_key;
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
  if (!in_use) return;
  if (device_get_tick() > timeout_value) {
    cp_clear_user_present_flag();
    cp_stop_using_pin_uv_auth_token();
  }
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

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-clearpinuvauthtokenpermissionsexceptlbw
void cp_clear_pin_uv_auth_token_permissions_except_lbw(void) {
  if (in_use) permissions &= ~CP_PERMISSION_LBW;
}

void cp_stop_using_pin_uv_auth_token(void) {
  permissions_rp_id[0] = 0;
  permissions = 0;
  in_use = false;
  user_verified = false;
  user_present = false;
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
  ecc_generate(SECP256R1, &ka_key);
  DBG_MSG("Regenerate:\nPri: ");
  PRINT_HEX(ka_key.pri, PRIVATE_KEY_LENGTH[SECP256R1]);
  DBG_MSG("Pub: ");
  PRINT_HEX(ka_key.pub, PUBLIC_KEY_LENGTH[SECP256R1]);
}

void cp_reset_pin_uv_auth_token(void) {
  random_buffer(pin_token, sizeof(pin_token));
  cp_stop_using_pin_uv_auth_token();
}

void cp_get_public_key(uint8_t *buf) {
  memcpy(buf, ka_key.pub, PUBLIC_KEY_LENGTH[SECP256R1]);
}

int cp_decapsulate(uint8_t *buf, int pin_protocol) {
  int ret = ecdh(SECP256R1, ka_key.pri, buf, buf);
  DBG_MSG("ECDH: ");
  PRINT_HEX(buf, PUBLIC_KEY_LENGTH[SECP256R1]);
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
  cfg.out = out;
  if (pin_protocol == 1) {
    memzero(iv, sizeof(iv));
    cfg.key = key;
  } else {
    random_buffer(iv, sizeof(iv));
    cfg.key = key + SHARED_SECRET_SIZE_HMAC;
  }
  int ret = block_cipher_enc(&cfg);
  if (pin_protocol == 2) {
    // "in" and "out" arguments can be the same pointer 
    memmove(out + sizeof(iv), out, in_size);
    memcpy(out, iv, sizeof(iv));
  }
  return ret;
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
    cfg.key = key + SHARED_SECRET_SIZE_HMAC;
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
    return memcmp_s(buf, sig, PIN_AUTH_SIZE_P1) == 0;
  else
    return memcmp_s(buf, sig, SHA256_DIGEST_LENGTH) == 0;
}

bool cp_verify_pin_token(const uint8_t *msg, size_t msg_len, const uint8_t *sig, int pin_protocol) {
  if (!in_use) return false;
  timeout_value = device_get_tick() + 30000;
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
  return memcmp_s(&permissions_rp_id[1], rp_id_hash, SHA256_DIGEST_LENGTH) == 0;
}

void cp_associate_rp_id(const uint8_t *rp_id_hash) {
  permissions_rp_id[0] = 1;
  memcpy(&permissions_rp_id[1], rp_id_hash, SHA256_DIGEST_LENGTH);
}

key_type_t cose_alg_to_key_type(int alg) {
  switch (alg) {
  case COSE_ALG_ES256:
    return SECP256R1;
  case COSE_ALG_EDDSA:
    return ED25519;
  default:
    if (ctap_sm2_attr.enabled && alg == ctap_sm2_attr.algo_id) return SM2;
    return KEY_TYPE_PKC_END;
  }
}

static int read_device_pri_key(uint8_t *pri_key) {
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

static void generate_credential_id_nonce_tag(credential_id *kh, uint8_t kh_key[KH_KEY_SIZE], ecc_key_t *key) {
  // works for ECC algorithms with a 256-bit private key
  random_buffer(kh->nonce, CREDENTIAL_NONCE_SIZE);
  // private key = hmac-sha256(device private key, nonce)
  hmac_sha256(kh_key, KH_KEY_SIZE, kh->nonce, sizeof(kh->nonce), key->pri);
  DBG_MSG("Device key: ");
  PRINT_HEX(kh_key, KH_KEY_SIZE);
  DBG_MSG("Nonce: ");
  PRINT_HEX(kh->nonce, sizeof(kh->nonce));
  DBG_MSG("Private key: ");
  PRINT_HEX(key->pri, KH_KEY_SIZE);
  // tag = left(hmac-sha256(private key, rpIdHash or appid), 16), stored in kh.tag via key.pub
  hmac_sha256(key->pri, KH_KEY_SIZE, kh->rp_id_hash, sizeof(kh->rp_id_hash), key->pub);
  memcpy(kh->tag, key->pub, sizeof(kh->tag));
}

bool check_credential_protect_requirements(credential_id *kh, bool with_cred_list, bool uv) {
  DBG_MSG("credProtect: %hhu\n", kh->nonce[CREDENTIAL_NONCE_CP_POS]);
  if (kh->nonce[CREDENTIAL_NONCE_CP_POS] == CRED_PROTECT_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST) {
    if (!uv && !with_cred_list) {
      DBG_MSG("credentialProtectionPolicy (0x02) failed\n");
      return false;
    }
  } else if (kh->nonce[CREDENTIAL_NONCE_CP_POS] == CRED_PROTECT_VERIFICATION_REQUIRED) {
    if (!uv) {
      DBG_MSG("credentialProtectionPolicy (0x03) failed\n");
      return false;
    }
  }
  return true;
}

int generate_key_handle(credential_id *kh, uint8_t *pubkey, int32_t alg_type, uint8_t dc, uint8_t cp) {
  ecc_key_t key;
  uint8_t kh_key[KH_KEY_SIZE];

  kh->alg_type = alg_type;
  const key_type_t key_type = cose_alg_to_key_type(alg_type);
  if (key_type == KEY_TYPE_PKC_END) {
    DBG_MSG("Unsupported algo key_type\n");
    return -1;
  }

  kh->nonce[CREDENTIAL_NONCE_DC_POS] = dc;
  kh->nonce[CREDENTIAL_NONCE_CP_POS] = cp;

  const int ret = read_kh_key(kh_key);
  if (ret < 0) return ret;
  do {
    generate_credential_id_nonce_tag(kh, kh_key, &key);
  } while (ecc_complete_key(key_type, &key) < 0);
  memzero(kh_key, KH_KEY_SIZE);

  memcpy(pubkey, key.pub, PUBLIC_KEY_LENGTH[key_type]);
  DBG_MSG("Public: ");
  PRINT_HEX(pubkey, PUBLIC_KEY_LENGTH[key_type]);
  memzero(&key, sizeof(key));

  return 0;
}

int verify_key_handle(const credential_id *kh, ecc_key_t *key) {
  int ret = read_kh_key(key->pub); // use key.pub to store kh key first
  if (ret < 0) return ret;

  // get private key
  hmac_sha256(key->pub, KH_KEY_SIZE, kh->nonce, sizeof(kh->nonce), key->pri);
  DBG_MSG("Device key: ");
  PRINT_HEX(key->pub, KH_KEY_SIZE);
  DBG_MSG("Nonce: ");
  PRINT_HEX(kh->nonce, sizeof(kh->nonce));
  DBG_MSG("Private key: ");
  PRINT_HEX(key->pri, KH_KEY_SIZE);
  // get tag, store in key->pub, which should be verified first outside this function
  hmac_sha256(key->pri, KH_KEY_SIZE, kh->rp_id_hash, sizeof(kh->rp_id_hash), key->pub);
  if (memcmp_s(key->pub, kh->tag, sizeof(kh->tag)) != 0) {
    DBG_MSG("Incorrect key handle\n");
    memzero(key, sizeof(ecc_key_t));
    return 1;
  }
  return 0;
}

size_t sign_with_device_key(const uint8_t *input, size_t input_len, uint8_t *sig) {
  ecc_key_t key;
  int ret = read_device_pri_key(key.pri);
  if (ret < 0) return 0;
  ecc_sign(SECP256R1, &key, input, input_len, sig);
  memzero(&key, sizeof(key));
  return ecdsa_sig2ansi(PRI_KEY_SIZE, sig, sig);
}

int sign_with_private_key(int32_t alg_type, ecc_key_t *key, const uint8_t *input, size_t len, uint8_t *sig) {
  const key_type_t key_type = cose_alg_to_key_type(alg_type);
  DBG_MSG("Sign key type: %d, private key: ", key_type);
  PRINT_HEX(key->pri, PRIVATE_KEY_LENGTH[key_type]);
  if (key_type == KEY_TYPE_PKC_END) {
    DBG_MSG("Unsupported algo key_type\n");
    return -1;
  }

  if (key_type == ED25519) {
    if (ecc_complete_key(key_type, key) < 0) {
      ERR_MSG("Failed to complete key\n");
      return -1;
    }
    if (ecc_sign(key_type, key, input, len, sig) < 0) {
      ERR_MSG("Failed to sign\n");
      return -1;
    }
    return SIGNATURE_LENGTH[key_type];
  }
  if (key_type == SM2) {
    if (ecc_complete_key(key_type, key) < 0) {  // Compute Z requiring the public key
      ERR_MSG("Failed to complete key\n");
      return -1;
    }
    uint8_t z[SM3_DIGEST_LENGTH];
    sm2_z(SM2_ID_DEFAULT, key, z);
    sm3_init();
    sm3_update(z, SM3_DIGEST_LENGTH);
    sm3_update(input, len);
    sm3_final(sig);
  } else {
    sha256_init();
    sha256_update(input, len);
    sha256_final(sig);
  }
  DBG_MSG("Digest: ");
  PRINT_HEX(sig, PRIVATE_KEY_LENGTH[key_type]);
  if (ecc_sign(key_type, key, sig, PRIVATE_KEY_LENGTH[key_type], sig) < 0) {
    ERR_MSG("Failed to sign\n");
    return -1;
  }

  if (key_type == SM2) return SIGNATURE_LENGTH[key_type];

  // For ES256, convert the signature to ansi format
  DBG_MSG("Raw signature: ");
  PRINT_HEX(sig, SIGNATURE_LENGTH[key_type]);
  return ecdsa_sig2ansi(PRIVATE_KEY_LENGTH[key_type], sig, sig);
}

int get_cert(uint8_t *buf) { return read_file(CTAP_CERT_FILE, buf, 0, MAX_CERT_SIZE); }

bool has_pin(void) {
  uint8_t tmp;
  return read_attr(CTAP_CERT_FILE, PIN_ATTR, &tmp, 1) != 0;
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
  if (memcmp_s(storedPinHash, buf, PIN_HASH_SIZE_P1) == 0) return 0;
  return 1;
}

int get_pin_retries(void) {
  uint8_t ctr;
  int err = read_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &ctr, 1);
  if (err < 0) return err;
  return ctr;
}

int set_pin_retries(uint8_t ctr) { return write_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &ctr, 1); }

int make_hmac_secret_output(uint8_t *nonce, uint8_t *salt, uint8_t len, uint8_t *output, bool uv) {
  uint8_t hmac_buf[SHA256_DIGEST_LENGTH];
  // use hmac-sha256(HE_KEY, credential_id::nonce) as CredRandom
  int err = read_he_key(hmac_buf);
  if (err < 0) return err;

  if (uv) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
      hmac_buf[i] = ~hmac_buf[i];
  }

  hmac_sha256(hmac_buf, HE_KEY_SIZE, nonce, CREDENTIAL_NONCE_SIZE, hmac_buf);
  hmac_sha256(hmac_buf, HE_KEY_SIZE, salt, 32, output);
  if (len == 64) hmac_sha256(hmac_buf, HE_KEY_SIZE, salt + 32, 32, output + 32);
  return 0;
}

int make_large_blob_key(uint8_t *nonce, uint8_t *output) {
  static_assert(LARGE_BLOB_KEY_SIZE == HE_KEY_SIZE, "Reuse buffer");
  // use hmac-sha256(transform(HE_KEY), credential_id::nonce) as LargeBlobKey
  int err = read_he_key(output);
  if (err < 0) return err;

  // make it different from hmac extension key
  output[0] ^= output[1];
  output[1] ^= output[2];
  output[HE_KEY_SIZE-2] ^= output[0];
  output[HE_KEY_SIZE-1] ^= output[3];

  hmac_sha256(output, HE_KEY_SIZE, nonce, CREDENTIAL_NONCE_SIZE, output);
  return 0;
}
