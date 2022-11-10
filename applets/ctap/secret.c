// SPDX-License-Identifier: Apache-2.0
#include "secret.h"
#include <apdu.h>
#include <ecc.h>
#include <fs.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>
#include "cose-key.h"

static int key_type_to_cose_alg(key_type_t type) {
  switch (type) {
  case SECP256R1:
    return COSE_ALG_ES256;
  case ED25519:
    return COSE_ALG_EDDSA;
  case SM2:
    return COSE_ALG_SM2;
  default:
    return -65536;
  }
}

static key_type_t cose_alg_to_key_type(int alg) {
  switch (alg) {
  case COSE_ALG_ES256:
    return SECP256R1;
  case COSE_ALG_EDDSA:
    return ED25519;
  case COSE_ALG_SM2:
    return SM2;
  default:
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

static void generate_credential_id_nonce_tag(CredentialId *kh, ecc_key_t *key) {
  // works for ECC algorithms with a 256-bit private key
  random_buffer(kh->nonce, sizeof(kh->nonce));
  // private key = hmac-sha256(device private key, nonce), stored in key.pri
  hmac_sha256(key->pub, KH_KEY_SIZE, kh->nonce, sizeof(kh->nonce), key->pri);
  DBG_MSG("Device key: ");
  PRINT_HEX(key->pub, KH_KEY_SIZE);
  DBG_MSG("Nonce: ");
  PRINT_HEX(kh->nonce, sizeof(kh->nonce));
  DBG_MSG("Private key: ");
  PRINT_HEX(key->pri, KH_KEY_SIZE);
  // tag = left(hmac-sha256(private key, rpIdHash or appid), 16), stored in kh.tag via key.pub
  hmac_sha256(key->pri, KH_KEY_SIZE, kh->rpIdHash, sizeof(kh->rpIdHash), key->pub);
  memcpy(kh->tag, key->pub, sizeof(kh->tag));
}

int generate_key_handle(CredentialId *kh, uint8_t *pubkey, int32_t alg_type) {
  ecc_key_t key;

  int ret = read_kh_key(key.pub); // use key.pub to store kh key first
  if (ret < 0) return ret;

  if (alg_type != COSE_ALG_ES256 && alg_type != COSE_ALG_EDDSA && alg_type != COSE_ALG_SM2) {
    DBG_MSG("Unsupported algo key_type\n");
    memzero(&key, sizeof(key));
    return -1;
  }

  kh->alg_type = alg_type;
  key_type_t key_type = cose_alg_to_key_type(alg_type);

  do {
    generate_credential_id_nonce_tag(kh, &key);
  } while (ecc_complete_key(key_type, &key) < 0);

  memcpy(pubkey, key.pub, PUBLIC_KEY_LENGTH[key_type]);
  DBG_MSG("Public: ");
  PRINT_HEX(pubkey, PUBLIC_KEY_LENGTH[key_type]);
  memzero(&key, sizeof(key));

  return 0;
}

int verify_key_handle(const CredentialId *kh, ecc_key_t *key) {
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
  hmac_sha256(key->pri, KH_KEY_SIZE, kh->rpIdHash, sizeof(kh->rpIdHash), key->pub);
  if (memcmp(key->pub, kh->tag, sizeof(kh->tag)) == 0) {
    memzero(key, sizeof(ecc_key_t));
    return 0;
  }
  memzero(key->pub, sizeof(key->pub));
  return 1;
}

size_t sign_with_device_key(const uint8_t *input, size_t input_len, uint8_t *sig) {
  ecc_key_t key;
  int ret = read_device_pri_key(key.pri);
  if (ret < 0) return ret;
  ecc_sign(SECP256R1, &key, input, input_len, sig);
  memzero(&key, sizeof(key));
  return ecdsa_sig2ansi(PRI_KEY_SIZE, sig, sig);
}

int sign_with_private_key(int32_t alg_type, ecc_key_t *key, const uint8_t *input, size_t len, uint8_t *sig) {
  key_type_t key_type = cose_alg_to_key_type(alg_type);

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
  } else {
    sha256_init();
    sha256_update(input, len);
    sha256_final(sig);
    if (ecc_sign(key_type, key, sig, len, sig) < 0) {
      ERR_MSG("Failed to sign\n");
      return -1;
    }
    DBG_MSG("Raw signature: ");
    PRINT_HEX(sig, SIGNATURE_LENGTH[key_type]);
    return (int) ecdsa_sig2ansi(PRIVATE_KEY_LENGTH[key_type], sig, sig);
  }
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
    err = write_attr(CTAP_CERT_FILE, PIN_ATTR, buf, PIN_HASH_SIZE);
  }
  if (err < 0) return err;
  uint8_t ctr = 8;
  return write_attr(CTAP_CERT_FILE, PIN_CTR_ATTR, &ctr, 1);
}

int verify_pin_hash(uint8_t *buf) {
  uint8_t storedPinHash[PIN_HASH_SIZE];
  int err = read_attr(CTAP_CERT_FILE, PIN_ATTR, storedPinHash, PIN_HASH_SIZE);
  if (err < 0) return err;
  if (memcmp(storedPinHash, buf, PIN_HASH_SIZE) == 0) return 0;
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
  // use hmac-sha256(HE_KEY, CredentialId::nonce) as CredRandom
  int err = read_he_key(hmac_buf);
  if (err < 0) return err;

  hmac_sha256(hmac_buf, HE_KEY_SIZE, nonce, CREDENTIAL_NONCE_SIZE, hmac_buf);
  hmac_sha256(hmac_buf, HE_KEY_SIZE, salt, 32, output);
  if (len == 64) hmac_sha256(hmac_buf, HE_KEY_SIZE, salt + 32, 32, output + 32);
  return 0;
}
