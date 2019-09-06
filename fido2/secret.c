#include "secret.h"
#include <ecc.h>
#include <fs.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>

#define CTAP_CERT "ctap_cert"
#define KEY_ATTR 0x00
#define CTR_ATTR 0x01

static int read_keys(uint8_t *prikey) {
  int ret = read_attr(CTAP_CERT, KEY_ATTR, prikey, ECC_KEY_SIZE);
  if (ret < 0) return ret;
  return 0;
}

int get_sign_counter(uint32_t *counter) {
  int ret = read_attr(CTAP_CERT, CTR_ATTR, counter, sizeof(uint32_t));
  if (ret < 0) return ret;
  return 0;
}

int increase_counter(uint32_t *counter) {
  int ret = read_attr(CTAP_CERT, CTR_ATTR, counter, sizeof(uint32_t));
  if (ret < 0) return ret;
  ++*counter;
  ret = write_attr(CTAP_CERT, CTR_ATTR, counter, sizeof(uint32_t));
  if (ret < 0) return ret;
  return 0;
}

int generate_key_handle(KeyHandle *kh, uint8_t *pubkey) {
  int ret = read_keys(pubkey); // use pubkey as key buffer
  if (ret < 0) return ret;
  do {
    random_buffer(kh->nonce, sizeof(kh->nonce));
    // private key = hmac-sha256(device private key, nonce), stored in pubkey[0:32)
    hmac_sha256(pubkey, ECC_KEY_SIZE, kh->nonce, sizeof(kh->nonce), pubkey);
    // tag = left(hmac-sha256(private key, rpIdHash or appid), 16), stored in pubkey[32, 64)
    hmac_sha256(pubkey, ECC_KEY_SIZE, kh->rpIdHash, sizeof(kh->rpIdHash), pubkey + ECC_KEY_SIZE);
    memcpy(kh->tag, pubkey + ECC_KEY_SIZE, sizeof(kh->tag));
  } while (ecc_get_public_key(ECC_SECP256R1, pubkey, pubkey) < 0);
  return 0;
}

int verify_key_handle(KeyHandle *kh) {
  uint8_t prikey[ECC_KEY_SIZE];
  int ret = read_keys(prikey);
  if (ret < 0) return ret;
  // get private key
  hmac_sha256(prikey, ECC_KEY_SIZE, kh->nonce, sizeof(kh->nonce), prikey);
  // get tag, store in rpIdHash, which should be verified first outside of this function
  hmac_sha256(prikey, ECC_KEY_SIZE, kh->rpIdHash, sizeof(kh->rpIdHash), kh->rpIdHash);
  if (memcmp(kh->rpIdHash, kh->tag, sizeof(kh->tag)) == 0) {
    // store prikey to rpIdHash
    memcpy(kh->rpIdHash, prikey, sizeof(prikey));
    memzero(prikey, sizeof(prikey));
    return 0;
  }
  memzero(prikey, sizeof(prikey));
  return 1;
}

size_t sign_with_device_key(const uint8_t *digest, uint8_t *sig) {
  int ret = read_keys(sig);
  if (ret < 0) return ret;
  ecdsa_sign(ECC_SECP256R1, sig, digest, sig);
  return ecdsa_sig2ansi(sig, sig);
}

size_t sign_with_private_key(const uint8_t *key, const uint8_t *digest, uint8_t *sig) {
  ecdsa_sign(ECC_SECP256R1, key, digest, sig);
  return ecdsa_sig2ansi(sig, sig);
}

int get_cert(uint8_t *buf) { return read_file(CTAP_CERT, buf, MAX_CERT_SIZE); }
