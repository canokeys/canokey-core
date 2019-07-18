#include "u2f.h"
#include <apdu.h>
#include <block-cipher.h>
#include <ecdsa.h>
#include <fs.h>
#include <lfs.h>
#include <rand.h>
#include <sha2.h>
#include <string.h>

/*
 * Key Handle:
 * 32 bytes: app id
 * 32 bytes: private key
 * 64 bytes: public key
 */

#define CERT_FILE "u2f_cert"
#define KEY_FILE "u2f_key"
#define CTR_FILE "u2f_ctr"

volatile static uint8_t pressed = 0;
static block_cipher_config cipher_cfg;

void u2f_press() { pressed = 1; }

void u2f_unpress() { pressed = 0; }

int u2f_register(const CAPDU *capdu, RAPDU *rapdu) {
  if (capdu->lc != 64) {
    rapdu->sw = SW_WRONG_LENGTH;
    rapdu->len = 0;
    return 0;
  }

#ifdef NFC
  pressed = 1;
#endif
  if (!pressed) {
    rapdu->sw = SW_CONDITIONS_NOT_SATISFIED;
    rapdu->len = 0;
    return 0;
  }
  pressed = 0;

  U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)capdu->data;
  U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)rapdu->data;
  uint8_t handle[U2F_APPID_SIZE + U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE];
  memcpy(handle, req->appId, U2F_APPID_SIZE);
  ecdsa_generate(ECDSA_SECP256R1, handle + U2F_APPID_SIZE,
                 handle + U2F_APPID_SIZE + U2F_EC_KEY_SIZE);

  uint8_t key_buf[U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE + U2F_SECRET_KEY_SIZE];
  int err = read_file(KEY_FILE, key_buf, sizeof(key_buf));
  if (err < 0)
    return err;

  // REGISTER ID (1)
  resp->registerId = U2F_REGISTER_ID;
  // PUBLIC KEY (65)
  resp->pubKey.pointFormat = U2F_POINT_UNCOMPRESSED;
  memcpy(resp->pubKey.x, handle + U2F_APPID_SIZE + U2F_EC_KEY_SIZE,
         U2F_EC_PUB_KEY_SIZE);
  // KEY HANDLE LENGTH (1)
  resp->keyHandleLen = U2F_KH_SIZE;
  // KEY HANDLE (128)
  cipher_cfg.in = handle;
  cipher_cfg.out = handle;
  cipher_cfg.in_size = U2F_KH_SIZE;
  cipher_cfg.key = key_buf + U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE;
  cipher_cfg.iv = key_buf;
  block_cipher_enc(&cipher_cfg);
  memcpy(resp->keyHandleCertSig, handle, U2F_KH_SIZE);
  // CERTIFICATE (var)
  int cert_len = read_file(CERT_FILE, resp->keyHandleCertSig + U2F_KH_SIZE,
                           U2F_MAX_ATT_CERT_SIZE);
  if (cert_len < 0)
    return cert_len;
  // SIG (var)
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, (uint8_t[]){0x00}, 1);
  sha256_Update(&ctx, req->appId, U2F_APPID_SIZE);
  sha256_Update(&ctx, req->chal, U2F_CHAL_SIZE);
  sha256_Update(&ctx, handle, U2F_KH_SIZE);
  sha256_Update(&ctx, (const uint8_t *)&resp->pubKey, U2F_EC_PUB_KEY_SIZE + 1);
  sha256_Final(&ctx, handle);
  ecdsa_sign(ECDSA_SECP256R1, key_buf, handle, handle + 32);
  size_t signature_len = ecdsa_sig2ansi(
      handle + 32, resp->keyHandleCertSig + U2F_KH_SIZE + cert_len);
  rapdu->sw = SW_NO_ERROR;
  rapdu->len = 67 + U2F_KH_SIZE + cert_len + signature_len;
  return 0;
}

int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)capdu->data;
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)rapdu->data;

  if (req->keyHandleLen != U2F_KH_SIZE) {
    rapdu->sw = SW_WRONG_LENGTH;
    rapdu->len = 0;
    return 0;
  }

  uint8_t key_buf[U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE + U2F_SECRET_KEY_SIZE];
  int err = read_file(KEY_FILE, key_buf, sizeof(key_buf));
  if (err < 0)
    return err;
  cipher_cfg.in = req->keyHandle;
  cipher_cfg.out = req->keyHandle;
  cipher_cfg.in_size = U2F_KH_SIZE;
  cipher_cfg.key = key_buf + U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE;
  cipher_cfg.iv = key_buf;
  block_cipher_dec(&cipher_cfg);
  if (memcmp(req->appId, req->keyHandle, U2F_APPID_SIZE) != 0) {
    rapdu->sw = SW_WRONG_DATA;
    rapdu->len = 0;
    return 0;
  }

  if (capdu->p1 != U2F_AUTH_ENFORCE) {
    rapdu->sw = SW_WRONG_P1P2;
    rapdu->len = 0;
    return 0;
  }

#ifdef NFC
  pressed = 1;
#endif
  if (capdu->p1 == U2F_AUTH_CHECK_ONLY || !pressed) {
    rapdu->sw = SW_CONDITIONS_NOT_SATISFIED;
    rapdu->len = 0;
    return 0;
  }
  pressed = 0;

  uint32_t ctr = 0;
  err = read_file(CTR_FILE, &ctr, sizeof(ctr));
  if (err < 0)
    return err;
  ++ctr;
  err = write_file(CTR_FILE, &ctr, sizeof(ctr));
  if (err < 0)
    return err;

  resp->flags = U2F_AUTH_FLAG_TUP;
  ctr = htobe32(ctr);
  memcpy(resp->ctr, &ctr, sizeof(ctr));
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, req->appId, U2F_APPID_SIZE);
  sha256_Update(&ctx, (uint8_t[]){U2F_AUTH_FLAG_TUP}, 1);
  sha256_Update(&ctx, (const uint8_t *)&ctr, sizeof(ctr));
  sha256_Update(&ctx, req->chal, U2F_CHAL_SIZE);
  sha256_Final(&ctx, req->appId);

  ecdsa_sign(ECDSA_SECP256R1, req->keyHandle + U2F_APPID_SIZE, req->appId,
             resp->sig);
  size_t signature_len = ecdsa_sig2ansi(resp->sig, resp->sig);

  rapdu->sw = SW_NO_ERROR;
  rapdu->len = signature_len + 5;
  return 0;
}

int u2f_version(const CAPDU *capdu, RAPDU *rapdu) {
  if (capdu->lc != 0) {
    rapdu->sw = SW_WRONG_LENGTH;
    rapdu->len = 0;
    return 0;
  }
  rapdu->sw = SW_NO_ERROR;
  rapdu->len = 6;
  memcpy(rapdu->data, "U2F_V2", 6);
  return 0;
}

int u2f_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (capdu->lc != 8) {
    rapdu->sw = SW_WRONG_LENGTH;
    rapdu->len = 0;
    return 0;
  }
  if (capdu->p1 != 0x04) {
    rapdu->sw = SW_WRONG_P1P2;
    rapdu->len = 0;
    return 0;
  }
  if (memcmp(capdu->data,
             (uint8_t[]){0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01},
             8) != 0) {
    rapdu->sw = SW_WRONG_DATA;
    rapdu->len = 0;
    return 0;
  }
  rapdu->sw = SW_NO_ERROR;
  rapdu->len = 6;
  memcpy(rapdu->data, "U2F_V2", 6);
  return 0;
}

int u2f_personalization(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;

  uint8_t buffer[U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE + U2F_SECRET_KEY_SIZE];
  ecdsa_generate(ECDSA_SECP256R1, buffer, buffer + U2F_EC_KEY_SIZE);
  random_buffer(buffer + U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE,
                U2F_SECRET_KEY_SIZE);
  int err = write_file(KEY_FILE, buffer, sizeof(buffer));
  if (err < 0)
    return err;

  uint32_t ctr = 0;
  err = write_file(CTR_FILE, &ctr, sizeof(ctr));
  if (err < 0)
    return err;

  rapdu->sw = SW_NO_ERROR;
  rapdu->len = U2F_EC_PUB_KEY_SIZE;
  memcpy(rapdu->data, buffer + U2F_EC_KEY_SIZE, U2F_EC_PUB_KEY_SIZE);
  return 0;
}

int u2f_install_cert(const CAPDU *capdu, RAPDU *rapdu) {
  if (capdu->lc > U2F_MAX_ATT_CERT_SIZE) {
    rapdu->sw = SW_WRONG_LENGTH;
    rapdu->len = 0;
    return 0;
  }

  int err = write_file(CERT_FILE, capdu->data, capdu->lc);
  if (err < 0)
    return err;

  rapdu->sw = SW_NO_ERROR;
  rapdu->len = 0;
  return 0;
}

int u2f_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  if (capdu->cla == 0x00) {
    switch (capdu->ins) {
    case U2F_REGISTER:
      return u2f_register(capdu, rapdu);
    case U2F_AUTHENTICATE:
      return u2f_authenticate(capdu, rapdu);
    case U2F_VERSION:
      return u2f_version(capdu, rapdu);
    case U2F_SELECT:
      return u2f_select(capdu, rapdu);
    }
    rapdu->sw = SW_INS_NOT_SUPPORTED;
    rapdu->len = 0;
    return 0;
  }
  if (capdu->cla == 0x80) {
    switch (capdu->ins) {
    case U2F_PERSONALIZATION:
      return u2f_personalization(capdu, rapdu);
    case U2F_INSTALL_CERT:
      return u2f_install_cert(capdu, rapdu);
    }
    rapdu->sw = SW_INS_NOT_SUPPORTED;
    rapdu->len = 0;
    return 0;
  }
  rapdu->sw = SW_CLA_NOT_SUPPORTED;
  rapdu->len = 0;
  return 0;
}

void u2f_config(void (*enc)(const uint8_t *in, uint8_t *out,
                            const uint8_t *key),
                void (*dec)(const uint8_t *in, uint8_t *out,
                            const uint8_t *key)) {
  cipher_cfg.block_size = 16;
  cipher_cfg.mode = CTR;
  cipher_cfg.encrypt = enc;
  cipher_cfg.decrypt = dec;
}
