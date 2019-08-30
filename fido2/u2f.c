#include <apdu.h>
#include <block-cipher.h>
#include <ecc.h>
#include <fs.h>
#include <rand.h>
#include <sha.h>
#include <string.h>
#include <u2f.h>

#ifndef htobe32
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe32(x) (x)
#else
#define htobe32(x) __builtin_bswap32(x)
#endif
#endif

/*
 * Key Handle:
 * 32 bytes: app id
 * 32 bytes: private key
 * 64 bytes: public key
 */

#define CERT_FILE "u2f_cert"
#define KEY_FILE "u2f_key"
#define CTR_FILE "u2f_ctr"

volatile static uint8_t pressed;
static block_cipher_config cipher_cfg;

void u2f_press(void) { pressed = 1; }

void u2f_unpress(void) { pressed = 0; }

static int u2f_register(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 64)
    EXCEPT(SW_WRONG_LENGTH);

#ifdef NFC
  pressed = 1;
#endif
  if (!pressed)
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  pressed = 0;

  U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)DATA;
  U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)RDATA;
  uint8_t handle[U2F_APPID_SIZE + U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE];
  memcpy(handle, req->appId, U2F_APPID_SIZE);
  ecc_generate(ECC_SECP256R1, handle + U2F_APPID_SIZE,
               handle + U2F_APPID_SIZE + U2F_EC_KEY_SIZE);

  uint8_t key_buf[U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE + U2F_SECRET_KEY_SIZE];
  int err = read_file(KEY_FILE, key_buf, sizeof(key_buf));
  if (err < 0)
    return err;

  // there are overlaps between req and resp
  sha256_init();
  sha256_update((uint8_t[]){0x00}, 1);
  sha256_update(req->appId, U2F_APPID_SIZE);
  sha256_update(req->chal, U2F_CHAL_SIZE);

  // build response
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
  sha256_update(handle, U2F_KH_SIZE);
  sha256_update((const uint8_t *)&resp->pubKey, U2F_EC_PUB_KEY_SIZE + 1);
  sha256_final(handle);
  ecdsa_sign(ECC_SECP256R1, key_buf, handle, handle + 32);
  size_t signature_len = ecdsa_sig2ansi(
      handle + 32, resp->keyHandleCertSig + U2F_KH_SIZE + cert_len);
  LL = 67 + U2F_KH_SIZE + cert_len + signature_len;
  return 0;
}

static int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)DATA;
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)RDATA;

  if (req->keyHandleLen != U2F_KH_SIZE)
    EXCEPT(SW_WRONG_LENGTH);

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
  if (memcmp(req->appId, req->keyHandle, U2F_APPID_SIZE) != 0)
    EXCEPT(SW_WRONG_DATA);

#ifdef NFC
  pressed = 1;
#endif
  if (P1 == U2F_AUTH_CHECK_ONLY || !pressed)
    EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  pressed = 0;

  uint32_t ctr = 0;
  err = read_file(CTR_FILE, &ctr, sizeof(ctr));
  if (err < 0)
    return err;
  ++ctr;
  err = write_file(CTR_FILE, &ctr, sizeof(ctr));
  if (err < 0)
    return err;
  ctr = htobe32(ctr);

  sha256_init();
  sha256_update(req->appId, U2F_APPID_SIZE);
  sha256_update((uint8_t[]){U2F_AUTH_FLAG_TUP}, 1);
  sha256_update((const uint8_t *)&ctr, sizeof(ctr));
  sha256_update(req->chal, U2F_CHAL_SIZE);
  sha256_final(req->appId);
  ecdsa_sign(ECC_SECP256R1, req->keyHandle + U2F_APPID_SIZE, req->appId,
             resp->sig);
  size_t signature_len = ecdsa_sig2ansi(resp->sig, resp->sig);

  resp->flags = U2F_AUTH_FLAG_TUP;
  memcpy(resp->ctr, &ctr, sizeof(ctr));

  LL = signature_len + 5;
  return 0;
}

static int u2f_version(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0)
    EXCEPT(SW_WRONG_LENGTH);
  LL = 6;
  memcpy(RDATA, "U2F_V2", 6);
  return 0;
}

static int u2f_select(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;

  LL = 6;
  memcpy(RDATA, "U2F_V2", 6);
  return 0;
}

int u2f_install_private_key(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;

  if (LC != U2F_EC_KEY_SIZE)
    EXCEPT(SW_WRONG_LENGTH);

  uint8_t buffer[U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE + U2F_SECRET_KEY_SIZE];
  memcpy(buffer, DATA, LC);
  ecc_get_public_key(ECC_SECP256R1, buffer, buffer + U2F_EC_KEY_SIZE);
  random_buffer(buffer + U2F_EC_KEY_SIZE + U2F_EC_PUB_KEY_SIZE,
                U2F_SECRET_KEY_SIZE);
  int err = write_file(KEY_FILE, buffer, sizeof(buffer));
  if (err < 0)
    return err;

  uint32_t ctr = 0;
  return write_file(CTR_FILE, &ctr, sizeof(ctr));
}

int u2f_install_cert(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC > U2F_MAX_ATT_CERT_SIZE)
    EXCEPT(SW_WRONG_LENGTH);

  return write_file(CERT_FILE, DATA, LC);
}

int u2f_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (CLA != 0x00)
    EXCEPT(SW_CLA_NOT_SUPPORTED);

  int ret;
  switch (INS) {
  case U2F_REGISTER:
    ret = u2f_register(capdu, rapdu);
    break;
  case U2F_AUTHENTICATE:
    ret = u2f_authenticate(capdu, rapdu);
    break;
  case U2F_VERSION:
    ret = u2f_version(capdu, rapdu);
    break;
  case U2F_SELECT:
    ret = u2f_select(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  else
    return 0;
}

void u2f_config(uint8_t block_size,
                int (*enc)(const uint8_t *, uint8_t *, const uint8_t *),
                int (*dec)(const uint8_t *, uint8_t *, const uint8_t *)) {
  cipher_cfg.block_size = block_size;
  cipher_cfg.mode = CTR;
  cipher_cfg.encrypt = enc;
  cipher_cfg.decrypt = dec;
  pressed = 0;
}
