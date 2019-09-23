#include <apdu.h>
#include <ecc.h>
#include <fs.h>
#include <memzero.h>
#include <sha.h>
#include <string.h>
#include <u2f.h>

#include "fido-internal.h"
#include "secret.h"

volatile static uint8_t pressed;

void u2f_press(void) { pressed = 1; }

void u2f_unpress(void) { pressed = 0; }

int u2f_register(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 64) EXCEPT(SW_WRONG_LENGTH);

#ifdef NFC
  pressed = 1;
#endif
  if (!pressed) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  pressed = 0;

  U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)DATA;
  U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)RDATA;
  CredentialId kh;
  uint8_t digest[SHA256_DIGEST_LENGTH];

  memcpy(kh.rpIdHash, req->appId, U2F_APPID_SIZE);
  int err = generate_key_handle(&kh, resp->pubKey.x);
  if (err < 0) return err;

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
  // KEY HANDLE LENGTH (1)
  resp->keyHandleLen = sizeof(CredentialId);
  // KEY HANDLE (128)
  memcpy(resp->keyHandleCertSig, &kh, sizeof(CredentialId));
  // CERTIFICATE (var)
  int cert_len = read_file(CTAP_CERT_FILE, resp->keyHandleCertSig + sizeof(CredentialId), 0, U2F_MAX_ATT_CERT_SIZE);
  if (cert_len < 0) return cert_len;
  // SIG (var)
  sha256_update((const uint8_t *)&kh, sizeof(CredentialId));
  sha256_update((const uint8_t *)&resp->pubKey, U2F_EC_PUB_KEY_SIZE + 1);
  sha256_final(digest);
  size_t signature_len = sign_with_device_key(digest, resp->keyHandleCertSig + sizeof(CredentialId) + cert_len);
  LL = 67 + sizeof(CredentialId) + cert_len + signature_len;
  return 0;
}

int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)DATA;
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)RDATA;
  CTAP_authData auth_data;
  size_t len;
  uint8_t priv_key[ECC_KEY_SIZE];

  if (req->keyHandleLen != sizeof(CredentialId)) EXCEPT(SW_WRONG_LENGTH);

#ifdef NFC
  pressed = 1;
#endif
  if (P1 == U2F_AUTH_CHECK_ONLY || !pressed) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  pressed = 0;

  if (memcmp(req->appId, ((CredentialId *)req->keyHandle)->rpIdHash, U2F_APPID_SIZE) != 0) EXCEPT(SW_WRONG_DATA);

  uint8_t err = verify_key_handle((CredentialId *)req->keyHandle, priv_key);
  if (err) EXCEPT(SW_WRONG_DATA);
  err = ctap_make_auth_data(req->appId, (uint8_t *)&auth_data, 0, 0, 1, &len);
  if (err) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);

  memcpy(resp, &auth_data.flags, 1 + sizeof(auth_data.signCount));
  sha256_init();
  sha256_update((const uint8_t *)&auth_data, U2F_APPID_SIZE + 1 + sizeof(auth_data.signCount));
  sha256_update(req->chal, U2F_CHAL_SIZE);
  sha256_final(req->appId);
  ecdsa_sign(ECC_SECP256R1, priv_key, req->appId, resp->sig);
  memzero(priv_key, sizeof(priv_key));
  size_t signature_len = ecdsa_sig2ansi(resp->sig, resp->sig);

  LL = signature_len + 5;
  return 0;
}

int u2f_version(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  LL = 6;
  memcpy(RDATA, "U2F_V2", 6);
  return 0;
}

int u2f_select(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;
  LL = 6;
  memcpy(RDATA, "U2F_V2", 6);
  return 0;
}

void u2f_config() { pressed = 0; }
