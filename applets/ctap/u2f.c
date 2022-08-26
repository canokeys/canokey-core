// SPDX-License-Identifier: Apache-2.0
#include "u2f.h"
#include <apdu.h>
#include <device.h>
#include <ecc.h>
#include <fs.h>
#include <memzero.h>
#include <sha.h>
#include <string.h>

#include "ctap-internal.h"
#include "secret.h"
#include "cose-key.h"

int u2f_register(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 64) EXCEPT(SW_WRONG_LENGTH);

  if (!is_nfc()) {
    start_blinking(2);
    if (get_touch_result() == TOUCH_NO) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    set_touch_result(TOUCH_NO);
    stop_blinking();
  }

  U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *) DATA;
  U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *) RDATA;
  credential_id kh;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  uint8_t pubkey[PUB_KEY_SIZE];

  memcpy(kh.rp_id_hash, req->appId, U2F_APPID_SIZE);
  int err = generate_key_handle(&kh, pubkey, COSE_ALG_ES256, false);
  if (err < 0) return err;

  // there are overlaps between req and resp
  sha256_init();
  sha256_update((uint8_t[]) {0x00}, 1);
  sha256_update(req->appId, U2F_APPID_SIZE);
  sha256_update(req->chal, U2F_CHAL_SIZE);

  // build response
  // REGISTER ID (1)
  resp->registerId = U2F_REGISTER_ID;
  // PUBLIC KEY (65)
  resp->pubKey.pointFormat = U2F_POINT_UNCOMPRESSED;
  memcpy(resp->pubKey.x, pubkey, PUB_KEY_SIZE); // accessing out of bounds is intentional.
  // KEY HANDLE LENGTH (1)
  resp->keyHandleLen = sizeof(credential_id);
  // KEY HANDLE (128)
  memcpy(resp->keyHandleCertSig, &kh, sizeof(credential_id));
  // CERTIFICATE (var)
  int cert_len = read_file(CTAP_CERT_FILE, resp->keyHandleCertSig + sizeof(credential_id), 0, U2F_MAX_ATT_CERT_SIZE);
  if (cert_len < 0) return cert_len;
  // SIG (var)
  sha256_update((const uint8_t *) &kh, sizeof(credential_id));
  sha256_update((const uint8_t *) &resp->pubKey, U2F_EC_PUB_KEY_SIZE + 1);
  sha256_final(digest);
  size_t signature_len = sign_with_device_key(digest, resp->keyHandleCertSig + sizeof(credential_id) + cert_len);
  LL = 67 + sizeof(credential_id) + cert_len + signature_len;

  return 0;
}

int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *) DATA;
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *) RDATA;
  CTAP_auth_data auth_data;
  size_t len;
  uint8_t priv_key[PRI_KEY_SIZE];

  if (LC != sizeof(U2F_AUTHENTICATE_REQ)) EXCEPT(SW_WRONG_DATA); // required by FIDO Conformance Tool
  if (req->keyHandleLen != sizeof(credential_id)) EXCEPT(SW_WRONG_LENGTH);
  if (memcmp(req->appId, ((credential_id *) req->keyHandle)->rp_id_hash, U2F_APPID_SIZE) != 0) EXCEPT(SW_WRONG_DATA);
  uint8_t err = verify_key_handle((credential_id *) req->keyHandle, priv_key, false);
  if (err) EXCEPT(SW_WRONG_DATA);

  if (P1 == U2F_AUTH_CHECK_ONLY) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
  if (!is_nfc()) {
    start_blinking(2);
    if (get_touch_result() == TOUCH_NO) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    set_touch_result(TOUCH_NO);
    stop_blinking();
  }

  len = sizeof(auth_data);
  uint8_t flags = FLAGS_UP;
  err = ctap_make_auth_data(req->appId, (uint8_t *) &auth_data, flags, 0, NULL, &len, COSE_ALG_ES256, false);
  if (err) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);

  sha256_init();
  sha256_update((const uint8_t *) &auth_data, U2F_APPID_SIZE + 1 + sizeof(auth_data.sign_count));
  sha256_update(req->chal, U2F_CHAL_SIZE);
  sha256_final(req->appId);
  memcpy(resp, &auth_data.flags, 1 + sizeof(auth_data.sign_count));
  ecdsa_sign(ECC_SECP256R1, priv_key, req->appId, resp->sig);
  memzero(priv_key, sizeof(priv_key));
  size_t signature_len = ecdsa_sig2ansi(U2F_EC_KEY_SIZE, resp->sig, resp->sig);
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
  (void) capdu;
  LL = 6;
  memcpy(RDATA, "U2F_V2", 6);
  return 0;
}
