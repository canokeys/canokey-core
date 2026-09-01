// SPDX-License-Identifier: Apache-2.0
#include "u2f.h"
#include <applet-scratch.h>
#include <apdu.h>
#include <crypto-util.h>
#include <device.h>
#include <ecc.h>
#include <fs.h>
#include <memzero.h>
#include <sha.h>
#include <string.h>

#include "ctap-internal.h"
#include "secret.h"
#include "cose-key.h"

typedef struct {
  uint8_t register_id;
  U2F_EC_POINT pub_key;
  uint8_t key_handle_len;
  credential_id key_handle;
} __packed U2F_register_prefix;

typedef struct {
  uint16_t cert_len;
  uint8_t sig_len;
} U2F_register_stream_state;

static U2F_register_stream_state u2f_register_stream_state;

#define u2f_register_stream_buffer applet_session_scratch.buffer

static int u2f_register_stream_read_at(void *ctx, uint32_t offset, uint8_t *buf, uint16_t len) {
  U2F_register_stream_state *state = (U2F_register_stream_state *)ctx;
  const uint8_t *stream_buf = u2f_register_stream_buffer;
  const size_t prefix_len = sizeof(U2F_register_prefix);
  size_t copied = 0;

  if (offset < prefix_len) {
    size_t n = MIN((size_t)len, prefix_len - offset);
    memcpy(buf, stream_buf + offset, n);
    copied += n;
    offset += (uint32_t)n;
  }

  if (copied < len && offset < prefix_len + state->cert_len) {
    size_t cert_off = offset - prefix_len;
    size_t to_read = MIN((size_t)len - copied, (size_t)state->cert_len - cert_off);
    int ret = read_file(CTAP_CERT_FILE, buf + copied, (lfs_soff_t)cert_off, (lfs_size_t)to_read);
    if (ret < 0) return ret;
    copied += (size_t)ret;
    offset += (uint32_t)ret;
    if ((size_t)ret != to_read) return (int)copied;
  }

  if (copied < len) {
    size_t sig_off = offset - prefix_len - state->cert_len;
    if (sig_off < state->sig_len) {
      size_t n = MIN((size_t)len - copied, (size_t)state->sig_len - sig_off);
      memcpy(buf + copied, stream_buf + prefix_len + sig_off, n);
      copied += n;
    }
  }

  return (int)copied;
}

int u2f_register(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != 64) EXCEPT(SW_WRONG_LENGTH);

  if (!is_nfc()) {
    start_blinking(2);
    if (get_touch_result() == TOUCH_NO) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    set_touch_result(TOUCH_NO);
    stop_blinking();
  }

  U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)DATA;
  U2F_register_prefix *resp = (U2F_register_prefix *)u2f_register_stream_buffer;
  credential_id kh;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  uint8_t pubkey[PUB_KEY_SIZE];
  sha256_ctx_t sha256;

  memcpy(kh.rp_id_hash, req->appId, U2F_APPID_SIZE);
  int err = generate_key_handle(&kh, pubkey, COSE_ALG_ES256, 0, CRED_PROTECT_VERIFICATION_OPTIONAL, false);
  if (err < 0) return err;

  // there are overlaps between req and resp
  sha256_init(&sha256);
  sha256_update(&sha256, (uint8_t[]){0x00}, 1);
  sha256_update(&sha256, req->appId, U2F_APPID_SIZE);
  sha256_update(&sha256, req->chal, U2F_CHAL_SIZE);

  // build response
  // REGISTER ID (1)
  resp->register_id = U2F_REGISTER_ID;
  // PUBLIC KEY (65)
  resp->pub_key.pointFormat = U2F_POINT_UNCOMPRESSED;
  memcpy(resp->pub_key.x, pubkey, PUB_KEY_SIZE); // accessing out of bounds is intentional.
  // KEY HANDLE LENGTH (1)
  resp->key_handle_len = sizeof(credential_id);
  memcpy(&resp->key_handle, &kh, sizeof(credential_id));
  int cert_len = get_file_size(CTAP_CERT_FILE);
  if (cert_len < 0 || cert_len > U2F_MAX_ATT_CERT_SIZE) return -1;
  // SIG (var)
  sha256_update(&sha256, (const uint8_t *)&kh, sizeof(credential_id));
  sha256_update(&sha256, (const uint8_t *)&resp->pub_key, U2F_EC_PUB_KEY_SIZE + 1);
  sha256_final(&sha256, digest);
  size_t signature_len =
      sign_with_device_key(digest, PRIVATE_KEY_LENGTH[SECP256R1], u2f_register_stream_buffer + sizeof(*resp));
  if (signature_len > U2F_MAX_EC_SIG_SIZE) return -1;

  u2f_register_stream_state.cert_len = (uint16_t)cert_len;
  u2f_register_stream_state.sig_len = (uint8_t)signature_len;
  apdu_response_source_set((uint32_t)sizeof(*resp) + (uint32_t)cert_len + (uint32_t)signature_len, SW_NO_ERROR,
                           u2f_register_stream_read_at, NULL, &u2f_register_stream_state);
  LL = 0;

  return 0;
}

int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)DATA;
  U2F_AUTHENTICATE_RESP *resp = (U2F_AUTHENTICATE_RESP *)RDATA;
  CTAP_auth_data auth_data;
  size_t len;
  ecc_key_t key; // TODO: cleanup
  sha256_ctx_t sha256;

  if (LC != sizeof(U2F_AUTHENTICATE_REQ)) EXCEPT(SW_WRONG_DATA); // required by FIDO Conformance Tool
  if (req->keyHandleLen != sizeof(credential_id)) EXCEPT(SW_WRONG_LENGTH);
  if (memcmp_s(req->appId, ((credential_id *)req->keyHandle)->rp_id_hash, U2F_APPID_SIZE) != 0) EXCEPT(SW_WRONG_DATA);
  uint8_t err = verify_key_handle((credential_id *)req->keyHandle, &key);
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
  err = ctap_make_auth_data(req->appId, (uint8_t *)&auth_data, flags, NULL, 0, &len, COSE_ALG_ES256, false, 0);
  if (err) EXCEPT(SW_CONDITIONS_NOT_SATISFIED);

  sha256_init(&sha256);
  sha256_update(&sha256, (const uint8_t *)&auth_data, U2F_APPID_SIZE + 1 + sizeof(auth_data.sign_count));
  sha256_update(&sha256, req->chal, U2F_CHAL_SIZE);
  sha256_final(&sha256, req->appId);
  memcpy(resp, &auth_data.flags, 1 + sizeof(auth_data.sign_count));
  ecc_sign(SECP256R1, &key, req->appId, PRIVATE_KEY_LENGTH[SECP256R1], resp->sig);
  memzero(&key, sizeof(key));
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

int u2f_select(const CAPDU *capdu __attribute__((unused)), RAPDU *rapdu) {
  LL = 6;
  memcpy(RDATA, "U2F_V2", 6);
  return 0;
}
