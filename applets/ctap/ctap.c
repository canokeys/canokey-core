// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-internal.h"
#include "ctap-parser.h"
#include "secret.h"
#include "u2f.h"
#include <block-cipher.h>
#include <cbor.h>
#include <common.h>
#include <crypto-util.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if ((ret) != 0) ERR_MSG("CHECK_PARSER_RET %#x\n", ret);                                                            \
    if ((ret) > 0) return ret;                                                                                         \
  } while (0)

#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if ((ret) != 0) ERR_MSG("CHECK_CBOR_RET %#x\n", ret);                                                              \
    if ((ret) != 0) return CTAP2_ERR_INVALID_CBOR;                                                                     \
  } while (0)

#define SET_RESP()                                                                                                     \
  do {                                                                                                                 \
    if (*resp == 0)                                                                                                    \
      *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1);                                                \
    else                                                                                                               \
      *resp_len = 1;                                                                                                   \
  } while (0)

#define WAIT(timeout_response)                                                                                         \
  do {                                                                                                                 \
    if (is_nfc()) break;\
    switch (wait_for_user_presence(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID)) {                                                              \
    case USER_PRESENCE_CANCEL:                                                                                         \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      return timeout_response;                                                                                         \
    }                                                                                                                  \
  } while (0)

#define KEEPALIVE()                                                                                                    \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    send_keepalive_during_processing(current_cmd_src == CTAP_SRC_HID ? WAIT_ENTRY_CTAPHID : WAIT_ENTRY_CCID);                                                              \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};

// pin & command states
static uint8_t consecutive_pin_counter, last_cmd;
// source of APDU in process 
static ctap_src_t current_cmd_src;
// SM2 attr
CTAP_sm2_attr ctap_sm2_attr;

uint8_t ctap_install(uint8_t reset) {
  consecutive_pin_counter = 3;
  last_cmd = CTAP_INVALID_CMD;
  current_cmd_src = CTAP_SRC_NONE;
  cp_initialize();
  if (!reset && get_file_size(LB_FILE) >= 0) {
    if (read_attr(CTAP_CERT_FILE, SM2_ATTR, &ctap_sm2_attr, sizeof(ctap_sm2_attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    DBG_MSG("CTAP initialized\n");
    return 0;
  }
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_file(DC_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(DC_FILE, DC_GENERAL_ATTR, kh_key, sizeof(CTAP_dc_general_attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(DC_META_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(CTAP_CERT_FILE, NULL, 0, 0, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, kh_key, 4) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, HE_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memcpy(kh_key,
         (uint8_t[]) {0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
                      0x3c}, 17);
  if (write_file(LB_FILE, kh_key, 0, 17, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memzero(kh_key, sizeof(kh_key));
  DBG_MSG("CTAP reset and initialized\n");
  return 0;
}

int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != PRI_KEY_SIZE) EXCEPT(SW_WRONG_LENGTH);
  // initialize SM2 config
  ctap_sm2_attr.enabled = 0;
  ctap_sm2_attr.curve_id = 9; // An unused one. See https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
  ctap_sm2_attr.algo_id = -48; // An unused one. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  if (write_attr(CTAP_CERT_FILE, SM2_ATTR, &ctap_sm2_attr, sizeof(ctap_sm2_attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  return write_attr(CTAP_CERT_FILE, KEY_ATTR, DATA, LC);
}

int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC > MAX_CERT_SIZE) EXCEPT(SW_WRONG_LENGTH);
  return write_file(CTAP_CERT_FILE, DATA, 0, LC, 1);
}

int ctap_read_sm2_config(const CAPDU *capdu, RAPDU *rapdu) {
  UNUSED(capdu);
  const int ret = read_attr(CTAP_CERT_FILE, SM2_ATTR, RDATA, sizeof(ctap_sm2_attr));
  if (ret < 0) return ret;
  LL = ret;
  return 0;
}

int ctap_write_sm2_config(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != sizeof(ctap_sm2_attr)) EXCEPT(SW_WRONG_LENGTH);
  const int ret = write_attr(CTAP_CERT_FILE, SM2_ATTR, DATA, sizeof(ctap_sm2_attr));
  memcpy(&ctap_sm2_attr, DATA, sizeof(ctap_sm2_attr));
  return ret;
}

static int build_ecdsa_cose_key(uint8_t *data, int algo, int curve) {
  uint8_t buf[80];
  CborEncoder encoder, map_encoder;

  cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
  CborError ret = cbor_encoder_create_map(&encoder, &map_encoder, 5);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_KTY);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_KTY_EC2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_ALG);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, algo);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_CRV);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, curve);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_X);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map_encoder, data, 32);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_Y);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map_encoder, data + 32, 32);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&encoder, &map_encoder);
  CHECK_CBOR_RET(ret);

  const int len = cbor_encoder_get_buffer_size(&encoder, buf);
  memcpy(data, buf, len);
  return len;
}

static int build_ed25519_cose_key(uint8_t *data) {
  uint8_t buf[50];
  CborEncoder encoder, map_encoder;

  cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
  CborError ret = cbor_encoder_create_map(&encoder, &map_encoder, 4);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_KTY);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_KTY_OKP);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_ALG);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_ALG_EDDSA);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_CRV);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_CRV_ED25519);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map_encoder, COSE_KEY_LABEL_X);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map_encoder, data, 32);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&encoder, &map_encoder);
  CHECK_CBOR_RET(ret);

  const int len = cbor_encoder_get_buffer_size(&encoder, buf);
  memcpy(data, buf, len);
  return len;
}

int ctap_consistency_check(void) {
  CTAP_dc_general_attr attr;
  if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (attr.pending_add || attr.pending_delete) {
    DBG_MSG("Rolling back credential operations\n");
    if (get_file_size(DC_FILE) >= ((int) attr.index + 1) * (int) sizeof(CTAP_discoverable_credential)) {
      CTAP_discoverable_credential dc;
      if (read_file(DC_FILE, &dc, attr.index * (int) sizeof(CTAP_discoverable_credential),
                    sizeof(CTAP_discoverable_credential)) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      if (!dc.deleted) {
        // delete the credential that had been written
        DBG_MSG("Delete cred at %hhu\n", attr.index);
        dc.deleted = true;
        if (write_file(DC_FILE, &dc, attr.index * (int) sizeof(CTAP_discoverable_credential),
                      sizeof(CTAP_discoverable_credential), 0) < 0)
          return CTAP2_ERR_UNHANDLED_REQUEST;
      }
    }
    // delete the meta then
    int nr_rp = get_file_size(DC_META_FILE);
    if (nr_rp < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    nr_rp /= sizeof(CTAP_rp_meta);
    for (int i = 0; i < nr_rp; ++i) {
      CTAP_rp_meta meta;
      int size = read_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if ((meta.slots & (1ull << attr.index)) != 0) {
        DBG_MSG("Orig slot bitmap: 0x%llx\n", meta.slots);
        meta.slots &= ~(1ull << attr.index);
        DBG_MSG("New slot bitmap: 0x%llx\n", meta.slots);
        size = write_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta), 0);
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        break;
      }
    }
    if (attr.pending_delete)
      attr.numbers--;

    attr.pending_add = 0;
    attr.pending_delete = 0;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  return 0;
}

uint8_t ctap_make_auth_data(uint8_t *rp_id_hash, uint8_t *buf, uint8_t flags, const uint8_t *extension,
                            size_t extension_size, size_t *len, int32_t alg_type, bool dc, uint8_t cred_protect) {
  // See https://www.w3.org/TR/webauthn/#sec-authenticator-data
  // auth data is a byte string
  // --------------------------------------------------------------------------------
  //  Name       |  Length  | Description
  // ------------|----------|---------------------------------------------------------
  //  rp_id_hash |  32      | SHA256 of rp_id, we generate it outside this function
  //  flags      |  1       | 0: UP, 2: UV, 6: AT, 7: ED
  //  sign_count |  4       | 32-bit endian number
  //  attCred    |  var     | Exist iff in authenticatorMakeCredential request
  //             |          | 16-byte aaguid
  //             |          | 2-byte key handle length
  //             |          | key handle
  //             |          | public key (in COSE_key format)
  //  extension  |  var     | Build outside
  // --------------------------------------------------------------------------------
  size_t outLen = 37; // without attCred
  CTAP_auth_data *ad = (CTAP_auth_data *) buf;
  if (*len < outLen) return CTAP2_ERR_LIMIT_EXCEEDED;

  memcpy(ad->rp_id_hash, rp_id_hash, sizeof(ad->rp_id_hash));
  ad->flags = flags;

  uint32_t ctr;
  if (increase_counter(&ctr) < 0) {
    DBG_MSG("Fail to increase the counter\n");
    return CTAP2_ERR_UNHANDLED_REQUEST;
  }
  ad->sign_count = htobe32(ctr);

  if (flags & FLAGS_AT) {
    if (*len < outLen + sizeof(ad->at) - 1) {
      DBG_MSG("Attestation is too long\n");
      return CTAP2_ERR_LIMIT_EXCEEDED;
    }

    // If no credProtect extension was included in the request the authenticator SHOULD use the default value of 1 for compatibility with CTAP2.0 platforms.
    if (cred_protect == CRED_PROTECT_ABSENT) cred_protect = CRED_PROTECT_VERIFICATION_OPTIONAL;

    memcpy(ad->at.aaguid, aaguid, sizeof(aaguid));
    ad->at.credential_id_length = htobe16(sizeof(credential_id));
    memcpy(ad->at.credential_id.rp_id_hash, rp_id_hash, sizeof(ad->at.credential_id.rp_id_hash));
    if (generate_key_handle(&ad->at.credential_id, ad->at.public_key, alg_type, (uint8_t)dc, cred_protect) < 0) {
      DBG_MSG("Fail to generate a key handle\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    int cose_key_size;
    if (alg_type == COSE_ALG_ES256) {
      cose_key_size = build_ecdsa_cose_key(ad->at.public_key, COSE_ALG_ES256, COSE_KEY_CRV_P256);
    } else if (alg_type == COSE_ALG_EDDSA) {
      cose_key_size = build_ed25519_cose_key(ad->at.public_key);
    } else if (alg_type == ctap_sm2_attr.algo_id) {
      cose_key_size = build_ecdsa_cose_key(ad->at.public_key, ctap_sm2_attr.algo_id, ctap_sm2_attr.curve_id);
    } else {
      DBG_MSG("Unknown algorithm type\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    outLen += sizeof(ad->at) - sizeof(ad->at.public_key) + cose_key_size;
  }
  if (flags & FLAGS_ED) {
    if (*len < outLen + extension_size) {
      DBG_MSG("Extension is too long\n");
      return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    memcpy(buf + outLen, extension, extension_size);
    outLen += extension_size;
  }
  *len = outLen;
  return 0;
}

static uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg
  uint8_t data_buf[sizeof(CTAP_auth_data)];
  CborParser parser;
  CTAP_make_credential mc;

  int ret = parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);

  ret = ctap_consistency_check();
  CHECK_PARSER_RET(ret);
  KEEPALIVE();

  // 1. If authenticator supports clientPin features and the platform sends a zero length pin_uv_auth_param
  if ((mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && mc.pin_uv_auth_param_len == 0) {
    // a. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    // b. If the user declines permission, or the operation times out, then end the operation by returning
    //    CTAP2_ERR_OPERATION_DENIED.
    WAIT(CTAP2_ERR_OPERATION_DENIED);
    // c. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
    //    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    if (has_pin())
      return CTAP2_ERR_PIN_INVALID;
    else
      return CTAP2_ERR_PIN_NOT_SET;
  }

  // 2. If the pin_uv_auth_param parameter is present
  //   a. If the pinUvAuthProtocol parameter’s value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
  //     > This has been processed when parsing.
  //   b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
  if ((mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) &&
      !(mc.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
    DBG_MSG("Missing required pin_uv_auth_protocol\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }
  // 3. Validate pubKeyCredParams with the following steps
  //    > This has been processed when parsing.

  // 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as false.
  bool uv = false; // up is always true, see 14.c

  // 5. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (mc.options.uv == OPTION_ABSENT) mc.options.uv = OPTION_FALSE;
  //    b. If the pin_uv_auth_param is present, let the "uv" option be treated as being present with the value false.
  if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) mc.options.uv = OPTION_FALSE;
  //    c. If the "uv" option is true then
  if (mc.options.uv == OPTION_TRUE) {
    //     1) If the authenticator does not support a built-in user verification method end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
    DBG_MSG("Rule 5-c-1 not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
    //     2) [N/A] If the built-in user verification method has not yet been enabled, end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
  }
  //    d. If the "rk" option is present then: DO NOTHING
  //    e. Else: (the "rk" option is absent): Let the "rk" option be treated as being present with the value false.
  if (mc.options.rk == OPTION_ABSENT) mc.options.rk = OPTION_FALSE;
  //    f. If the "up" option is present then:
  //       If the "up" option is false, end the operation by returning CTAP2_ERR_INVALID_OPTION.
  if (mc.options.up == OPTION_FALSE) {
    DBG_MSG("Rule 5-f not satisfied\n");
    return CTAP2_ERR_INVALID_OPTION;
  }
  //    g. If the "up" option is absent, let the "up" option be treated as being present with the value true
  mc.options.up = OPTION_TRUE;

  // 6. [N/A] If the alwaysUv option ID is present and true

  // 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response
  //    If the following statements are all true:
  //    a) The authenticator is protected by some form of user verification.
  //    b) [ALWAYS TRUE] The "uv" option is set to false.
  //    c) The pin_uv_auth_param parameter is not present.
  //    d) The "rk" option is present and set to true.
  if (has_pin() /* a) */ && (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0 /* c) */ &&
      mc.options.rk == OPTION_TRUE) {
    // If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    // end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    DBG_MSG("Rule 7 not satisfied\n");
    return CTAP2_ERR_PUAT_REQUIRED;
    // [N/A] Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
  }

  // 8. [N/A] Else (the makeCredUvNotRqd option ID is present with the value false or is absent)

  // 9. [N/A] If the enterpriseAttestation parameter is present

  // 10. If the following statements are all true
  //     a) "rk" and "uv" [ALWAYS TRUE] options are both set to false or omitted.
  //     b) [ALWAYS TRUE] the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
  //     c) the pin_uv_auth_param parameter is not present.
  //     Then go to Step 12.
  if (mc.options.rk == OPTION_FALSE && (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0) {
    DBG_MSG("Rule 10 satisfied, go to Step 12\n");
    goto step12;
  }

  // 11. If the authenticator is protected by some form of user verification, then:
  if (has_pin()) {
    //   11.1 If pin_uv_auth_param parameter is present (implying the "uv" option is false (see Step 5)):
    if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
      //   a) Call verify(pinUvAuthToken, client_data_hash, pin_uv_auth_param).
      //      If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
      if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      if (!cp_verify_pin_token(mc.client_data_hash, sizeof(mc.client_data_hash), mc.pin_uv_auth_param,
                              mc.pin_uv_auth_protocol)) {
        DBG_MSG("Fail to verify pin token\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //   b) Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
      if (!cp_has_permission(CP_PERMISSION_MC)) {
        DBG_MSG("Fail to verify pin permission\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //   c) If the pinUvAuthToken has a permissions RP ID associated:
      //      If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
      if (!cp_verify_rp_id(mc.rp_id_hash)) {
        DBG_MSG("Fail to verify pin rp id\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //   d) Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
      //   e) If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
      if (!cp_get_user_verified_flag_value()) {
        DBG_MSG("userVerifiedFlagValue is false\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //   f) If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
      uv = true;
      //   g) If the pinUvAuthToken does not have a permissions RP ID associated:
      //      Associate the request’s rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
      cp_associate_rp_id(mc.rp_id_hash);
      DBG_MSG("PIN verified\n");
    }
    //   11.2 [N/A] If the "uv" option is present and set to true
  }

  step12:
  // 12. If the exclude_list parameter is present and contains a credential ID created by this authenticator,
  //     that is bound to the specified rp.id:
  if (mc.exclude_list_size > 0) {
    for (size_t i = 0; i < mc.exclude_list_size; ++i) {
      ecc_key_t key;
      parse_credential_descriptor(&mc.exclude_list, data_buf); // save credential id in data_buf
      credential_id *kh = (credential_id *) data_buf;
      // compare rp_id first
      if (memcmp_s(kh->rp_id_hash, mc.rp_id_hash, sizeof(kh->rp_id_hash)) != 0) goto next_exclude_list;
      // then verify key handle and get private key in rp_id_hash
      ret = verify_key_handle(kh, &key);
      memzero(&key, sizeof(key));
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (ret == 0) {
        DBG_MSG("Exclude ID found\n");
        // a) If the credential’s credProtect value is not userVerificationRequired
        if (kh->nonce[CREDENTIAL_NONCE_CP_POS] != CRED_PROTECT_VERIFICATION_REQUIRED ||
        // b) Else (implying the credential’s credProtect value is userVerificationRequired)
        //    AND If the "uv" bit is true in the response:
          (kh->nonce[CREDENTIAL_NONCE_CP_POS] == CRED_PROTECT_VERIFICATION_REQUIRED && uv)) {

          //    i. Let userPresentFlagValue be false.
          bool userPresentFlagValue = false;
          //    ii. If the pinUvAuthParam parameter is present then let userPresentFlagValue be the result of calling
          //        getUserPresentFlagValue().
          if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) userPresentFlagValue = cp_get_user_present_flag_value();
          //    iii. [N/A] Else, if evidence of user interaction was provided as part of Step 11 let userPresentFlagValue be true.
          //    iv. If userPresentFlagValue is false, then:
          //        (1) Wait for user presence.
          //        (2) Regardless of whether user presence is obtained or the authenticator times out,
          //            terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
          if (!userPresentFlagValue) WAIT(CTAP2_ERR_CREDENTIAL_EXCLUDED);
          //    v. Else, (implying userPresentFlagValue is true) terminate this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED.
          return CTAP2_ERR_CREDENTIAL_EXCLUDED;

        // c) Else (implying user verification was not collected in Step 11),
        //    remove the credential from the excludeList and continue parsing the rest of the list.
        } else {
          DBG_MSG("Ignore this Exclude ID\n");
        }
      }
      next_exclude_list:
      ret = cbor_value_advance(&mc.exclude_list);
      CHECK_CBOR_RET(ret);
    }
  }

  // 13. [N/A] If evidence of user interaction was provided as part of Step 11

  // 14. [ALWAYS TRUE] If the "up" option is set to true
  //     a) If the pin_uv_auth_param parameter is present then:
  if (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
    if (!cp_get_user_present_flag_value()) {
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
  } else {
    //   b) Else (implying the pin_uv_auth_param parameter is not present)
    //     1. [ALWAYS TRUE] If the "up" bit is false in the response :
    WAIT(CTAP2_ERR_OPERATION_DENIED);
  }
  //     c) [N/A] Set the "up" bit to true in the response
  //     d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  CborEncoder map;
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  size_t extension_size = 0;
  // 15. If the extensions parameter is present:
  uint8_t extension_map_items = (mc.ext_hmac_secret ? 1 : 0) +
                                // largeBlobKey has no outputs here
                                (mc.ext_cred_protect != CRED_PROTECT_ABSENT ? 1 : 0) +
                                (mc.ext_has_cred_blob ? 1 : 0);
  if (extension_map_items > 0) {
    CborEncoder extension_encoder;
    cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
    ret = cbor_encoder_create_map(&extension_encoder, &map, extension_map_items);
    CHECK_CBOR_RET(ret);

    if (mc.ext_has_cred_blob) {
      bool accepted = false;
      if (mc.ext_cred_blob_len <= MAX_CRED_BLOB_LENGTH && mc.options.rk == OPTION_TRUE) {
        accepted = true;
      }
      ret = cbor_encode_text_stringz(&map, "credBlob");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_boolean(&map, accepted);
      CHECK_CBOR_RET(ret);
    }
    if (mc.ext_cred_protect != CRED_PROTECT_ABSENT) {
      ret = cbor_encode_text_stringz(&map, "credProtect");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, mc.ext_cred_protect);
      CHECK_CBOR_RET(ret);
    }
    if (mc.ext_hmac_secret) {
      ret = cbor_encode_text_stringz(&map, "hmac-secret");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_boolean(&map, true);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&extension_encoder, &map);
    CHECK_CBOR_RET(ret);
    extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
    DBG_MSG("extension_size=%zu\n", extension_size);
  }
  if (mc.ext_large_blob_key) {
    if (mc.options.rk != OPTION_TRUE) {
      DBG_MSG("largeBlobKey requires rk\n");
      return CTAP2_ERR_INVALID_OPTION;
    }
    // Generate key in Step 17
  }

  // Now prepare the response
  ret = cbor_encoder_create_map(encoder, &map, 3 /*fmt, authData, attStmt*/ + (mc.ext_large_blob_key ? 1 : 0));
  CHECK_CBOR_RET(ret);

  // [member name] fmt
  ret = cbor_encode_int(&map, MC_RESP_FMT);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&map, "packed");
  CHECK_CBOR_RET(ret);

  // 16. Generate a new credential key pair for the algorithm chosen in step 3.
  // [member name] authData
  len = sizeof(data_buf);
  uint8_t flags = FLAGS_AT | (extension_size > 0 ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | FLAGS_UP;
  ret = ctap_make_auth_data(mc.rp_id_hash, data_buf, flags, extension_buffer, extension_size, &len,
                            mc.alg_type, mc.options.rk == OPTION_TRUE, mc.ext_cred_protect);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, MC_RESP_AUTH_DATA);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // 17. If the "rk" option is set to true:
  //     a) The authenticator MUST create a discoverable credential.
  //     b) If a credential for the same rp.id and account ID already exists on the authenticator:
  //        Overwrite that credential.
  //     c) Store the user parameter along with the newly-created key pair.
  //     d) If authenticator does not have enough internal storage to persist the new credential, return CTAP2_ERR_KEY_STORE_FULL.
  CTAP_discoverable_credential dc = {0};
  if (mc.options.rk == OPTION_TRUE) {
    DBG_MSG("Processing discoverable credential\n");
    int size = get_file_size(DC_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    int n_dc = size / (int) sizeof(CTAP_discoverable_credential), pos, first_deleted = MAX_DC_NUM;
    for (pos = 0; pos != n_dc; ++pos) {
      if (read_file(DC_FILE, &dc, pos * (int) sizeof(CTAP_discoverable_credential),
                    sizeof(CTAP_discoverable_credential)) < 0) {
        ERR_MSG("Unable to read DC_FILE\n");
        return CTAP2_ERR_UNHANDLED_REQUEST;
      }
      if (dc.deleted) {
        if (first_deleted == MAX_DC_NUM) first_deleted = pos;
        continue;
      }
      // b
      if (memcmp_s(mc.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
          mc.user.id_size == dc.user.id_size && memcmp_s(mc.user.id, dc.user.id, mc.user.id_size) == 0)
        break;
    }
    // d
    if (pos == n_dc && first_deleted != MAX_DC_NUM) {
      DBG_MSG("Use slot %d\n", first_deleted);
      pos = first_deleted;
    }
    DBG_MSG("Finally use slot %d\n", pos);
    if (pos >= MAX_DC_NUM) {
      DBG_MSG("Storage full\n");
      return CTAP2_ERR_KEY_STORE_FULL;
    }
    memcpy(&dc.credential_id, data_buf + 55, sizeof(dc.credential_id));
    memcpy(&dc.user, &mc.user, sizeof(user_entity)); // c
    dc.has_large_blob_key = mc.ext_large_blob_key;
    dc.cred_blob_len = 0;
    if (mc.ext_has_cred_blob && mc.ext_cred_blob_len <= MAX_CRED_BLOB_LENGTH) {
      dc.cred_blob_len = mc.ext_cred_blob_len;
      memcpy(dc.cred_blob, mc.ext_cred_blob, mc.ext_cred_blob_len);
    }
    dc.deleted = false;

    CTAP_dc_general_attr attr;
    if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    attr.pending_add = 1;
    attr.index = (uint8_t)pos;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (write_file(DC_FILE, &dc, pos * (int) sizeof(CTAP_discoverable_credential),
                   sizeof(CTAP_discoverable_credential), 0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;

    // Process metadata
    size = get_file_size(DC_META_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    int n_rp = size / (int) sizeof(CTAP_rp_meta), meta_pos;
    CTAP_rp_meta meta;
    first_deleted = MAX_DC_NUM;
    for (meta_pos = 0; meta_pos != n_rp; ++meta_pos) {
      size = read_file(DC_META_FILE, &meta, meta_pos * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (meta.slots == 0) { // deleted
        if (first_deleted == MAX_DC_NUM) first_deleted = meta_pos;
        continue;
      }
      if (memcmp_s(mc.rp_id_hash, meta.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) break;
    }
    if (meta_pos == n_rp) {
      meta.slots = 0; // a new entry's slot should be empty
      if (first_deleted != MAX_DC_NUM) {
        DBG_MSG("Use deleted slot %d for meta\n", first_deleted);
        meta_pos = first_deleted;
      }
    }
    DBG_MSG("Finally use slot %d for meta\n", meta_pos);
    memcpy(meta.rp_id_hash, mc.rp_id_hash, SHA256_DIGEST_LENGTH);
    memcpy(meta.rp_id, mc.rp_id, MAX_STORED_RPID_LENGTH);
    meta.rp_id_len = mc.rp_id_len;
    meta.slots |= 1ull << pos;
    DBG_MSG("New meta.slots =  %llu\n", meta.slots);
    if (write_file(DC_META_FILE, &meta, meta_pos * (int) sizeof(CTAP_rp_meta),
                   sizeof(CTAP_rp_meta), 0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    attr.pending_add = 0;
    ++attr.numbers;
    if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
  // 19. Generate an attestation statement for the newly-created credential using client_data_hash

  // [member name] attStmt
  // https://www.w3.org/TR/webauthn/#packed-attestation
  // {
  //   alg: COSE_ALG_ES256,
  //   sig: bytes (ASN.1),
  //   x5c: [ attestnCert: bytes, * (caCert: bytes) ]
  // }
  ret = cbor_encode_int(&map, MC_RESP_ATT_STMT);
  CHECK_CBOR_RET(ret);
  CborEncoder att_map;
  ret = cbor_encoder_create_map(&map, &att_map, 3);
  CHECK_CBOR_RET(ret);
  {
    // alg (ECC secp256r1)
    ret = cbor_encode_text_stringz(&att_map, "alg");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&att_map, COSE_ALG_ES256);
    CHECK_CBOR_RET(ret);

    // sig (asn.1)
    ret = cbor_encode_text_stringz(&att_map, "sig");
    CHECK_CBOR_RET(ret);
    sha256_init();
    sha256_update(data_buf, len);
    sha256_update(mc.client_data_hash, sizeof(mc.client_data_hash));
    sha256_final(data_buf);
    len = sign_with_device_key(data_buf, PRIVATE_KEY_LENGTH[SECP256R1], data_buf);
    if (!len) return CTAP2_ERR_UNHANDLED_REQUEST;
    ret = cbor_encode_byte_string(&att_map, data_buf, len);
    CHECK_CBOR_RET(ret);

    // cert (is an array)
    ret = cbor_encode_text_stringz(&att_map, "x5c");
    CHECK_CBOR_RET(ret);
    CborEncoder x5carr;
    ret = cbor_encoder_create_array(&att_map, &x5carr, 1);
    CHECK_CBOR_RET(ret);
    {
      // to save RAM, generate an empty cert first, then fill it manually
      // data_buf is never read here because length=0
      ret = cbor_encode_byte_string(&x5carr, data_buf, 0);
      CHECK_CBOR_RET(ret);
      uint8_t *ptr = x5carr.data.ptr - 1;
      ret = get_cert(ptr + 3);
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      *ptr++ = 0x59;
      *ptr++ = HI(ret);
      *ptr++ = LO(ret);
      x5carr.data.ptr = ptr + ret;
    }
    ret = cbor_encoder_close_container(&att_map, &x5carr);
    CHECK_CBOR_RET(ret);
    // att done
  }
  ret = cbor_encoder_close_container(&map, &att_map);
  CHECK_CBOR_RET(ret);

  if (mc.ext_large_blob_key) {
    uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
    static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
    ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, MC_RESP_LARGE_BLOB_KEY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  return 0;
}

static uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *params, size_t len, bool in_get_next_assertion) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
  static CTAP_get_assertion ga;
  static uint8_t credential_list[MAX_DC_NUM], number_of_credentials, credential_counter;
  static bool uv, up, user_details;
  static uint32_t timer;

  CTAP_discoverable_credential dc = {0}; // We use dc to store the selected credential
  uint8_t data_buf[sizeof(CTAP_auth_data) + CLIENT_DATA_HASH_SIZE];
  ecc_key_t key;  // TODO: cleanup
  CborParser parser;
  int ret;

  if (!in_get_next_assertion) {
    credential_counter = 0;
    ret = ctap_consistency_check();
    CHECK_PARSER_RET(ret);
  } else {
    // GET_NEXT_ASSERTION
    // 1. If authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
    if (last_cmd != CTAP_GET_ASSERTION && last_cmd != CTAP_GET_NEXT_ASSERTION) return CTAP2_ERR_NOT_ALLOWED;
    // 2. If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
    if (credential_counter >= number_of_credentials) return CTAP2_ERR_NOT_ALLOWED;
    // 3. If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than
    //    30 seconds, discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
    //    This step is OPTIONAL if transport is done over NFC.
    if (device_get_tick() - timer > 30000) return CTAP2_ERR_NOT_ALLOWED;
    // 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
    // 5. Update the response to include the selected credential’s publicKeyCredentialUserEntity information.
    //    User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be
    //    returned if user verification was not done by the authenticator in the original authenticatorGetAssertion call.
    // 6. Sign the client_data_hash along with authData with the selected credential.
    goto step7;
    // 7. Reset the timer. This step is OPTIONAL if transport is done over NFC.
    // 8. Increment credentialCounter.
    // > Process at the end of this function.
  }
  ret = parse_get_assertion(&parser, &ga, params, len);
  CHECK_PARSER_RET(ret);
  KEEPALIVE();

  // 1. If authenticator supports clientPin features and the platform sends a zero length pin_uv_auth_param
  if ((ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && ga.pin_uv_auth_param_len == 0) {
    // a. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
    // b. If the user declines permission, or the operation times out, then end the operation by returning
    //    CTAP2_ERR_OPERATION_DENIED.
    WAIT(CTAP2_ERR_OPERATION_DENIED);
    // c. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
    //    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
    if (has_pin())
      return CTAP2_ERR_PIN_INVALID;
    else
      return CTAP2_ERR_PIN_NOT_SET;
  }

  // 2. If the pin_uv_auth_param parameter is present
  //   a. If the pinUvAuthProtocol parameter’s value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
  //     > This has been processed when parsing.
  //   b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
  if ((ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) &&
      !(ga.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
    DBG_MSG("Missing required pin_uv_auth_protocol\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }

  // 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as false.
  uv = false;
  up = false;

  // 4. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (ga.options.uv == OPTION_ABSENT) ga.options.uv = OPTION_FALSE;
  //    b. If the pin_uv_auth_param is present, let the "uv" option be treated as being present with the value false.
  if (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) ga.options.uv = OPTION_FALSE;
  //    c. If the "uv" option is true then
  if (ga.options.uv == OPTION_TRUE) {
    //     1) If the authenticator does not support a built-in user verification method end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
    DBG_MSG("Rule 4-c-1 not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
    //     2) [N/A] If the built-in user verification method has not yet been enabled, end the operation
    //        by returning CTAP2_ERR_INVALID_OPTION.
  }
  //    d. If the "rk" option is present then: Return CTAP2_ERR_UNSUPPORTED_OPTION.
  if (ga.options.rk != OPTION_ABSENT) {
    DBG_MSG("Rule 4-d not satisfied.\n");
    return CTAP2_ERR_UNSUPPORTED_OPTION;
  }
  //    e. If the "up" option is not present then: Let the "up" option be treated as being present with the value true.
  if (ga.options.up == OPTION_ABSENT) ga.options.up = OPTION_TRUE;

  // 5. [N/A] If the alwaysUv option ID is present and true and the "up" option is present and true

  // 6. If authenticator is protected by some form of user verification, then:
  //    6.2 [N/A] If the "uv" option is present and set to true
  //    6.1 If pin_uv_auth_param parameter is present
  if (has_pin() && (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
    //  a) Call verify(pinUvAuthToken, client_data_hash, pin_uv_auth_param).
    //     If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
    //     If the verification returns success, set the "uv" bit to true in the response.
    if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    if (!cp_verify_pin_token(ga.client_data_hash, sizeof(ga.client_data_hash), ga.pin_uv_auth_param,
                             ga.pin_uv_auth_protocol)) {
      DBG_MSG("Fail to verify pin token\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    uv = true;
    //  b) Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
    //  c) If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    if (!cp_get_user_verified_flag_value()) {
      DBG_MSG("userVerifiedFlagValue is false\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    //  d) Verify that the pinUvAuthToken has the ga permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
    if (!cp_has_permission(CP_PERMISSION_GA)) {
      DBG_MSG("Fail to verify pin permission\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    //  e) If the pinUvAuthToken has a permissions RP ID associated:
    //     If the permissions RP ID does not match the rp_id in this request, return CTAP2_ERR_PIN_AUTH_INVALID.
    if (!cp_verify_rp_id(ga.rp_id_hash)) {
      DBG_MSG("Fail to verify pin rp id\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    //  f) If the pinUvAuthToken does not have a permissions RP ID associated:
    //     Associate the request’s rp_id parameter value with the pinUvAuthToken as its permissions RP ID.
    cp_associate_rp_id(ga.rp_id_hash);
  }

  step7:
  // 7. Locate all credentials that are eligible for retrieval under the specified criteria
  //    a) If the allow_list parameter is present and is non-empty, locate all denoted credentials created by this
  //       authenticator and bound to the specified rp_id.
  //    b) If an allow_list is not present, locate all discoverable credentials that are created by this authenticator
  //       and bound to the specified rp_id.
  //    c) Create an applicable credentials list populated with the located credentials.
  //    d) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationRequired, and the "uv" bit is false in the response, remove that credential from the
  //       applicable credentials list.
  //    e) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationOptionalWithCredentialIDList and there is no allow_list passed by the client and the "uv"
  //       bit is false in the response, remove that credential from the applicable credentials list.
  //    f) If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
  //    g) Let numberOfCredentials be the number of applicable credentials found.
  // NOTE: only one credential is used as stated in Step 11 & 12; therefore, we select that credential according to
  //       Step 11 & 12:
  // 11. If the allow_list parameter is present:
  //     Select any credential from the applicable credentials list.
  //     Delete the numberOfCredentials member.
  // 12. If allow_list is not present:
  //     a) If numberOfCredentials is one: Select that credential.
  //     b) If numberOfCredentials is more than one:
  //        1) Order the credentials in the applicable credentials list by the time when they were created in
  //           reverse order. (I.e. the first credential is the most recently created.)
  //        2）If the authenticator does not have a display:
  //           i. Remember the authenticatorGetAssertion parameters.
  //           ii. Create a credential counter (credentialCounter) and set it to 1. This counter signifies the next
  //               credential to be returned by the authenticator, assuming zero-based indexing.
  //           iii. Start a timer. This is used during authenticatorGetNextAssertion command. This step is OPTIONAL
  //                if transport is done over NFC.
  //           iv. Select the first credential.
  //        3) [N/A] If authenticator has a display and at least one of the "uv" and "up" options is true.
  //    c) Update the response to include the selected credential’s publicKeyCredentialUserEntity information.
  //       User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity
  //       MUST NOT be returned if user verification is not done by the authenticator.
  if (ga.allow_list_size > 0) { // Step 11
    size_t i;
    for (i = 0; i < ga.allow_list_size; ++i) {
      parse_credential_descriptor(&ga.allow_list, (uint8_t *) &dc.credential_id);
      // compare the rp_id first
      if (memcmp_s(dc.credential_id.rp_id_hash, ga.rp_id_hash, sizeof(dc.credential_id.rp_id_hash)) != 0) goto next;
      // then verify the key handle and get private key
      int err = verify_key_handle(&dc.credential_id, &key);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) {
        // Skip the credential which is protected
        if (!check_credential_protect_requirements(&dc.credential_id, true, uv)) goto next;
        if (dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS]) { // Verify if it's a valid dc.
          memcpy(data_buf, dc.credential_id.nonce, sizeof(dc.credential_id.nonce)); // use data_buf to store the nonce temporarily
          int size = get_file_size(DC_FILE);
          if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
          int n_dc = (int) (size / sizeof(CTAP_discoverable_credential));
          bool found = false;
          DBG_MSG("%d discoverable credentials\n", n_dc);
          for (int j = 0; j < n_dc; ++j) {
            if (read_file(DC_FILE, &dc, j * (int) sizeof(CTAP_discoverable_credential),
                          sizeof(CTAP_discoverable_credential)) < 0)
              return CTAP2_ERR_UNHANDLED_REQUEST;
            if (dc.deleted) {
              DBG_MSG("Skipped DC at %d\n", j);
              continue;
            }
            if (memcmp_s(ga.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
                memcmp_s(data_buf, dc.credential_id.nonce, sizeof(dc.credential_id.nonce)) == 0) {
              found = true;
              break;
            }
          }
          DBG_MSG("matching credential_id%s found\n", (found ? "" : " not"));
          if (found) break;
          // if (!found) return CTAP2_ERR_NO_CREDENTIALS;
        } else { // not DC
          break; // Step 11: Select any credential from the applicable credentials list.
        }
      }
      next:
      ret = cbor_value_advance(&ga.allow_list);
      CHECK_CBOR_RET(ret);
    }
    // 7-f
    if (i == ga.allow_list_size) {
      DBG_MSG("no valid credential found in the allow list\n");
      return CTAP2_ERR_NO_CREDENTIALS;
    }
    number_of_credentials = 1;
  } else { // Step 12
    int size;
    if (credential_counter == 0) {
      size = get_file_size(DC_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      int n_dc = (int) (size / sizeof(CTAP_discoverable_credential));
      number_of_credentials = 0;
      for (int i = n_dc - 1; i >= 0; --i) {  // 12-b-1
        if (read_file(DC_FILE, &dc, i * (int) sizeof(CTAP_discoverable_credential),
                      sizeof(CTAP_discoverable_credential)) < 0)
          return CTAP2_ERR_UNHANDLED_REQUEST;
        if (dc.deleted) {
          DBG_MSG("Skipped DC at %d\n", i);
          continue;
        }
        // Skip the credential which is protected
        if (!check_credential_protect_requirements(&dc.credential_id, false, uv)) continue;
        if (memcmp_s(ga.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0)
          credential_list[number_of_credentials++] = i;
      }
      // 7-f
      if (number_of_credentials == 0) return CTAP2_ERR_NO_CREDENTIALS;
    }
    // fetch dc and get private key
    if (read_file(DC_FILE, &dc, credential_list[credential_counter] * (int) sizeof(CTAP_discoverable_credential),
                  sizeof(CTAP_discoverable_credential)) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (verify_key_handle(&dc.credential_id, &key) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // For single account per RP case, authenticator returns "id" field to the platform which will be returned to the [WebAuthn] layer.
  // For multiple accounts per RP case, where the authenticator does not have a display, authenticator returns "id" as well as other fields to the platform.
  // User identifiable information (name, DisplayName, icon) MUST NOT be returned if user verification is not done by the authenticator.
  user_details = uv && number_of_credentials > 1;

  // 8. [N/A] If evidence of user interaction was provided as part of Step 6.2
  // 9. If the "up" option is set to true or not present:
  //    Note: This step is skipped in authenticatorGetNextAssertion
  if (credential_counter == 0 && ga.options.up == OPTION_TRUE) {
    //    a) If the pin_uv_auth_param parameter is present then:
    if (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
      if (!cp_get_user_present_flag_value()) {
        WAIT(CTAP2_ERR_OPERATION_DENIED);
      }
    } else {
      //    b) Else (implying the pin_uv_auth_param parameter is not present):
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
    //    c) Set the "up" bit to true in the response.
    up = true;
    //    d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
    cp_clear_user_present_flag();
    cp_clear_user_verified_flag();
    cp_clear_pin_uv_auth_token_permissions_except_lbw();
  }

  DBG_MSG("Credential id: ");
  PRINT_HEX((const uint8_t *) &dc.credential_id, sizeof(dc.credential_id));

  // 10. If the extensions parameter is present:
  //     a) Process any extensions that this authenticator supports, ignoring any that it does not support.
  //     b) Authenticator extension outputs generated by the authenticator extension processing are returned to the
  //        authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to, or a subset
  //        of, the keys of the authenticator extension inputs map.

  // Process credProtect extension
  if (!check_credential_protect_requirements(&dc.credential_id, ga.allow_list_size > 0, uv)) return CTAP2_ERR_NO_CREDENTIALS;

  CborEncoder map, sub_map;
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  size_t extension_size = 0;
  uint8_t extension_map_items = (ga.ext_cred_blob ? 1 : 0) +
                                // largeBlobKey has no outputs here
                                ((ga.parsed_params & PARAM_HMAC_SECRET) ? 1 : 0);
  if (extension_map_items > 0) {
    CborEncoder extension_encoder;
    // build extensions
    cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
    ret = cbor_encoder_create_map(&extension_encoder, &map, extension_map_items);
    CHECK_CBOR_RET(ret);

    // Process credBlob extension
    if (ga.ext_cred_blob) {
      ret = cbor_encode_text_stringz(&map, "credBlob");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, dc.cred_blob, dc.cred_blob_len);
      CHECK_CBOR_RET(ret);
    }

    // Process hmac-secret extension
    if (ga.parsed_params & PARAM_HMAC_SECRET) {
      if (credential_counter == 0) {
        // If "up" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION.
        if (!up) return CTAP2_ERR_UNSUPPORTED_OPTION;
        ret = cp_decapsulate(ga.ext_hmac_secret_key_agreement, ga.ext_hmac_secret_pin_protocol);
        CHECK_PARSER_RET(ret);
        DBG_MSG("Shared secret: ");
        PRINT_HEX(ga.ext_hmac_secret_key_agreement, ga.ext_hmac_secret_pin_protocol == 2 ? SHARED_SECRET_SIZE_P2 : SHARED_SECRET_SIZE_P1);
        if (!cp_verify(ga.ext_hmac_secret_key_agreement, SHARED_SECRET_SIZE_HMAC, ga.ext_hmac_secret_salt_enc,
                      ga.ext_hmac_secret_salt_enc_len, ga.ext_hmac_secret_salt_auth, ga.ext_hmac_secret_pin_protocol)) {
          ERR_MSG("Hmac verification failed\n");
          return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (cp_decrypt(ga.ext_hmac_secret_key_agreement, ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_salt_enc_len,
                      ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_pin_protocol) != 0) {
          ERR_MSG("Hmac decryption failed\n");
          return CTAP2_ERR_UNHANDLED_REQUEST;
        }
      }
      uint8_t hmac_secret_output[HMAC_SECRET_SALT_IV_SIZE + HMAC_SECRET_SALT_SIZE];
      DBG_MSG("hmac-secret-salt: ");
      PRINT_HEX(ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_pin_protocol == 1
                                                ? ga.ext_hmac_secret_salt_enc_len
                                                : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE);
      ret = make_hmac_secret_output(dc.credential_id.nonce, ga.ext_hmac_secret_salt_enc,
                                    ga.ext_hmac_secret_pin_protocol == 1
                                        ? ga.ext_hmac_secret_salt_enc_len
                                        : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE,
                                    hmac_secret_output, uv);
      CHECK_PARSER_RET(ret);
      DBG_MSG("hmac-secret %s UV (plain): ", uv ? "with" : "without");
      PRINT_HEX(hmac_secret_output, ga.ext_hmac_secret_pin_protocol == 1
                                        ? ga.ext_hmac_secret_salt_enc_len
                                        : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE);
      if (cp_encrypt(ga.ext_hmac_secret_key_agreement, hmac_secret_output,
                    ga.ext_hmac_secret_pin_protocol == 1 ? ga.ext_hmac_secret_salt_enc_len
                                                          : ga.ext_hmac_secret_salt_enc_len - HMAC_SECRET_SALT_IV_SIZE,
                    hmac_secret_output, ga.ext_hmac_secret_pin_protocol) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      DBG_MSG("hmac-secret output: ");
      PRINT_HEX(hmac_secret_output, ga.ext_hmac_secret_salt_enc_len);
      if (credential_counter + 1 == number_of_credentials) { // encryption key will not be used any more
        memzero(ga.ext_hmac_secret_key_agreement, sizeof(ga.ext_hmac_secret_key_agreement));
      }

      ret = cbor_encode_text_stringz(&map, "hmac-secret");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, hmac_secret_output, ga.ext_hmac_secret_salt_enc_len);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&extension_encoder, &map);
    CHECK_CBOR_RET(ret);
    extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
    DBG_MSG("extension_size=%zu\n", extension_size);
  }

  // 13. Sign the client_data_hash along with authData with the selected credential.
  uint8_t map_items = 3;
  if (dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS]) ++map_items; // user. For discoverable credentials on FIDO devices, at least user "id" is mandatory.
  if (ga.allow_list_size == 0 && credential_counter == 0 && number_of_credentials > 1) ++map_items; // numberOfCredentials
  if (dc.has_large_blob_key) ++map_items; // largeBlobKey
  ret = cbor_encoder_create_map(encoder, &map, map_items);
  CHECK_CBOR_RET(ret);

  // build credential id
  ret = cbor_encode_int(&map, GA_RESP_CREDENTIAL);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_map(&map, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&sub_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&sub_map, (const uint8_t *) &dc.credential_id, sizeof(credential_id));
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "type");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "public-key");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &sub_map);
  CHECK_CBOR_RET(ret);

  // auth data
  len = sizeof(data_buf);
  uint8_t flags = (extension_size > 0 ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | (up ? FLAGS_UP : 0);
  ret = ctap_make_auth_data(ga.rp_id_hash, data_buf, flags, extension_buffer, extension_size, &len,
                            dc.credential_id.alg_type, dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS],
                            dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS]);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, MC_RESP_AUTH_DATA);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // signature
  ret = cbor_encode_int(&map, GA_RESP_SIGNATURE);
  CHECK_CBOR_RET(ret);
  memcpy(data_buf + len, ga.client_data_hash, CLIENT_DATA_HASH_SIZE);
  DBG_MSG("Message: ");
  PRINT_HEX(data_buf, len + CLIENT_DATA_HASH_SIZE);
  len = sign_with_private_key(dc.credential_id.alg_type, &key, data_buf, len + CLIENT_DATA_HASH_SIZE, data_buf);
  if (len < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  DBG_MSG("Signature: ");
  PRINT_HEX(data_buf, len);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // user
  if (dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS]) {
    ret = cbor_encode_int(&map, GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_create_map(&map, &sub_map, user_details ? 3 : 1);
    CHECK_CBOR_RET(ret);
    {
      ret = cbor_encode_text_stringz(&sub_map, "id");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&sub_map, dc.user.id, dc.user.id_size);
      CHECK_CBOR_RET(ret);
      if (user_details) {
        ret = cbor_encode_text_stringz(&sub_map, "name");
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_text_stringz(&sub_map, dc.user.name);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_text_stringz(&sub_map, "displayName");
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_text_stringz(&sub_map, dc.user.display_name);
        CHECK_CBOR_RET(ret);
      }
    }
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
  }

  if (ga.allow_list_size == 0 && credential_counter == 0 && number_of_credentials > 1) {
    ret = cbor_encode_int(&map, GA_RESP_NUMBER_OF_CREDENTIALS);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, number_of_credentials);
    CHECK_CBOR_RET(ret);
  }

  if (dc.has_large_blob_key) {
    uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
    static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
    ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, GA_RESP_LARGE_BLOB_KEY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  ++credential_counter;
  timer = device_get_tick();

  return 0;
}

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetNextAssertion
static uint8_t ctap_get_next_assertion(CborEncoder *encoder) {
  return ctap_get_assertion(encoder, NULL, 0, true);
}

static uint8_t ctap_get_info(CborEncoder *encoder) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
  CborEncoder map, sub_map;
  int ret = cbor_encoder_create_map(encoder, &map, 13);
  CHECK_CBOR_RET(ret);

  // versions
  ret = cbor_encode_int(&map, GI_RESP_VERSIONS);
  CHECK_CBOR_RET(ret);
  CborEncoder array;
  ret = cbor_encoder_create_array(&map, &array, 3);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&array, "U2F_V2");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "FIDO_2_1");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // extensions
  ret = cbor_encode_int(&map, GI_RESP_EXTENSIONS);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 4);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&array, "credBlob");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "credProtect");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "hmac-secret");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "largeBlobKey");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // aaguid
  ret = cbor_encode_int(&map, GI_RESP_AAGUID);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, aaguid, sizeof(aaguid));
  CHECK_CBOR_RET(ret);

  // options
  ret = cbor_encode_int(&map, GI_RESP_OPTIONS);
  CHECK_CBOR_RET(ret);
  CborEncoder option_map;
  ret = cbor_encoder_create_map(&map, &option_map, 6);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&option_map, "rk");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&option_map, true);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&option_map, "credMgmt");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&option_map, true);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&option_map, "clientPin");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&option_map, has_pin());
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&option_map, "largeBlobs");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&option_map, true);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&option_map, "pinUvAuthToken");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&option_map, true);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&option_map, "makeCredUvNotRqd");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&option_map, true);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &option_map);
  CHECK_CBOR_RET(ret);

  // maxMsgSize
  ret = cbor_encode_int(&map, GI_RESP_MAX_MSG_SIZE);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, MAX_CTAP_BUFSIZE);
  CHECK_CBOR_RET(ret);

  // pinUvAuthProtocols
  ret = cbor_encode_int(&map, GI_RESP_PIN_UV_AUTH_PROTOCOLS);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 2);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_int(&array, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&array, 2);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // maxCredentialCountInList
  ret = cbor_encode_int(&map, GI_RESP_MAX_CREDENTIAL_COUNT_IN_LIST);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, MAX_CREDENTIAL_COUNT_IN_LIST);
  CHECK_CBOR_RET(ret);

  // maxCredentialIdLength
  ret = cbor_encode_int(&map, GI_RESP_MAX_CREDENTIAL_ID_LENGTH);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, sizeof(credential_id));
  CHECK_CBOR_RET(ret);

  // transports
  ret = cbor_encode_int(&map, GI_RESP_TRANSPORTS);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 2);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&array, "nfc");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "usb");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // algorithms
  ret = cbor_encode_int(&map, GI_RESP_ALGORITHMS);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, ctap_sm2_attr.enabled ? 3 : 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_map(&array, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&sub_map, "alg");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&sub_map, COSE_ALG_ES256);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "type");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "public-key");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&array, &sub_map);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_map(&array, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&sub_map, "alg");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&sub_map, COSE_ALG_EDDSA);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "type");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "public-key");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&array, &sub_map);
  CHECK_CBOR_RET(ret);
  if (ctap_sm2_attr.enabled) {
    ret = cbor_encoder_create_map(&array, &sub_map, 2);
    CHECK_CBOR_RET(ret);
    {
      ret = cbor_encode_text_stringz(&sub_map, "alg");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&sub_map, ctap_sm2_attr.algo_id);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "type");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "public-key");
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&array, &sub_map);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // maxSerializedLargeBlobArray
  ret = cbor_encode_int(&map, GI_RESP_MAX_SERIALIZED_LARGE_BLOB_ARRAY);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, LARGE_BLOB_SIZE_LIMIT);
  CHECK_CBOR_RET(ret);

  // firmwareVersion
  ret = cbor_encode_int(&map, GI_RESP_FIRMWARE_VERSION);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, FIRMWARE_VERSION);
  CHECK_CBOR_RET(ret);

  // maxCredBlobLength
  ret = cbor_encode_int(&map, GI_RESP_MAX_CRED_BLOB_LENGTH);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, MAX_CRED_BLOB_LENGTH);
  CHECK_CBOR_RET(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t ctap_client_pin(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_client_pin cp;
  int ret = parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);

  CborEncoder map, key_map;
  uint8_t iv[16], buf[PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2], i;
  memzero(iv, sizeof(iv));
  uint8_t *ptr;
  int err, retries, cose_key_size;
  switch (cp.sub_command) {
    case CP_CMD_GET_PIN_RETRIES:
    DBG_MSG("Subcommand Get Pin Retries\n");
      ret = cbor_encoder_create_map(encoder, &map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CP_RESP_PIN_RETRIES);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, get_pin_retries());
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CP_CMD_GET_KEY_AGREEMENT:
      DBG_MSG("Subcommand Get Key Agreement\n");
      ret = cbor_encoder_create_map(encoder, &map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CP_RESP_KEY_AGREEMENT);
      CHECK_CBOR_RET(ret);
      // to save RAM, generate an empty key first, then fill it manually
      ret = cbor_encoder_create_map(&map, &key_map, 0);
      CHECK_CBOR_RET(ret);
      ptr = key_map.data.ptr - 1;
      cp_get_public_key(ptr);
      cose_key_size = build_ecdsa_cose_key(ptr, COSE_ALG_ECDH_ES_HKDF_256, COSE_KEY_CRV_P256);
      key_map.data.ptr = ptr + cose_key_size;
      ret = cbor_encoder_close_container(&map, &key_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CP_CMD_SET_PIN:
      DBG_MSG("Subcommand Set Pin\n");
      err = has_pin();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err > 0) return CTAP2_ERR_PIN_AUTH_INVALID;
      ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      DBG_MSG("Shared Secret: ");
      PRINT_HEX(cp.key_agreement, cp.pin_uv_auth_protocol == 2 ? SHARED_SECRET_SIZE_P2 : SHARED_SECRET_SIZE_P1);
      if (!cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, cp.new_pin_enc,
                     cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2, cp.pin_uv_auth_param,
                     cp.pin_uv_auth_protocol)) {
        ERR_MSG("CP verification failed\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      if (cp_decrypt(cp.key_agreement, cp.new_pin_enc,
                     cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2,
                     cp.new_pin_enc, cp.pin_uv_auth_protocol) != 0) {
        ERR_MSG("CP decryption failed\n");
        return CTAP2_ERR_UNHANDLED_REQUEST;
      }
      DBG_MSG("Decrypted key: ");
      PRINT_HEX(cp.new_pin_enc, 64);
      i = 63;
      while (i > 0 && cp.new_pin_enc[i] == 0)
        --i;
      if (i < 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
      err = set_pin(cp.new_pin_enc, i + 1);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      break;

    case CP_CMD_CHANGE_PIN:
      DBG_MSG("Subcommand Change Pin\n");
      err = has_pin();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
      err = get_pin_retries();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
      if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
      if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      retries = err - 1;
#endif
      ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      if (cp.pin_uv_auth_protocol == 1) {
        memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P1);
        memcpy(buf + PIN_ENC_SIZE_P1, cp.pin_hash_enc, PIN_HASH_SIZE_P1);
        ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, buf, PIN_ENC_SIZE_P1 + PIN_HASH_SIZE_P1,
                        cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
      } else {
        memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P2);
        memcpy(buf + PIN_ENC_SIZE_P2, cp.pin_hash_enc, PIN_HASH_SIZE_P2);
        ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE_HMAC, buf, PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2,
                        cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
      }
      if (ret == false) {
        ERR_MSG("CP verification failed\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      err = set_pin_retries(retries);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (cp_decrypt(cp.key_agreement, cp.pin_hash_enc,
                     cp.pin_uv_auth_protocol == 1 ? PIN_HASH_SIZE_P1 : PIN_HASH_SIZE_P2,
                     cp.pin_hash_enc, cp.pin_uv_auth_protocol)) {
        ERR_MSG("CP decryption failed\n");
        return CTAP2_ERR_UNHANDLED_REQUEST;
      }
      err = verify_pin_hash(cp.pin_hash_enc);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
      if (err > 0) {
        cp_regenerate();
        if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
        --consecutive_pin_counter;
        if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        return CTAP2_ERR_PIN_INVALID;
      }
#endif
      consecutive_pin_counter = 3;
      if (cp_decrypt(cp.key_agreement, cp.new_pin_enc,
                     cp.pin_uv_auth_protocol == 1 ? PIN_ENC_SIZE_P1 : PIN_ENC_SIZE_P2,
                     cp.new_pin_enc, cp.pin_uv_auth_protocol) != 0) {
        ERR_MSG("CP decryption failed\n");
        return CTAP2_ERR_UNHANDLED_REQUEST;
      }
      i = 63;
      while (i > 0 && cp.new_pin_enc[i] == 0)
        --i;
      if (i < 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
      err = set_pin(cp.new_pin_enc, i + 1);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      break;

    case CP_CMD_GET_PIN_TOKEN:
    case CP_CMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS:
      DBG_MSG("Subcommand Get Pin Token\n");
      // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
      // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
      err = has_pin();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
      err = get_pin_retries();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
      if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
      if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      retries = err - 1;
#endif
      ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      err = set_pin_retries(retries);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (cp_decrypt(cp.key_agreement, cp.pin_hash_enc,
                     cp.pin_uv_auth_protocol == 1 ? PIN_HASH_SIZE_P1 : PIN_HASH_SIZE_P2,
                     cp.pin_hash_enc, cp.pin_uv_auth_protocol)) {
        ERR_MSG("CP decryption failed\n");
        return CTAP2_ERR_UNHANDLED_REQUEST;
      }
      err = verify_pin_hash(cp.pin_hash_enc);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
      if (err > 0) {
        if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
        --consecutive_pin_counter;
        if (consecutive_pin_counter == 0) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        return CTAP2_ERR_PIN_INVALID;
      }
#endif
      consecutive_pin_counter = 3;
      err = set_pin_retries(8);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      cp_reset_pin_uv_auth_token();
      cp_begin_using_uv_auth_token(false);
      if (cp.sub_command == CP_CMD_GET_PIN_TOKEN) {
        cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA);
      } else {
        cp_set_permission(cp.permissions);
        if (cp.parsed_params & PARAM_RP) cp_associate_rp_id(cp.rp_id_hash);
      }
      cp_encrypt_pin_token(cp.key_agreement, buf, cp.pin_uv_auth_protocol);
      ret = cbor_encoder_create_map(encoder, &map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CP_RESP_PIN_UV_AUTH_TOKEN);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, buf, cp.pin_uv_auth_protocol == 1 ? PIN_TOKEN_SIZE : PIN_TOKEN_SIZE + 16);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;
  }

  return 0;
}

static int get_next_slot(uint64_t *slots, uint8_t *numbers) {
  int idx = -1;
  uint64_t val = *slots;
  *numbers = 0;
  for (int i = 0; i < 64; ++i) {
    if (val & 1) {
      ++*numbers;
      if (idx == -1) idx = i;
    }
    val >>= 1;
  }
  if (idx != -1) *slots &= ~(1ull << idx);
  return idx;
}

static uint8_t ctap_credential_management(CborEncoder *encoder, const uint8_t *params, size_t len) {
  static uint8_t last_cm_cmd;

  CborParser parser;
  CTAP_credential_management cm;
  int ret = parse_credential_management(&parser, &cm, params, len);
  CHECK_PARSER_RET(ret);
  ret = ctap_consistency_check();
  CHECK_PARSER_RET(ret);

  static int idx, n_rp; // for rp enumeration
  static uint64_t slots; // for credential enumeration
  int size, counter;
  CborEncoder map, sub_map;
  uint8_t numbers = 0;
  CTAP_rp_meta meta;
  CTAP_discoverable_credential dc;
  bool include_numbers;

  if (cm.sub_command == CM_CMD_GET_CREDS_METADATA ||
      cm.sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
      cm.sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN ||
      cm.sub_command == CM_CMD_DELETE_CREDENTIAL ||
      cm.sub_command == CM_CMD_UPDATE_USER_INFORMATION) {
    last_cm_cmd = cm.sub_command;
    uint8_t *buf = (uint8_t *) &dc; // buffer reuse
    _Static_assert(sizeof(CTAP_dc_general_attr) < sizeof(dc), "CTAP_dc_general_attr buffer overflow");
    if (read_attr(DC_FILE, DC_GENERAL_ATTR, buf, sizeof(CTAP_dc_general_attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    numbers = ((CTAP_dc_general_attr*)buf)->numbers;

    buf[0] = cm.sub_command;
    if (cm.param_len + 1 > sizeof(dc)) return CTAP1_ERR_INVALID_LENGTH;
    if (cm.param_len > 0) memcpy(&buf[1], cm.sub_command_params_ptr, cm.param_len);
    if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
    if (!cp_verify_pin_token(buf, cm.param_len + 1, cm.pin_uv_auth_param, cm.pin_uv_auth_protocol)) {
      DBG_MSG("PIN verification error\n");
      return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!cp_has_permission(CP_PERMISSION_CM)) return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  DBG_MSG("processing cm.sub_command %hhu\n", cm.sub_command);
  switch (cm.sub_command) {
    case CM_CMD_GET_CREDS_METADATA:
      if (cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
      ret = cbor_encoder_create_map(encoder, &map, 2);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_EXISTING_RESIDENT_CREDENTIALS_COUNT);
      CHECK_CBOR_RET(ret);
      DBG_MSG("Existing credentials: %d\n", numbers);
      ret = cbor_encode_int(&map, numbers);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_MAX_POSSIBLE_REMAINING_RESIDENT_CREDENTIALS_COUNT);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, MAX_DC_NUM - numbers);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CM_CMD_ENUMERATE_RPS_BEGIN:
      if (cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      size = get_file_size(DC_META_FILE), counter = 0;
      n_rp = size / (int) sizeof(CTAP_rp_meta);
      KEEPALIVE();
      for (int i = n_rp - 1; i >= 0; --i) {
        size = read_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots > 0) {
          idx = i;
          ++counter;
        }
      }
      DBG_MSG("%d RPs found\n", counter);
      size = read_file(DC_META_FILE, &meta, idx * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      ret = cbor_encoder_create_map(encoder, &map, 3);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_RP);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_create_map(&map, &sub_map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "id");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_string(&sub_map, (const char *) meta.rp_id, meta.rp_id_len);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(&map, &sub_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_RP_ID_HASH);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, meta.rp_id_hash, SHA256_DIGEST_LENGTH);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_TOTAL_RPS);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, counter);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CM_CMD_ENUMERATE_RPS_GET_NEXT_RP:
      if (last_cmd != CTAP_CREDENTIAL_MANAGEMENT ||
        (last_cm_cmd != CM_CMD_ENUMERATE_RPS_BEGIN && last_cm_cmd != CM_CMD_ENUMERATE_RPS_GET_NEXT_RP)) {
        last_cm_cmd = 0;
        return CTAP2_ERR_NOT_ALLOWED;
      }
      last_cm_cmd = cm.sub_command;
      for (int i = idx + 1; i < n_rp; ++i) {
        size = read_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots > 0) {
          DBG_MSG("Fetch RP at %d\n", i);
          idx = i;
          break;
        }
      }
      ret = cbor_encoder_create_map(encoder, &map, 2);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_RP);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_create_map(&map, &sub_map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "id");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_string(&sub_map, (const char *) meta.rp_id, meta.rp_id_len);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(&map, &sub_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_RP_ID_HASH);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&map, meta.rp_id_hash, SHA256_DIGEST_LENGTH);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CM_CMD_ENUMERATE_CREDENTIALS_BEGIN:
      if (!cp_verify_rp_id(cm.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      include_numbers = true;
      size = get_file_size(DC_META_FILE);
      n_rp = size / (int) sizeof(CTAP_rp_meta);
      KEEPALIVE();
      for (idx = 0; idx < n_rp; ++idx) {
        size = read_file(DC_META_FILE, &meta, idx * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots == 0) continue;
        if (memcmp_s(meta.rp_id_hash, cm.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) break;
      }
      if (idx == n_rp) {
        DBG_MSG("Specified RP not found\n");
        return CTAP2_ERR_NO_CREDENTIALS;
      }
      DBG_MSG("Use meta at slot %d: ", idx);
      PRINT_HEX((const uint8_t *) &meta, sizeof(meta));
      slots = meta.slots;
    generate_credential_response:
      DBG_MSG("Current slot bitmap: 0x%llx\n", slots);
      idx = get_next_slot(&slots, &numbers);
      size = read_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                       sizeof(CTAP_discoverable_credential));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      DBG_MSG("Slot %d printed\n", idx);
      ret = cbor_encoder_create_map(encoder, &map, 4 + (uint8_t)include_numbers + (uint8_t)dc.has_large_blob_key);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_USER);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_create_map(&map, &sub_map, 3);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "id");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&sub_map, dc.user.id, dc.user.id_size);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "name");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, dc.user.name);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "displayName");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, dc.user.display_name);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(&map, &sub_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_CREDENTIAL_ID);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_create_map(&map, &sub_map, 2);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "id");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&sub_map, (const uint8_t *) &dc.credential_id, sizeof(credential_id));
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "type");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "public-key");
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(&map, &sub_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_PUBLIC_KEY);
      CHECK_CBOR_RET(ret);
      // to save RAM, generate an empty key first, then fill it manually
      ret = cbor_encoder_create_map(&map, &sub_map, 0);
      CHECK_CBOR_RET(ret);
      ecc_key_t key;
      ret = verify_key_handle(&dc.credential_id, &key);
      if (ret != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      key_type_t key_type = cose_alg_to_key_type(dc.credential_id.alg_type);
      if (ecc_complete_key(key_type, &key) < 0) {
        ERR_MSG("Failed to complete key\n");
        return -1;
      }
      uint8_t *ptr = sub_map.data.ptr - 1;
      memcpy(ptr, key.pub, PUBLIC_KEY_LENGTH[key_type]);
      if (dc.credential_id.alg_type == COSE_ALG_ES256) {
        int cose_key_size = build_ecdsa_cose_key(ptr, COSE_ALG_ES256, COSE_KEY_CRV_P256);
        sub_map.data.ptr = ptr + cose_key_size;
      } else if (dc.credential_id.alg_type == COSE_ALG_EDDSA) {
        int cose_key_size = build_ed25519_cose_key(ptr);
        sub_map.data.ptr = ptr + cose_key_size;
      }
      ret = cbor_encoder_close_container(&map, &sub_map);
      CHECK_CBOR_RET(ret);
      if (include_numbers) {
        ret = cbor_encode_int(&map, CM_RESP_TOTAL_CREDENTIALS);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_int(&map, numbers);
        CHECK_CBOR_RET(ret);
      }
      ret = cbor_encode_int(&map, CM_RESP_CRED_PROTECT);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS]);
      CHECK_CBOR_RET(ret);
      if (dc.has_large_blob_key) {
        uint8_t *large_blob_key = dc.cred_blob; // reuse buffer
        static_assert(LARGE_BLOB_KEY_SIZE <= MAX_CRED_BLOB_LENGTH, "Reuse buffer");
        ret = make_large_blob_key(dc.credential_id.nonce, large_blob_key);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_int(&map, CM_RESP_LARGE_BLOB_KEY);
        CHECK_CBOR_RET(ret);
        ret = cbor_encode_byte_string(&map, large_blob_key, LARGE_BLOB_KEY_SIZE);
        CHECK_CBOR_RET(ret);
      }
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL:
      if (last_cmd != CTAP_CREDENTIAL_MANAGEMENT || (
          last_cm_cmd != CM_CMD_ENUMERATE_CREDENTIALS_BEGIN &&
          last_cm_cmd != CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL)) {
        last_cm_cmd = 0;
        return CTAP2_ERR_NOT_ALLOWED;
      }
      last_cm_cmd = cm.sub_command;
      include_numbers = false;
      goto generate_credential_response;

    case CM_CMD_DELETE_CREDENTIAL:
      if (!cp_verify_rp_id(cm.credential_id.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      size = get_file_size(DC_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      numbers = size / sizeof(CTAP_discoverable_credential);
      for (idx = 0; idx < numbers; ++idx) {
        size = read_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                         sizeof(CTAP_discoverable_credential));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (dc.deleted) continue;
        if (memcmp_s(&dc.credential_id, &cm.credential_id, sizeof(credential_id)) == 0) {
          DBG_MSG("Found, credential_id: ");
          PRINT_HEX((const uint8_t *) &dc.credential_id, sizeof(credential_id));
          break;
        }
      }
      if (idx == numbers) return CTAP2_ERR_NO_CREDENTIALS;

      CTAP_dc_general_attr attr;
      if (read_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      attr.index = (uint8_t)idx;
      attr.pending_delete = 1;
      if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

      // delete dc first
      dc.deleted = true;
      if (write_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                     sizeof(CTAP_discoverable_credential),
                     0) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      DBG_MSG("Slot %d deleted\n", idx);
      // delete the meta then
      size = get_file_size(DC_META_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      numbers = size / sizeof(CTAP_rp_meta);
      KEEPALIVE();
      for (int i = 0; i < numbers; ++i) {
        size = read_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (memcmp_s(meta.rp_id_hash, cm.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) {
          DBG_MSG("Orig slot bitmap: 0x%llx\n", meta.slots);
          meta.slots &= ~(1ull << idx);
          DBG_MSG("New slot bitmap: 0x%llx\n", meta.slots);
          size = write_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta), 0);
          if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
          break;
        }
      }
      attr.numbers--;
      attr.pending_delete = 0;
      if (write_attr(DC_FILE, DC_GENERAL_ATTR, &attr, sizeof(attr)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      break;

    case CM_CMD_UPDATE_USER_INFORMATION:
      if (!cp_verify_rp_id(cm.credential_id.rp_id_hash)) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      // TODO: refactor this
      size = get_file_size(DC_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      numbers = size / sizeof(CTAP_discoverable_credential);
      KEEPALIVE();
      for (idx = 0; idx < numbers; ++idx) {
        size = read_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                         sizeof(CTAP_discoverable_credential));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (dc.deleted) continue;
        if (memcmp_s(&dc.credential_id, &cm.credential_id, sizeof(credential_id)) == 0) {
          DBG_MSG("Found, credential_id: ");
          PRINT_HEX((const uint8_t *) &dc.credential_id, sizeof(credential_id));
          break;
        }
      }
      if (idx == numbers) {
        DBG_MSG("No matching credential\n");
        return CTAP2_ERR_NO_CREDENTIALS;
      }
      if (dc.user.id_size != cm.user.id_size || memcmp_s(&dc.user.id, &cm.user.id, dc.user.id_size) != 0) {
        DBG_MSG("Incorrect user id\n");
        return CTAP1_ERR_INVALID_PARAMETER;
      }
      memcpy(&dc.user, &cm.user, sizeof(user_entity));
      if (write_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                     sizeof(CTAP_discoverable_credential),
                     0) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      DBG_MSG("Slot %d updated\n", idx);
      break;
  }


  return 0;
}

static uint8_t ctap_selection(void) {
  WAIT(CTAP2_ERR_USER_ACTION_TIMEOUT);
  return 0;
}

static uint8_t ctap_reset_data(void) {
  // If the request comes after 10 seconds of powering up, the authenticator returns CTAP2_ERR_NOT_ALLOWED.
  if (device_get_tick() > 10000) {
    return CTAP2_ERR_NOT_ALLOWED;
  }
  return ctap_install(1);
}

static uint8_t ctap_large_blobs(CborEncoder *encoder, const uint8_t *params, size_t len) {
  static uint16_t expectedNextOffset, expectedLength;

  CborParser parser;
  CborEncoder map;
  CTAP_large_blobs lb;
  uint8_t buf[256]; // for pin auth
  int ret = parse_large_blobs(&parser, &lb, params, len);
  CHECK_PARSER_RET(ret);

  // 1. If offset is not present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // 2. If neither get nor set are present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // 3. If both get and set are present in the input map, return CTAP1_ERR_INVALID_PARAMETER.
  // > Step 1-3 are checked when parsing.

  // 4. If get is present in the input map:
  if (lb.parsed_params & PARAM_GET) {
    //  a) If length is present, return CTAP1_ERR_INVALID_PARAMETER.
    //  b) If either of pinUvAuthParam or pinUvAuthProtocol are present, return CTAP1_ERR_INVALID_PARAMETER.
    //  c) If the value of get is greater than maxFragmentLength, return CTAP1_ERR_INVALID_LENGTH.
    //  > Step a-c are checked when parsing.

    int size = get_file_size(LB_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    //  d) If the value of offset is greater than the length of the stored serialized large-blob array,
    //     return CTAP1_ERR_INVALID_PARAMETER.
    if ((int)lb.offset > size) {
      DBG_MSG("4-d not satisfied\n");
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    //  e) Return a CBOR map, as defined below, where the value of config is a substring of the stored serialized
    //     large-blob array. The substring SHOULD start at the offset given in offset and contain the number of bytes
    //     specified as get's value. If too few bytes exist at that offset, return the maximum number available.
    //     Note that if offset is equal to the length of the serialized large-blob array then this will result
    //     in a zero-length substring.
    if (lb.offset + (int)lb.get > size) lb.get = size - lb.offset;
    DBG_MSG("read %hu bytes at %hu\n", lb.get, lb.offset);
    KEEPALIVE();
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, LB_RESP_CONFIG);
    CHECK_CBOR_RET(ret);
    // to save RAM, we encode the buffer manually
    uint8_t *ptr = map.data.ptr;
    ret = cbor_encode_uint(&map, lb.get);
    CHECK_CBOR_RET(ret);
    *ptr |= 0x40; // CBOR Major type 2
    if (read_file(LB_FILE, map.data.ptr, lb.offset, lb.get) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    map.data.ptr += lb.get;
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
  } else {
    // 5. Else (implying that set is present in the input map):
    //    a) If the length of the value of set is greater than maxFragmentLength, return CTAP1_ERR_INVALID_LENGTH.
    //       > Checked when paring.
    //    b) If the value of offset is zero:
    if (lb.offset == 0) {
      //     i. If length is not present, return CTAP1_ERR_INVALID_PARAMETER.
      //     ii. If the value of length is greater than 1024 bytes and exceeds the capacity of the device,
      //         return CTAP2_ERR_LARGE_BLOB_STORAGE_FULL. (Authenticators MUST be capable of storing at least 1024 bytes.)
      //     iii. If the value of length is less than 17, return CTAP1_ERR_INVALID_PARAMETER.
      //         > Step i - iii are checked when parsing.

      //     iv. Set expectedLength to the value of length.
      expectedLength = lb.length;
      //     v. Set expectedNextOffset to zero.
      expectedNextOffset = 0;
    }
    //    c) Else (i.e. the value of offset is not zero):
    //       If length is present, return CTAP1_ERR_INVALID_PARAMETER.
    //       > Checked when paring.
    //    d) If the value of offset is not equal to expectedNextOffset, return CTAP1_ERR_INVALID_SEQ.
    if (lb.offset != expectedNextOffset) {
      DBG_MSG("5-d not satisfied\n");
      return CTAP1_ERR_INVALID_SEQ;
    }
    //    e) If the authenticator is protected by some form of user verification
    //       or the alwaysUv option ID is present and true:
    if (has_pin()) {
      //     i. If pinUvAuthParam is absent from the input map, then end the operation by
      //        returning CTAP2_ERR_PUAT_REQUIRED.
      if (!(lb.parsed_params & PARAM_PIN_UV_AUTH_PARAM)) {
        DBG_MSG("5-e-i not satisfied\n");
        return CTAP2_ERR_PUAT_REQUIRED;
      }
      //     ii. If pinUvAuthProtocol is absent from the input map, then end the operation by
      //         returning CTAP2_ERR_MISSING_PARAMETER.
      if (!(lb.parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL)) {
        DBG_MSG("5-e-ii not satisfied\n");
        return CTAP2_ERR_MISSING_PARAMETER;
      }
      //     iii. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
      //       > Checked when paring.
      //     iv. The authenticator calls verify(pinUvAuthToken, 32×0xff || h’0c00' || uint32LittleEndian(offset) ||
      //         SHA-256(contents of set byte string, i.e. not including an outer CBOR tag with major type two),
      //         pinUvAuthParam).
      //         If the verification fails, return CTAP2_ERR_PIN_AUTH_INVALID.
      memset(buf, 0xFF, 32);
      buf[32] = 0x0C;
      buf[33] = 0x00;
      buf[34] = lb.offset & 0xFF;
      buf[35] = lb.offset >> 8;
      buf[36] = 0x00;
      buf[37] = 0x00;
      sha256_raw(lb.set, lb.set_len, buf + 38);
      if (!consecutive_pin_counter) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      if (!cp_verify_pin_token(buf, 70, lb.pin_uv_auth_param, lb.pin_uv_auth_protocol)) {
        DBG_MSG("Fail to verify pin token\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      //     v. Check if the pinUvAuthToken has the lbw permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
      if (!cp_has_permission(CP_PERMISSION_LBW)) {
        DBG_MSG("Fail to verify pin permission\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
    }
    //    f) If the sum of offset and the length of the value of set is greater than the value of expectedLength,
    //       return CTAP1_ERR_INVALID_PARAMETER.
    if (lb.offset + lb.set_len > (size_t)expectedLength) {
      DBG_MSG("5-g not satisfied, %hu + %zu > %hu\n", lb.offset, lb.set_len, expectedLength);
      return CTAP1_ERR_INVALID_PARAMETER;
    }
    //    g) If the value of offset is zero, prepare a buffer to receive a new serialized large-blob array.
    //    h) Append the value of set to the buffer containing the pending serialized large-blob array.
    KEEPALIVE();
    if (write_file(LB_FILE_TMP, lb.set, lb.offset, lb.set_len, lb.offset == 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    //    i) Update expectedNextOffset to be the new length of the pending serialized large-blob array.
    expectedNextOffset += lb.set_len;
    //    j) If the length of the pending serialized large-blob array is equal to expectedLength:
    if (expectedNextOffset == expectedLength) {
      //     i. Verify that the final 16 bytes in the buffer are the truncated SHA-256 hash of the preceding bytes.
      //        If the hash does not match, return CTAP2_ERR_INTEGRITY_FAILURE.
      int offset = 0;
      expectedLength -= 16;
      sha256_init();
      while (offset < expectedLength) {
        int to_read = sizeof(buf);
        if (to_read > expectedLength - offset) to_read = expectedLength - offset;
        if (read_file(LB_FILE_TMP, buf, offset, to_read) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        sha256_update(buf, to_read);
        offset += to_read;
      }
      sha256_final(buf);
      if (read_file(LB_FILE_TMP, buf + 16, offset, 16) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (memcmp_s(buf, buf + 16, 16)) return CTAP2_ERR_INTEGRITY_FAILURE;
      //     ii. Commit the contents of the buffer as the new serialized large-blob array for this authenticator.
      if (fs_rename(LB_FILE_TMP, LB_FILE) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      //     iii. Return CTAP2_OK and an empty response.
    }
    //    k) Else:
    //       i. More data is needed to complete the pending serialized large-blob array.
    //       ii. Return CTAP2_OK and an empty response. Await further writes.
    //    > DO NOTHING
  }
  return 0;
}

static int ctap_process_cbor(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len) {
  if (req_len-- == 0) return -1;

  cp_pin_uv_auth_token_usage_timer_observer();

  CborEncoder encoder;
  cbor_encoder_init(&encoder, resp + 1, *resp_len - 1, 0);

  uint8_t cmd = *req++;
  switch (cmd) {
    case CTAP_MAKE_CREDENTIAL:
      DBG_MSG("-----------------MC-------------------\n");
      *resp = ctap_make_credential(&encoder, req, req_len);
      SET_RESP();
      break;
    case CTAP_GET_ASSERTION:
      DBG_MSG("-----------------GA-------------------\n");
      *resp = ctap_get_assertion(&encoder, req, req_len, false);
      SET_RESP();
      break;
    case CTAP_GET_NEXT_ASSERTION:
      DBG_MSG("----------------NEXT------------------\n");
      *resp = ctap_get_next_assertion(&encoder);
      SET_RESP();
      break;
    case CTAP_GET_INFO:
      DBG_MSG("-----------------GI-------------------\n");
      *resp = ctap_get_info(&encoder);
      SET_RESP();
      break;
    case CTAP_CLIENT_PIN:
      DBG_MSG("-----------------CP-------------------\n");
      *resp = ctap_client_pin(&encoder, req, req_len);
      SET_RESP();
      break;
    case CTAP_RESET:
      DBG_MSG("----------------RESET-----------------\n");
      *resp = ctap_reset_data();
      *resp_len = 1;
      break;
    case CTAP_CRED_MANAGE_LEGACY: // compatible with old libfido2
      cmd = CTAP_CREDENTIAL_MANAGEMENT;
    case CTAP_CREDENTIAL_MANAGEMENT:
      DBG_MSG("----------------CM--------------------\n");
      *resp = ctap_credential_management(&encoder, req, req_len);
      SET_RESP();
      break;
    case CTAP_SELECTION:
      DBG_MSG("----------------SELECTION-------------\n");
      *resp = ctap_selection();
      SET_RESP();
      break;
    case CTAP_LARGE_BLOBS:
      DBG_MSG("----------------LB--------------------\n");
      *resp = ctap_large_blobs(&encoder, req, req_len);
      SET_RESP();
      break;
    case CTAP_CONFIG:
      DBG_MSG("----------------CONFIG----------------\n");
      *resp = CTAP2_ERR_UNHANDLED_REQUEST;
      *resp_len = 1;
      break;
    default:
      *resp = CTAP2_ERR_UNHANDLED_REQUEST;
      *resp_len = 1;
      break;
  }
  last_cmd = cmd;
  if (*resp != 0) { // do not allow GET_NEXT_ASSERTION if error occurs
    last_cmd = CTAP_INVALID_CMD;
  }
  return 0;
}

int ctap_process_cbor_with_src(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len, ctap_src_t src) {
  
  if (current_cmd_src != CTAP_SRC_NONE) return -1;
  // Must set current_cmd_src to CTAP_SRC_NONE before return
  current_cmd_src = src;
  int ret = ctap_process_cbor(req, req_len, resp, resp_len);
  current_cmd_src = CTAP_SRC_NONE;
  return ret;
}

int ctap_process_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src) {
  int ret = 0;
  LL = 0;
  if (current_cmd_src != CTAP_SRC_NONE) EXCEPT(SW_UNABLE_TO_PROCESS);
  // Must set current_cmd_src to CTAP_SRC_NONE before return
  current_cmd_src = src;
  SW = SW_NO_ERROR;
  if (CLA == 0x80) {
    if (INS == CTAP_INS_MSG) {
      // rapdu buffer size: APDU_BUFFER_SIZE
      size_t len = APDU_BUFFER_SIZE;

      ret = ctap_process_cbor(DATA, LC, RDATA, &len);
      // len is the actual len written to RDATA
      LL = len;
    } else {
      current_cmd_src = CTAP_SRC_NONE;
      EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else if (CLA == 0x00) {
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
      case CTAP_INS_MSG:
        break;
      default:
        current_cmd_src = CTAP_SRC_NONE;
        EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else {
    current_cmd_src = CTAP_SRC_NONE;
    EXCEPT(SW_CLA_NOT_SUPPORTED);
  }

  current_cmd_src = CTAP_SRC_NONE;
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  else
    return 0;
}

int ctap_wink(void) {
    start_blinking_interval(1, 50);
    return 0;
}

