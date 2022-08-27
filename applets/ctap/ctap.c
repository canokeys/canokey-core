// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-internal.h"
#include "ctap-parser.h"
#include "secret.h"
#include "u2f.h"
#include <aes.h>
#include <block-cipher.h>
#include <cbor.h>
#include <common.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
#include <ed25519.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if (ret != 0) ERR_MSG("CHECK_PARSER_RET %#x\n", ret);                                                              \
    if (ret > 0) return ret;                                                                                           \
  } while (0)

#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if (ret != 0) ERR_MSG("CHECK_CBOR_RET %#x\n", ret);                                                                \
    if (ret != 0) return CTAP2_ERR_INVALID_CBOR;                                                                       \
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
    if (is_nfc()) break;                                                                                               \
    switch (wait_for_user_presence(WAIT_ENTRY_CTAPHID)) {                                                              \
    case USER_PRESENCE_CANCEL:                                                                                         \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      return timeout_response;                                                                                         \
    }                                                                                                                  \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};
// pin related
static uint8_t consecutive_pin_counter;
// assertion related
static uint8_t credential_list[MAX_DC_NUM], credential_counter, credential_idx, last_cmd;

uint8_t ctap_install(uint8_t reset) {
  consecutive_pin_counter = 3;
  credential_counter = 0;
  credential_idx = 0;
  last_cmd = 0xff;
  cp_initialize();
  if (!reset && get_file_size(CTAP_CERT_FILE) >= 0) {
    DBG_MSG("CTAP initialized\n");
    return 0;
  }
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_file(DC_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(DC_FILE, DC_NUMBERS_ATTR, kh_key, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(DC_META_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(CTAP_CERT_FILE, NULL, 0, 0, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, kh_key, 4) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, HE_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memzero(kh_key, sizeof(kh_key));
  DBG_MSG("CTAP reset and initialized\n");
  return 0;
}

int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != PRI_KEY_SIZE) EXCEPT(SW_WRONG_LENGTH);
  return write_attr(CTAP_CERT_FILE, KEY_ATTR, DATA, LC);
}

int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC > MAX_CERT_SIZE) EXCEPT(SW_WRONG_LENGTH);
  return write_file(CTAP_CERT_FILE, DATA, 0, LC, 1);
}

static void build_cose_key(uint8_t *data, uint8_t ecdh) {
  // format public key as
  // A5
  // 01 02
  // 03 26 (ecdsa) or 03 38 18 (ecdh)
  // 20 01
  // 21 58 20 x
  // 22 58 20 y
  if (ecdh) {
    memmove(data + 46, data + 32, 32);
    memmove(data + 11, data, 32);
  } else {
    memmove(data + 45, data + 32, 32);
    memmove(data + 10, data, 32);
  }
  data[0] = 0xA5;
  data[1] = 0x01;
  data[2] = 0x02;
  data[3] = 0x03;
  if (ecdh) {
    data[4] = 0x38;
    data[5] = 0x18;
    data[6] = 0x20;
    data[7] = 0x01;
    data[8] = 0x21;
    data[9] = 0x58;
    data[10] = 0x20;
    data[43] = 0x22;
    data[44] = 0x58;
    data[45] = 0x20;
  } else {
    data[4] = 0x26;
    data[5] = 0x20;
    data[6] = 0x01;
    data[7] = 0x21;
    data[8] = 0x58;
    data[9] = 0x20;
    data[42] = 0x22;
    data[43] = 0x58;
    data[44] = 0x20;
  }
}

static void build_ed25519_cose_key(uint8_t *data) {
  // A4                                    # map(4)
  //  01                                   # unsigned(1)  kty =
  //  01                                   # unsigned(2)    OKP (1)
  //  03                                   # unsigned(3)  alg =
  //  27                                   # negative(7)    EdDSA (-8)
  //  20                                   # negative(0)  crv =
  //  06                                   # unsigned(6)    Ed25519 (6)
  //  21                                   # negative(1)  x =
  //  58 20                                # bytes(32)      [bstr]
  //     (32 bytes x)

  memmove(data + 10, data, 32);
  data[0] = 0xa4;
  data[1] = 0x01;
  data[2] = 0x01;
  data[3] = 0x03;
  data[4] = 0x27;
  data[5] = 0x20;
  data[6] = 0x06;
  data[7] = 0x21;
  data[8] = 0x58;
  data[9] = 0x20;
}

uint8_t ctap_make_auth_data(uint8_t *rp_id_hash, uint8_t *buf, uint8_t flags, const uint8_t *extension,
                            uint8_t extension_size, size_t *len, int32_t alg_type, bool dc, uint8_t cred_protect) {
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

    memcpy(ad->at.aaguid, aaguid, sizeof(aaguid));
    ad->at.credential_id_length = htobe16(sizeof(credential_id));
    memcpy(ad->at.credential_id.rp_id_hash, rp_id_hash, sizeof(ad->at.credential_id.rp_id_hash));
    ad->at.credential_id.nonce[CREDENTIAL_NONCE_DC_POS] = dc ? 1 : 0;
    ad->at.credential_id.nonce[CREDENTIAL_NONCE_CP_POS] = cred_protect;
    if (generate_key_handle(&ad->at.credential_id, ad->at.public_key, alg_type) < 0) {
      DBG_MSG("Fail to generate a key handle\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
    if (alg_type == COSE_ALG_ES256) {
      build_cose_key(ad->at.public_key, 0);
      outLen += sizeof(ad->at) - sizeof(ad->at.public_key) + COSE_KEY_ES256_SIZE;
    } else if (alg_type == COSE_ALG_EDDSA) {
      build_ed25519_cose_key(ad->at.public_key);
      outLen += sizeof(ad->at) - sizeof(ad->at.public_key) + COSE_KEY_EDDSA_SIZE;
    } else {
      DBG_MSG("Unknown algorithm type\n");
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
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
  //    > This has been processed when parsing.
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
  if (has_pin() /* a) */ && (mc.parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0 /* b) */ &&
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
  //     11.2 [N/A] If the "uv" option is present and set to true
  //     11.1 If pin_uv_auth_param parameter is present (implying the "uv" option is false (see Step 5)):
  //     a) Call verify(pinUvAuthToken, client_data_hash, pin_uv_auth_param).
  //        If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
  if (!cp_verify_pin_token(mc.client_data_hash, sizeof(mc.client_data_hash), mc.pin_uv_auth_param,
                           mc.pin_uv_auth_protocol)) {
    DBG_MSG("Fail to verify pin token\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  //     b) Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
  if (!cp_has_permission(CP_PERMISSION_MC)) {
    DBG_MSG("Fail to verify pin permission\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  //     c) If the pinUvAuthToken has a permissions RP ID associated:
  //        If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
  if (!cp_verify_rp_id(mc.rp_id_hash)) {
    DBG_MSG("Fail to verify pin rp id\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  //     d) Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
  //     e) If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
  if (!cp_get_user_verified_flag_value()) {
    DBG_MSG("userVerifiedFlagValue is false\n");
    return CTAP2_ERR_PIN_AUTH_INVALID;
  }
  //     f) If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
  uv = true;
  //     g) If the pinUvAuthToken does not have a permissions RP ID associated:
  //        Associate the request’s rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
  cp_associate_rp_id(mc.rp_id_hash);
  DBG_MSG("PIN verified\n");

  step12:
  // 12. If the exclude_list parameter is present and contains a credential ID created by this authenticator, that is bound to the specified rp.id:
  //     a) If the credential’s credProtect value is not userVerificationRequired, then:
  if (mc.exclude_list_size > 0) {
    for (size_t i = 0; i < mc.exclude_list_size; ++i) {
      uint8_t pri_key[PRI_KEY_SIZE];
      parse_credential_descriptor(&mc.exclude_list, data_buf); // save credential id in data_buf
      credential_id *kh = (credential_id *) data_buf;
      // compare rp_id first
      if (memcmp(kh->rp_id_hash, mc.rp_id_hash, sizeof(kh->rp_id_hash)) != 0) continue;
      // then verify key handle and get private key in rp_id_hash
      ret = verify_key_handle(kh, pri_key);
      memzero(pri_key, sizeof(pri_key));
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (ret == 0) {
        DBG_MSG("Exclude ID found\n");
        // TODO: follow the spec
//        WAIT();
        return CTAP2_ERR_CREDENTIAL_EXCLUDED;
      }
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
    WAIT(CTAP2_ERR_OPERATION_DENIED);
  }
  //     c) [N/A] Set the "up" bit to true in the response
  //     d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  // 15. If the extensions parameter is present:
  uint8_t extension_buffer[MAX_EXTENSION_SIZE_IN_AUTH];
  CborEncoder extension_encoder, map;
  cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
  ret = cbor_encoder_create_map(&extension_encoder, &map,
                                (mc.ext_hmac_secret ? 1 : 0) +
                                (mc.ext_large_blob_key ? 1 : 0) +
                                (mc.ext_cred_protect > 0 ? 1 : 0) +
                                (mc.ext_cred_blob_len > 0 ? 1 : 0));
  CHECK_CBOR_RET(ret);
  if (mc.ext_hmac_secret) {
    ret = cbor_encode_text_stringz(&map, "hmac-secret");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&map, true);
    CHECK_CBOR_RET(ret);
  }
  if (mc.ext_large_blob_key) {
    ret = cbor_encode_text_stringz(&map, "largeBlobKey");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&map, true);
    CHECK_CBOR_RET(ret);
  }
  if (mc.ext_cred_protect > 0) {
    ret = cbor_encode_text_stringz(&map, "credProtect");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, mc.ext_cred_protect);
    CHECK_CBOR_RET(ret);
  }
  if (mc.ext_cred_blob_len > 0) {
    ((CTAP_auth_data *) data_buf)->at.credential_id.cred_blob_len = mc.ext_cred_blob_len;
    memcpy(((CTAP_auth_data *) data_buf)->at.credential_id.cred_blob, mc.ext_cred_blob,
           mc.ext_cred_blob_len);
    ret = cbor_encode_text_stringz(&map, "credBlob");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_boolean(&map, true);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&extension_encoder, &map);
  CHECK_CBOR_RET(ret);
  size_t extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);

  // NOW PREPARE THE RESPONSE
  ret = cbor_encoder_create_map(encoder, &map, 3);
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
  if (mc.options.rk == OPTION_TRUE) {
    DBG_MSG("Processing discoverable credential\n");
    CTAP_discoverable_credential dc;
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
      if (memcmp(mc.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0 &&
          mc.user.id_size == dc.user.id_size && memcmp(mc.user.id, dc.user.id, mc.user.id_size) == 0)
        break;
    }
    // d
    if (pos == n_dc && first_deleted != MAX_DC_NUM) {
      DBG_MSG("Use slot %d\n", first_deleted);
      pos = first_deleted;
    }
    if (pos >= MAX_DC_NUM) {
      DBG_MSG("Storage full\n");
      return CTAP2_ERR_KEY_STORE_FULL;
    }
    memcpy(&dc.credential_id, data_buf + 55, sizeof(dc.credential_id));
    memcpy(&dc.user, &mc.user, sizeof(user_entity)); // c
    dc.deleted = false;
    if (write_file(DC_FILE, &dc, pos * (int) sizeof(CTAP_discoverable_credential),
                   sizeof(CTAP_discoverable_credential), 0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    uint8_t numbers;
    if (read_attr(DC_FILE, DC_NUMBERS_ATTR, &numbers, sizeof(numbers)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    ++numbers;
    if (write_attr(DC_FILE, DC_NUMBERS_ATTR, &numbers, sizeof(numbers)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

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
      if (memcmp(mc.rp_id_hash, meta.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) break;
    }
    if (meta_pos == n_rp && first_deleted != MAX_DC_NUM) {
      DBG_MSG("Use slot %d for meta\n", first_deleted);
      meta_pos = first_deleted;
    }
    if (meta_pos == n_rp) meta.slots = 0; // a new entry's slot should be empty
    memcpy(meta.rp_id_hash, mc.rp_id_hash, SHA256_DIGEST_LENGTH);
    memcpy(meta.rp_id, mc.rp_id, MAX_STORED_RPID_LENGTH);
    meta.rp_id_len = mc.rp_id_len;
    meta.slots |= 1 << pos;
    if (write_file(DC_META_FILE, &meta, meta_pos * (int) sizeof(CTAP_rp_meta),
                   sizeof(CTAP_rp_meta), 0) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
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
    len = sign_with_device_key(data_buf, data_buf);
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
      ret = cbor_encode_byte_string(&x5carr, NULL, 0);
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

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  return 0;
}

static uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *params, size_t len, bool in_get_next_assertion) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
  static CTAP_get_assertion ga;
  CTAP_discoverable_credential dc; // We use dc to store the selected credential
  uint8_t data_buf[sizeof(CTAP_auth_data) + CLIENT_DATA_HASH_SIZE], pri_key[PRI_KEY_SIZE];
  CborParser parser;
  int ret;

  if (in_get_next_assertion) goto step7;
  ret = parse_get_assertion(&parser, &ga, params, len);
  CHECK_PARSER_RET(ret);

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
  //    > This has been processed when parsing.

  // 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as false.
  bool uv = false; // up is always true, see 9.c

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
  //    d. If the "dc" option is present then: Return CTAP2_ERR_UNSUPPORTED_OPTION.
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
  if (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) {
    //  a) Call verify(pinUvAuthToken, client_data_hash, pin_uv_auth_param).
    //     If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
    //     If the verification returns success, set the "uv" bit to true in the response.
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
      if (memcmp(dc.credential_id.rp_id_hash, ga.rp_id_hash, sizeof(dc.credential_id.rp_id_hash)) != 0) goto next;
      // then verify the key handle and get private key
      int err = verify_key_handle(&dc.credential_id, pri_key);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) {
        if (dc.credential_id.nonce[CREDENTIAL_NONCE_DC_POS]) { // Verify if it's a valid dc.
          int size = get_file_size(DC_FILE);
          if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
          int n_dc = (int) (size / sizeof(CTAP_discoverable_credential));
          bool found = false;
          for (int j = 0; j < n_dc; ++j) {
            if (read_file(DC_FILE, &dc, j * (int) sizeof(CTAP_discoverable_credential),
                          sizeof(CTAP_discoverable_credential)) < 0)
              return CTAP2_ERR_UNHANDLED_REQUEST;
            if (dc.deleted) {
              DBG_MSG("Skipped DC at %d\n", j);
              continue;
            }
            if (memcmp(ga.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) {
              found = true;
              break;
            }
          }
          if (!found) return CTAP2_ERR_NO_CREDENTIALS;
        }
        break; // Step 11: Select any credential from the applicable credentials list.
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
  } else { // Step 12
    int size;
    if (credential_idx == 0) {
      size = get_file_size(DC_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      int n_dc = (int) (size / sizeof(CTAP_discoverable_credential));
      credential_counter = 0;
      for (int i = n_dc - 1; i >= 0; --i) {  // 12-b-1
        if (read_file(DC_FILE, &dc, i * (int) sizeof(CTAP_discoverable_credential),
                      sizeof(CTAP_discoverable_credential)) < 0)
          return CTAP2_ERR_UNHANDLED_REQUEST;
        if (dc.deleted) {
          DBG_MSG("Skipped DC at %d\n", i);
          continue;
        }
        if (memcmp(ga.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0)
          credential_list[credential_counter++] = i;
      }
      // 7-f
      if (credential_counter == 0) return CTAP2_ERR_NO_CREDENTIALS;
    }
    // fetch dc and get private key
    if (read_file(DC_FILE, &dc, credential_list[credential_idx] * (int) sizeof(CTAP_discoverable_credential),
                  sizeof(CTAP_discoverable_credential)) < 0)
      return CTAP2_ERR_UNHANDLED_REQUEST;
    if (verify_key_handle(&dc.credential_id, pri_key) != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // 8. [N/A] If evidence of user interaction was provided as part of Step 6.2
  // 9. If the "up" option is set to true or not present:
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
  //    d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  // 10. If the extensions parameter is present:
  //     a) Process any extensions that this authenticator supports, ignoring any that it does not support.
  //     b) Authenticator extension outputs generated by the authenticator extension processing are returned to the
  //        authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to, or a subset
  //        of, the keys of the authenticator extension inputs map.

  uint8_t extension_buffer[79], extension_size = 0; // TODO: fix the length
  CborEncoder extension_encoder, map, sub_map;
  // build extensions
  cbor_encoder_init(&extension_encoder, extension_buffer, sizeof(extension_buffer), 0);
  ret = cbor_encoder_create_map(&extension_encoder, &map,
                                (ga.ext_cred_blob ? 1 : 0) +
                                (ga.ext_large_blob_key ? 1 : 0) +
                                ((ga.parsed_params & PARAM_HMAC_SECRET) ? 1 : 0));
  CHECK_CBOR_RET(ret);

  // Process credBlob extension
  if (ga.ext_cred_blob) {
    ret = cbor_encode_text_stringz(&map, "credBlob");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, dc.credential_id.cred_blob, dc.credential_id.cred_blob_len);
    CHECK_CBOR_RET(ret);
  }

  // Process credProtect extension
  if (dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS] == CRED_PROTECT_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST) {
    if (uv == false && ga.allow_list_size == 0) {
      DBG_MSG("credentialProtectionPolicy (0x02) failed\n");
      return CTAP2_ERR_NO_CREDENTIALS;
    }
  } else if (dc.credential_id.nonce[CREDENTIAL_NONCE_CP_POS] == CRED_PROTECT_VERIFICATION_REQUIRED) {
    if (uv == false) {
      DBG_MSG("credentialProtectionPolicy (0x03) failed\n");
      return CTAP2_ERR_NO_CREDENTIALS;
    }
  }

  // Process hmac-secret extension
  if (ga.parsed_params & PARAM_HMAC_SECRET) {
    uint8_t iv[16] = {0};
    block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
    if (credential_idx == 0) {
      ret = cp_decapsulate(ga.ext_hmac_secret_key_agreement, ga.ext_hmac_secret_pin_protocol);
      CHECK_PARSER_RET(ret);
      uint8_t hmac_buf[SHA256_DIGEST_LENGTH];
      hmac_sha256(ga.ext_hmac_secret_key_agreement, SHARED_SECRET_SIZE, ga.ext_hmac_secret_salt_enc,
                  ga.ext_hmac_secret_salt_len,
                  hmac_buf);
      if (memcmp(hmac_buf, ga.ext_hmac_secret_salt_auth, HMAC_SECRET_SALT_AUTH_SIZE) != 0)
        return CTAP2_ERR_EXTENSION_FIRST;
      cfg.key = ga.ext_hmac_secret_key_agreement;
      cfg.in_size = ga.ext_hmac_secret_salt_len;
      cfg.in = ga.ext_hmac_secret_salt_enc;
      cfg.out = ga.ext_hmac_secret_salt_enc;
      block_cipher_dec(&cfg);
    }
    ret = make_hmac_secret_output(dc.credential_id.nonce, ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_salt_len,
                                  ga.ext_hmac_secret_salt_enc, uv);
    CHECK_PARSER_RET(ret);
    DBG_MSG("hmac-secret (plain): ");
    PRINT_HEX(ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_salt_len);
    cfg.key = ga.ext_hmac_secret_key_agreement;
    cfg.in_size = ga.ext_hmac_secret_salt_len;
    cfg.in = ga.ext_hmac_secret_salt_enc;
    cfg.out = ga.ext_hmac_secret_salt_enc;
    block_cipher_enc(&cfg);
    memzero(ga.ext_hmac_secret_key_agreement, sizeof(ga.ext_hmac_secret_key_agreement));

    ret = cbor_encode_text_stringz(&map, "hmac-secret");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, ga.ext_hmac_secret_salt_enc, ga.ext_hmac_secret_salt_len);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&extension_encoder, &map);
  CHECK_CBOR_RET(ret);
  extension_size = cbor_encoder_get_buffer_size(&extension_encoder, extension_buffer);
  DBG_MSG("extension_size=%hhu\n", extension_size);

  // 13. Sign the client_data_hash along with authData with the selected credential.
  uint8_t map_items = 3;
  if (ga.allow_list_size == 0) ++map_items;
  if (credential_idx == 0 && credential_counter > 1) ++map_items;
  ret = cbor_encoder_create_map(encoder, &map, map_items);
  CHECK_CBOR_RET(ret);

  // build credential id
  ret = cbor_encode_int(&map, GA_RESP_CREDENTIAL);
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

  // auth data
  len = sizeof(data_buf);
  uint8_t flags = (extension_size > 0 ? FLAGS_ED : 0) | (uv > 0 ? FLAGS_UV : 0) | FLAGS_UP;
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
  if (dc.credential_id.alg_type == COSE_ALG_ES256) {
    sha256_init();
    sha256_update(data_buf, len);
    sha256_update(ga.client_data_hash, sizeof(ga.client_data_hash));
    sha256_final(data_buf);
    len = sign_with_ecdsa_private_key(pri_key, data_buf, data_buf);
  } else if (dc.credential_id.alg_type == COSE_ALG_EDDSA) {
    memcpy(data_buf + len, ga.client_data_hash, CLIENT_DATA_HASH_SIZE);
    len = sign_with_ed25519_private_key(pri_key, data_buf, len + CLIENT_DATA_HASH_SIZE, data_buf);
  }
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // user
  if (ga.allow_list_size == 0) {
    bool user_details = (ga.parsed_params & PARAM_PIN_UV_AUTH_PARAM) && credential_counter > 1;
    ret = cbor_encode_int(&map, GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_create_map(&map, &sub_map, user_details ? 2 : 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&sub_map, dc.user.id, dc.user.id_size);
    CHECK_CBOR_RET(ret);
    if (user_details) {
      ret = cbor_encode_text_stringz(&sub_map, "display_name");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, (char *) dc.user.display_name);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
  }

  if (credential_idx == 0 && credential_counter > 1) {
    ret = cbor_encode_int(&map, GA_RESP_NUMBER_OF_CREDENTIALS);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, credential_counter);
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  memzero(pri_key, sizeof(pri_key));
  ++credential_idx;

  return 0;
}

static uint8_t ctap_get_next_assertion(CborEncoder *encoder) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetNextAssertion
  // 1. If authenticator does not remember any authenticatorGetAssertion parameters, return CTAP2_ERR_NOT_ALLOWED.
  if (last_cmd != CTAP_GET_ASSERTION && last_cmd != CTAP_GET_NEXT_ASSERTION) return CTAP2_ERR_NOT_ALLOWED;
  // 2. If the credentialCounter is equal to or greater than numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED.
  if (credential_idx >= credential_counter) return CTAP2_ERR_NOT_ALLOWED;
  // 3. [TODO] If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than
  //    30 seconds, discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
  //    This step is OPTIONAL if transport is done over NFC.
  // 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
  // 5. Update the response to include the selected credential’s publicKeyCredentialUserEntity information.
  //    User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be
  //    returned if user verification was not done by the authenticator in the original authenticatorGetAssertion call.
  // 6. Sign the client_data_hash along with authData with the selected credential.
  // 7. [TODO] Reset the timer. This step is OPTIONAL if transport is done over NFC.
  // 8. Increment credentialCounter.
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
  ret = cbor_encoder_create_array(&map, &array, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "FIDO_2_1");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "U2F_V2");
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // extensions
  ret = cbor_encode_int(&map, GI_RESP_EXTENSIONS);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 4);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "hmac-secret");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "credProtect");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "largeBlobKey");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "credBlob");
  CHECK_CBOR_RET(ret);
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
  ret = cbor_encoder_create_map(&map, &option_map, 5);
  CHECK_CBOR_RET(ret);
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
  ret = cbor_encode_boolean(&option_map, has_pin() > 0);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&option_map, "pinUvAuthToken");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_boolean(&option_map, true);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&option_map, "largeBlobs");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_boolean(&option_map, true);
  CHECK_CBOR_RET(ret);
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
  ret = cbor_encode_int(&array, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&array, 1);
  CHECK_CBOR_RET(ret);
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
  ret = cbor_encode_text_stringz(&array, "usb");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&array, "nfc");
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // algorithms
  ret = cbor_encode_int(&map, GI_RESP_ALGORITHMS);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_map(&array, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "type");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "public-key");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "alg");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&sub_map, -7); // ES256 (P-256)
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&array, &sub_map);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_map(&array, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "type");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "public-key");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "alg");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&sub_map, -8); // EdDSA
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&array, &sub_map);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // maxSerializedLargeBlobArray
  ret = cbor_encode_int(&map, GI_RESP_MAX_SERIALIZED_LARGE_BLOB_ARRAY);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, 1024);   // TODO: update
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
  int err, retries;
  switch (cp.sub_command) {
    case CP_CMD_GET_PIN_RETRIES:
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
      ret = cbor_encoder_create_map(encoder, &map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CP_RESP_KEY_AGREEMENT);
      CHECK_CBOR_RET(ret);
      // to save RAM, generate an empty key first, then fill it manually
      ret = cbor_encoder_create_map(&map, &key_map, 0);
      CHECK_CBOR_RET(ret);
      ptr = key_map.data.ptr - 1;
      cp_get_public_key(ptr);
      build_cose_key(ptr, 1);
      key_map.data.ptr = ptr + MAX_COSE_KEY_SIZE;
      ret = cbor_encoder_close_container(&map, &key_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CP_CMD_SET_PIN:
      err = has_pin();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err > 0) return CTAP2_ERR_PIN_AUTH_INVALID;
      ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      DBG_MSG("Shared Secret: ");
      PRINT_HEX(cp.key_agreement, PUB_KEY_SIZE);
      if (!cp_verify(cp.key_agreement, SHARED_SECRET_SIZE, cp.new_pin_enc,
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
      err = has_pin();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
      err = get_pin_retries();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
      if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
      retries = err - 1;
#endif
      ret = cp_decapsulate(cp.key_agreement, cp.pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      if (cp.pin_uv_auth_protocol == 1) {
        memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P1);
        memcpy(buf + PIN_ENC_SIZE_P1, cp.pin_hash_enc, PIN_HASH_SIZE_P1);
        ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE, buf, PIN_ENC_SIZE_P1 + PIN_HASH_SIZE_P1,
                        cp.pin_uv_auth_param, cp.pin_uv_auth_protocol);
      } else {
        memcpy(buf, cp.new_pin_enc, PIN_ENC_SIZE_P2);
        memcpy(buf + PIN_ENC_SIZE_P2, cp.pin_hash_enc, PIN_HASH_SIZE_P2);
        ret = cp_verify(cp.key_agreement, SHARED_SECRET_SIZE, buf, PIN_ENC_SIZE_P2 + PIN_HASH_SIZE_P2,
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
        if (consecutive_pin_counter == 1) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        --consecutive_pin_counter;
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
      // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinToken
      // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#getPinUvAuthTokenUsingPinWithPermissions
      err = has_pin();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
      err = get_pin_retries();
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
      if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
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
        if (consecutive_pin_counter == 1) return CTAP2_ERR_PIN_AUTH_BLOCKED;
        --consecutive_pin_counter;
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
  if (idx != -1) *slots &= ~(1 << idx);
  return idx;
}

static uint8_t ctap_credential_management(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_credential_management cm;
  int ret = parse_credential_management(&parser, &cm, params, len);
  CHECK_PARSER_RET(ret);

  static int idx, n_rp; // for rp enumeration
  static uint64_t slots; // for credential enumeration
  int size, counter;
  CborEncoder map, sub_map;
  uint8_t numbers;
  CTAP_rp_meta meta;
  CTAP_discoverable_credential dc;
  uint8_t *buf = (uint8_t *) &dc;
  bool include_numbers;
  if (read_attr(DC_FILE, DC_NUMBERS_ATTR, &numbers, sizeof(numbers)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

  switch (cm.sub_command) {
    case CM_CMD_GET_CREDS_METADATA:
      if (!cp_verify_pin_token((uint8_t[]) {CM_CMD_GET_CREDS_METADATA}, 1, cm.pin_uv_auth_param,
                               cm.pin_uv_auth_protocol)) {
        DBG_MSG("PIN verification error\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      if (!cp_has_permission(CP_PERMISSION_CM) || cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
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
      if (!cp_verify_pin_token((uint8_t[]) {CM_CMD_ENUMERATE_RPS_BEGIN}, 1, cm.pin_uv_auth_param,
                               cm.pin_uv_auth_protocol)) {
        DBG_MSG("PIN verification error\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      if (!cp_has_permission(CP_PERMISSION_CM) || cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      size = get_file_size(DC_META_FILE), counter = 0;
      n_rp = size / (int) sizeof(CTAP_rp_meta);
      for (int i = n_rp - 1; i >= 0; --i) {
        size = read_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots > 0) {
          idx = i;
          ++counter;
        }
      }
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
      // TODO: make sure the last cmd was CM_CMD_ENUMERATE_RPS_BEGIN
      for (int i = idx + 1; i < n_rp; ++i) {
        size = read_file(DC_META_FILE, &meta, i * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots > 0) break;
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
      include_numbers = true;
      buf[0] = CM_CMD_ENUMERATE_CREDENTIALS_BEGIN;
      buf[1] = 0xA1;
      buf[2] = 0x01;
      buf[3] = 0x58;
      buf[4] = 0x20;
      memcpy(&buf[5], cm.rp_id_hash, SHA256_DIGEST_LENGTH);
      if (!cp_verify_pin_token(buf, SHA256_DIGEST_LENGTH + 5, cm.pin_uv_auth_param, cm.pin_uv_auth_protocol)) {
        DBG_MSG("PIN verification error\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      if (!cp_has_permission(CP_PERMISSION_CM) || cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      size = get_file_size(DC_META_FILE);
      n_rp = size / (int) sizeof(CTAP_rp_meta);
      for (idx = 0; idx < n_rp; ++idx) {
        size = read_file(DC_META_FILE, &meta, idx * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (meta.slots == 0) continue;
        if (memcmp(meta.rp_id_hash, cm.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) break;
      }
      if (idx == n_rp) {
        DBG_MSG("Specified RP not found\n");
        return CTAP2_ERR_NO_CREDENTIALS;
      }
      slots = meta.slots;
    generate_credential_response:
      idx = get_next_slot(&slots, &numbers);
      size = read_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                       sizeof(CTAP_discoverable_credential));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      ret = cbor_encoder_create_map(encoder, &map, include_numbers ? 5 : 4);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_int(&map, CM_RESP_USER);
      CHECK_CBOR_RET(ret);
      ret = cbor_encoder_create_map(&map, &sub_map, 1);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "id");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_byte_string(&sub_map, dc.user.id, dc.user.id_size);
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
      uint8_t *ptr = sub_map.data.ptr - 1;
      ret = verify_key_handle(&dc.credential_id, ptr);
      if (ret != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (dc.credential_id.alg_type == COSE_ALG_ES256) {
        ecc_get_public_key(ECC_SECP256R1, ptr, ptr);
        build_cose_key(ptr, 0);
        sub_map.data.ptr = ptr + COSE_KEY_ES256_SIZE;
      } else if (dc.credential_id.alg_type == COSE_ALG_EDDSA) {
        ed25519_publickey(ptr, ptr);
        build_ed25519_cose_key(ptr);
        sub_map.data.ptr = ptr + COSE_KEY_EDDSA_SIZE;
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
      ret = cbor_encoder_close_container(encoder, &map);
      CHECK_CBOR_RET(ret);
      break;

    case CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL:
      // TODO: check last command
      include_numbers = false;
      goto generate_credential_response;

    case CM_CMD_DELETE_CREDENTIAL:
      buf[0] = CM_CMD_DELETE_CREDENTIAL;
      buf[1] = 0xA1;
      buf[2] = 0x02;
      buf[3] = 0xA2;
      buf[4] = 0x62;
      buf[5] = 0x69;
      buf[6] = 0x64;
      buf[7] = 0x58;
      buf[8] = sizeof(credential_id);
      memcpy(&buf[9], &cm.credential_id, sizeof(credential_id));
      memcpy(&buf[9 + sizeof(credential_id)], "\x64type\x6Apublic-key", 16);
      DBG_MSG("Pin Auth Msg: ");
      PRINT_HEX(buf, sizeof(credential_id) + 25);
      if (!cp_verify_pin_token(buf, sizeof(credential_id) + 25, cm.pin_uv_auth_param, cm.pin_uv_auth_protocol)) {
        DBG_MSG("PIN verification error\n");
        return CTAP2_ERR_PIN_AUTH_INVALID;
      }
      if (!cp_has_permission(CP_PERMISSION_CM) || cp_has_associated_rp_id()) return CTAP2_ERR_PIN_AUTH_INVALID;
      if (numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
      size = get_file_size(DC_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      numbers = size / sizeof(CTAP_discoverable_credential);
      for (idx = 0; idx < numbers; ++idx) {
        size = read_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                         sizeof(CTAP_discoverable_credential));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (dc.deleted) continue;
        if (memcmp(&dc.credential_id, &cm.credential_id, sizeof(credential_id)) == 0) {
          DBG_MSG("Found, rp_id_hash: ");
          PRINT_HEX(dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH);
          break;
        }
      }
      if (idx == numbers) return CTAP2_ERR_NO_CREDENTIALS;
      // TODO: how to achieve the consistency?
      // delete dc first
      dc.deleted = true;
      if (write_file(DC_FILE, &dc, idx * (int) sizeof(CTAP_discoverable_credential),
                     sizeof(CTAP_discoverable_credential),
                     0) < 0)
        return CTAP2_ERR_UNHANDLED_REQUEST;
      if (read_attr(DC_FILE, DC_NUMBERS_ATTR, &numbers, sizeof(numbers)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      --numbers;
      if (write_attr(DC_FILE, DC_NUMBERS_ATTR, &numbers, sizeof(numbers)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      // delete the meta then
      size = get_file_size(DC_META_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      numbers = size / sizeof(CTAP_rp_meta);
      for (int i = 0; i < numbers; ++i) {
        size = read_file(DC_META_FILE, &meta, idx * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (memcmp(meta.rp_id_hash, dc.credential_id.rp_id_hash, SHA256_DIGEST_LENGTH) == 0) {
          meta.slots &= ~(1 << idx);
          size = write_file(DC_META_FILE, &meta, idx * (int) sizeof(CTAP_rp_meta), sizeof(CTAP_rp_meta), 0);
          if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
          break;
        }
      }
      break;

    case CM_CMD_UPDATE_USER_INFORMATION:
      // TODO
      break;
  }

  return 0;
}

static uint8_t ctap_selection(void) {
  WAIT(CTAP2_ERR_USER_ACTION_TIMEOUT);
  return 0;
}

int ctap_process_cbor(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len) {
  if (req_len-- == 0) return -1;
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
      credential_idx = 0;
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
      *resp = ctap_install(1);
      *resp_len = 1;
      break;
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
      *resp = ctap_credential_management(&encoder, req, req_len);
      SET_RESP();
      break;
    case CTAP_CONFIG:
      DBG_MSG("----------------CONFIG----------------\n");
      *resp = ctap_credential_management(&encoder, req, req_len);
      SET_RESP();
      break;
    default:
      *resp = CTAP2_ERR_UNHANDLED_REQUEST;
      *resp_len = 1;
      break;
  }
  last_cmd = cmd;
  return 0;
}

int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  int ret = 0;
  LL = 0;
  SW = SW_NO_ERROR;
  if (CLA == 0x80) {
    if (INS == CTAP_INS_MSG) {
      // rapdu buffer size: APDU_BUFFER_SIZE
      size_t len = APDU_BUFFER_SIZE;

      ret = ctap_process_cbor(DATA, LC, RDATA, &len);
      // len is the actual len written to RDATA
      LL = len;
    } else {
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
        EXCEPT(SW_INS_NOT_SUPPORTED);
    }
  } else
    EXCEPT(SW_CLA_NOT_SUPPORTED);

  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  else
    return 0;
}
