// SPDX-License-Identifier: Apache-2.0
#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-internal.h"
#include "ctap-parser.h"
#include "pin.h"
#include "secret.h"
#include "u2f.h"
#include <aes.h>
#include <block-cipher.h>
#include <cbor.h>
#include <common.h>
#include <ctap.h>
#include <ctaphid.h>
#include <device.h>
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

#define WAIT(timeout_response)                                                                                     \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    switch (wait_for_user_presence(WAIT_ENTRY_CTAPHID)) {                                                              \
    case USER_PRESENCE_CANCEL:                                                                                         \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      return timeout_response;                                                                            \
    }                                                                                                                  \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};
// pin related
static uint8_t consecutive_pin_counter;
// assertion related
static uint8_t credential_list[MAX_RK_NUM], credential_numbers, credential_idx, last_cmd;

uint8_t ctap_install(uint8_t reset) {
  consecutive_pin_counter = 3;
  credential_numbers = 0;
  credential_idx = 0;
  last_cmd = 0xff;
  cp_initialize();
  if (!reset && get_file_size(CTAP_CERT_FILE) >= 0) {
    DBG_MSG("CTAP initialized\n");
    return 0;
  }
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_file(RK_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
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
  data[1] = 0x01; data[2] = 0x01;
  data[3] = 0x03; data[4] = 0x27;
  data[5] = 0x20; data[6] = 0x06;
  data[7] = 0x21; data[8] = 0x58; data[9] = 0x20;
}

uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t flags, uint8_t extensionSize,
                            const uint8_t *extension, size_t *len, int32_t alg_type) {
  // See https://www.w3.org/TR/webauthn/#sec-authenticator-data
  // auth data is a byte string
  // --------------------------------------------------------------------------------
  //  Name      |  Length  | Description
  // -----------|----------|---------------------------------------------------------
  //  rpIdHash  |  32      | SHA256 of rpId, we generate it outside of this function
  //  flags     |  1       | 0: UP, 2: UV, 6: AT, 7: ED
  //  signCount |  4       | 32-bit endian number
  //  attCred   |  var     | Exist iff in authenticatorMakeCredential request
  //            |          | 16-byte aaguid
  //            |          | 2-byte key handle length
  //            |          | key handle
  //            |          | public key (in COSE_key format)
  //  extension |  var     | IGNORE FOR NOW
  // --------------------------------------------------------------------------------
  size_t outLen = 37; // without attCred
  CTAP_authData *ad = (CTAP_authData *)buf;
  if (*len < outLen) return CTAP2_ERR_LIMIT_EXCEEDED;

  memcpy(ad->rpIdHash, rpIdHash, sizeof(ad->rpIdHash));
  ad->flags = flags;

  uint32_t ctr;
  int ret = increase_counter(&ctr);
  if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  ad->signCount = htobe32(ctr);

  if (flags & FLAGS_AT) {
    if (*len < outLen + sizeof(ad->at) - 1) return CTAP2_ERR_LIMIT_EXCEEDED;

    memcpy(ad->at.aaguid, aaguid, sizeof(aaguid));
    ad->at.credentialIdLength = htobe16(sizeof(CredentialId));
    memcpy(ad->at.credentialId.rpIdHash, rpIdHash, sizeof(ad->at.credentialId.rpIdHash));
    if (generate_key_handle(&ad->at.credentialId, ad->at.publicKey, alg_type) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (alg_type == COSE_ALG_ES256) {
      build_cose_key(ad->at.publicKey, 0);
      outLen += sizeof(ad->at) - sizeof(ad->at.publicKey) + COSE_KEY_ES256_SIZE;
    } else if (alg_type == COSE_ALG_EDDSA) {
      build_ed25519_cose_key(ad->at.publicKey);
      outLen += sizeof(ad->at) - sizeof(ad->at.publicKey) + COSE_KEY_EDDSA_SIZE;
    } else {
      return CTAP2_ERR_UNHANDLED_REQUEST;
    }
  }
  if (flags & FLAGS_ED) {
    if (*len < outLen + extensionSize) return CTAP2_ERR_LIMIT_EXCEEDED;
    memcpy(buf + outLen, extension, extensionSize);
    outLen += extensionSize;
  }
  *len = outLen;
  return 0;
}

static uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg
  uint8_t data_buf[sizeof(CTAP_authData)];
  CborParser parser;
  CTAP_makeCredential mc;
  // CBOR of {"hmac-secret": true}
  const uint8_t hmacExt[] = {0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5};

  int ret = parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);

  // 1. If authenticator supports clientPin features and the platform sends a zero length pinUvAuthParam
  if ((mc.parsedParams & PARAM_pinUvAuthParam) && mc.pinUvAuthParamLength == 0) {
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

  // 2. If the pinUvAuthParam parameter is present
  if (mc.parsedParams & PARAM_pinUvAuthParam) {
    // a. If the pinUvAuthProtocol parameter’s value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
    if (mc.pinUvAuthProtocol != 1) return CTAP1_ERR_INVALID_PARAMETER;
    // b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
    if ((mc.parsedParams & PARAM_pinUvAuthProtocol) == 0) return CTAP2_ERR_MISSING_PARAMETER;
  }

  // 3. Validate pubKeyCredParams with the following steps
  //    > This has been processed when parsing.

  // 4. Create a new authenticatorMakeCredential response structure and initialize both its "uv" bit and "up" bit as false.
  bool uv = false, up = false;

  // 5. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (mc.options.uv == OPTION_ABSENT) mc.options.uv = OPTION_FALSE;
  //    b. If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
  if (mc.parsedParams & PARAM_pinUvAuthParam) mc.options.uv = OPTION_FALSE;
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
    DBG_MSG("Rule 5-f not satisfied.\n");
    return CTAP2_ERR_INVALID_OPTION;
  }
  //    g. If the "up" option is absent, let the "up" option be treated as being present with the value true
  mc.options.up = OPTION_TRUE;

  // 6. [N/A] If the alwaysUv option ID is present and true
  // 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response
  //    If the following statements are all true:
  //    a) The authenticator is protected by some form of user verification.
  //    b) [ALWAYS TRUE] The "uv" option is set to false.
  //    c) The pinUvAuthParam parameter is not present.
  //    d) The "rk" option is present and set to true.
  if (has_pin() /* a) */ && (mc.parsedParams & PARAM_pinUvAuthParam) == 0 /* b) */ &&mc.options.rk == OPTION_TRUE) {
    // If ClientPin option ID is true and the noMcGaPermissionsWithClientPin option ID is absent or false,
    // end the operation by returning CTAP2_ERR_PUAT_REQUIRED.
    return CTAP2_ERR_PUAT_REQUIRED;
    // [N/A] Otherwise, end the operation by returning CTAP2_ERR_OPERATION_DENIED.
  }

  // 8. [N/A] Else (the makeCredUvNotRqd option ID is present with the value false or is absent)

  // 9. [N/A] If the enterpriseAttestation parameter is present

  // 10. If the following statements are all true
  //     a) "rk" and "uv" [ALWAYS TRUE] options are both set to false or omitted.
  //     b) [ALWAYS TRUE] the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
  //     c) the pinUvAuthParam parameter is not present.
  //     Then go to Step 12.
  if (mc.options.rk == OPTION_FALSE && (mc.parsedParams & PARAM_pinUvAuthParam) == 0) goto step12;

  // 11. If the authenticator is protected by some form of user verification, then:
  //     11.2 [N/A] If the "uv" option is present and set to true
  //     11.1 If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
  //     a) Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
  //        If the verification returns error, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
  if (!cp_verify_pin_token(mc.clientDataHash, sizeof(mc.clientDataHash), mc.pinUvAuthParam))
    return CTAP2_ERR_PIN_AUTH_INVALID;
  //     b) Verify that the pinUvAuthToken has the mc permission, if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
  if (!pin_has_permission(CP_PERMISSION_MC)) return CTAP2_ERR_PIN_AUTH_INVALID;
  //     c) If the pinUvAuthToken has a permissions RP ID associated:
  //        If the permissions RP ID does not match the rp.id in this request, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
  if (!pin_verify_rp_id(mc.rpIdHash)) return CTAP2_ERR_PIN_AUTH_INVALID;
  //     d) Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
  //     e) If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
  if (!cp_get_user_verified_flag_value()) return CTAP2_ERR_PIN_AUTH_INVALID;
  //     f) If userVerifiedFlagValue is true then set the "uv" bit to true in the response.
  uv = true;
  //     g) If the pinUvAuthToken does not have a permissions RP ID associated:
  //        Associate the request’s rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
  pin_associate_rp_id(mc.rpIdHash);

step12:
  // 12. If the excludeList parameter is present and contains a credential ID created by this authenticator, that is bound to the specified rp.id:
  //     a) If the credential’s credProtect value is not userVerificationRequired, then:
  if (mc.excludeListSize > 0) {
    for (size_t i = 0; i < mc.excludeListSize; ++i) {
      uint8_t pri_key[PRI_KEY_SIZE];
      parse_credential_descriptor(&mc.excludeList, data_buf); // save credential id in data_buf
      CredentialId *kh = (CredentialId *)data_buf;
      // compare rpId first
      if (memcmp(kh->rpIdHash, mc.rpIdHash, sizeof(kh->rpIdHash)) != 0) continue;
      // then verify key handle and get private key in rpIdHash
      ret = verify_key_handle(kh, pri_key);
      memzero(pri_key, sizeof(pri_key));
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (ret == 0) {
        DBG_MSG("Exclude ID found\n");
        // TODO: follow the spec
//        WAIT();
        return CTAP2_ERR_CREDENTIAL_EXCLUDED;
      }
      ret = cbor_value_advance(&mc.excludeList);
      CHECK_CBOR_RET(ret);
    }
  }

  // 13. [N/A] If evidence of user interaction was provided as part of Step 11

  // 14. [ALWAYS TRUE] If the "up" option is set to true
  //     a) If the pinUvAuthParam parameter is present then:
  if (mc.parsedParams & PARAM_pinUvAuthParam) {
    if (!cp_get_user_present_flag_value()) {
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
  } else {
    //   b) Else (implying the pinUvAuthParam parameter is not present)
    WAIT(CTAP2_ERR_OPERATION_DENIED);
  }
  //     c) Set the "up" bit to true in the response
  up = true;
  //     d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  // NOW PREPARE THE RESPONSE
  CborEncoder map;
  ret = cbor_encoder_create_map(encoder, &map, 3);
  CHECK_CBOR_RET(ret);

  // [member name] fmt
  ret = cbor_encode_int(&map, RESP_fmt);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&map, "packed");
  CHECK_CBOR_RET(ret);

  // 15. If the extensions parameter is present:
  // > Here, we only process the hmac-secret extension in ctap_make_auth_data()
  // TODO: more extensions
  // 16. Generate a new credential key pair for the algorithm chosen in step 3.
  // [member name] authData
  len = sizeof(data_buf);
  uint8_t flags = FLAGS_AT | (mc.extension_hmac_secret ? FLAGS_ED : 0) | (uv ? FLAGS_UV : 0) | (up ? FLAGS_UP : 0);
  ret = ctap_make_auth_data(mc.rpIdHash, data_buf, flags, sizeof(hmacExt), hmacExt, &len, mc.alg_type);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, RESP_authData);
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
    CTAP_residentKey rk;
    int size = get_file_size(RK_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    size_t nRk = size / sizeof(CTAP_residentKey), i;
    for (i = 0; i != nRk; ++i) {
      size = read_file(RK_FILE, &rk, i * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      // b
      if (memcmp(mc.rpIdHash, rk.credential_id.rpIdHash, SHA256_DIGEST_LENGTH) == 0 &&
          mc.user.id_size == rk.user.id_size && memcmp(mc.user.id, rk.user.id, mc.user.id_size) == 0)
        break;
    }
    // d
    if (i >= MAX_RK_NUM) return CTAP2_ERR_KEY_STORE_FULL;
    memcpy(&rk.credential_id, data_buf + 55, sizeof(rk.credential_id));
    memcpy(&rk.user, &mc.user, sizeof(UserEntity)); // c
    ret = write_file(RK_FILE, &rk, i * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey), 0);
    if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
  // 19. Generate an attestation statement for the newly-created credential using clientDataHash

  // [member name] attStmt
  // https://www.w3.org/TR/webauthn/#packed-attestation
  // {
  //   alg: COSE_ALG_ES256,
  //   sig: bytes (ASN.1),
  //   x5c: [ attestnCert: bytes, * (caCert: bytes) ]
  // }
  ret = cbor_encode_int(&map, RESP_attStmt);
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
    sha256_update(mc.clientDataHash, sizeof(mc.clientDataHash));
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

static uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
  static CTAP_getAssertion ga;
  uint8_t data_buf[sizeof(CTAP_authData) + CLIENT_DATA_HASH_SIZE], pri_key[PRI_KEY_SIZE];
  CborParser parser;

  int ret;
  if (credential_idx == 0) {
    ret = parse_get_assertion(&parser, &ga, params, len);
    CHECK_PARSER_RET(ret);
  }

  // 1. If authenticator supports clientPin features and the platform sends a zero length pinUvAuthParam
  if ((ga.parsedParams & PARAM_pinUvAuthParam) && ga.pinUvAuthParamLength == 0) {
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

  // 2. If the pinUvAuthParam parameter is present
  if (ga.parsedParams & PARAM_pinUvAuthParam) {
    // a. If the pinUvAuthProtocol parameter’s value is not supported, return CTAP1_ERR_INVALID_PARAMETER error.
    if (ga.pinUvAuthProtocol != 1) return CTAP1_ERR_INVALID_PARAMETER;
    // b. If the pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER error.
    if ((ga.parsedParams & PARAM_pinUvAuthProtocol) == 0) return CTAP2_ERR_MISSING_PARAMETER;
  }

  // 3. Create a new authenticatorGetAssertion response structure and initialize both its "uv" bit and "up" bit as false.
  bool uv = false, up = false;

  // 4. If the options parameter is present, process all option keys and values present in the parameter.
  //    a. If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
  if (ga.options.uv == OPTION_ABSENT) ga.options.uv = OPTION_FALSE;
  //    b. If the pinUvAuthParam is present, let the "uv" option be treated as being present with the value false.
  if (ga.parsedParams & PARAM_pinUvAuthParam) ga.options.uv = OPTION_FALSE;
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
  if (ga.options.rk != OPTION_ABSENT) return CTAP2_ERR_UNSUPPORTED_OPTION;
  //    e. If the "up" option is not present then: Let the "up" option be treated as being present with the value true.
  if (ga.options.up == OPTION_ABSENT) ga.options.up = OPTION_TRUE;

  // 5. [N/A] If the alwaysUv option ID is present and true and the "up" option is present and true

  // 6. If authenticator is protected by some form of user verification, then:
  //    6.2 [N/A] If the "uv" option is present and set to true
  //    6.1 If pinUvAuthParam parameter is present
  if (ga.parsedParams & PARAM_pinUvAuthParam) {
    //  a) Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
    //     If the verification returns error, return CTAP2_ERR_PIN_AUTH_INVALID error.
    //     If the verification returns success, set the "uv" bit to true in the response.
    if (!cp_verify_pin_token(ga.clientDataHash, sizeof(ga.clientDataHash), ga.pinUvAuthParam))
      return CTAP2_ERR_PIN_AUTH_INVALID;
    uv = true;
    //  b) Let userVerifiedFlagValue be the result of calling getUserVerifiedFlagValue().
    //  c) If userVerifiedFlagValue is false then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
    if (!cp_get_user_verified_flag_value()) return CTAP2_ERR_PIN_AUTH_INVALID;
    //  d) Verify that the pinUvAuthToken has the ga permission, if not, return CTAP2_ERR_PIN_AUTH_INVALID.
    if (!pin_has_permission(CP_PERMISSION_GA)) return CTAP2_ERR_PIN_AUTH_INVALID;
    //  e) If the pinUvAuthToken has a permissions RP ID associated:
    //     If the permissions RP ID does not match the rpId in this request, return CTAP2_ERR_PIN_AUTH_INVALID.
    if (!pin_verify_rp_id(ga.rpIdHash)) return CTAP2_ERR_PIN_AUTH_INVALID;
    //  f) If the pinUvAuthToken does not have a permissions RP ID associated:
    //     Associate the request’s rpId parameter value with the pinUvAuthToken as its permissions RP ID.
    pin_associate_rp_id(ga.rpIdHash);
  }

  // 7. Locate all credentials that are eligible for retrieval under the specified criteria
  //    a) If the allowList parameter is present and is non-empty, locate all denoted credentials created by this
  //       authenticator and bound to the specified rpId.
  //    b) If an allowList is not present, locate all discoverable credentials that are created by this authenticator
  //       and bound to the specified rpId.
  //    c) Create an applicable credentials list populated with the located credentials.
  //    d) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationRequired, and the "uv" bit is false in the response, remove that credential from the
  //       applicable credentials list.
  //    e) Iterate through the applicable credentials list, and if credential protection for a credential is marked
  //       as userVerificationOptionalWithCredentialIDList and there is no allowList passed by the client and the "uv"
  //       bit is false in the response, remove that credential from the applicable credentials list.
  //    f) If the applicable credentials list is empty, return CTAP2_ERR_NO_CREDENTIALS.
  //    g) Let numberOfCredentials be the number of applicable credentials found.
  // NOTE: only one credential is used as stated in Step 11 & 12; therefore, we select that credential according to
  //       Step 11 & 12:
  // 11. If the allowList parameter is present:
  //     Select any credential from the applicable credentials list.
  //     Delete the numberOfCredentials member.
  // 12. If allowList is not present:
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
  CTAP_residentKey rk; // We use rk to store the selected credential
  if (ga.allowListSize > 0) { // Step 11
    size_t i;
    for (i = 0; i < ga.allowListSize; ++i) {
      parse_credential_descriptor(&ga.allowList, (uint8_t *) &rk.credential_id);
      // compare the rpId first
      if (memcmp(rk.credential_id.rpIdHash, ga.rpIdHash, sizeof(rk.credential_id.rpIdHash)) != 0) goto next;
      // then verify the key handle and get private key
      int err = verify_key_handle(&rk.credential_id, pri_key);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) break; // Step 11: Select any credential from the applicable credentials list.
      next:
      ret = cbor_value_advance(&ga.allowList);
      CHECK_CBOR_RET(ret);
    }
    // 7-f
    if (i == ga.allowListSize) return CTAP2_ERR_NO_CREDENTIALS;
  } else { // Step 12
    int size = 0;
    if (credential_idx == 0) {
      // TODO: 12-b-2-iii
      size = get_file_size(RK_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      int nRk = (int)(size / sizeof(CTAP_residentKey));
      credential_numbers = 0;
      for (int i = nRk - 1; i >= 0; --i) {  // 12-b-1
        size = read_file(RK_FILE, &rk, i * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (memcmp(ga.rpIdHash, rk.credential_id.rpIdHash, SHA256_DIGEST_LENGTH) == 0)
          credential_list[credential_numbers++] = i;
      }
      // 7-f
      if (credential_numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    }
    // fetch rk and get private key
    size =
            read_file(RK_FILE, &rk, credential_list[credential_idx] * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    int err = verify_key_handle(&rk.credential_id, pri_key);
    if (err != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  // 8. [N/A] If evidence of user interaction was provided as part of Step 6.2
  // 9. If the "up" option is set to true or not present:
  //    a) If the pinUvAuthParam parameter is present then:
  if (ga.parsedParams & PARAM_pinUvAuthParam) {
    if (!cp_get_user_present_flag_value()) {
      WAIT(CTAP2_ERR_OPERATION_DENIED);
    }
  } else {
  //    b) Else (implying the pinUvAuthParam parameter is not present):
    WAIT(CTAP2_ERR_OPERATION_DENIED);
  }
  //    c) Set the "up" bit to true in the response.
  up = true;
  //    d) Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
  cp_clear_user_present_flag();
  cp_clear_user_verified_flag();
  cp_clear_pin_uv_auth_token_permissions_except_lbw();

  // 10. If the extensions parameter is present:
  //     a) Process any extensions that this authenticator supports, ignoring any that it does not support.
  //     b) Authenticator extension outputs generated by the authenticator extension processing are returned in the
  //        authenticator data. The set of keys in the authenticator extension outputs map MUST be equal to, or a subset
  //        of, the keys of the authenticator extension inputs map.
  uint8_t extensionBuffer[79], extensionSize = 0;
  uint8_t iv[16] = {0};
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  if ((ga.parsedParams & PARAM_hmacSecret) && credential_idx == 0) {
    // TODO
//    ret = get_shared_secret(ga.hmacSecretKeyAgreement);
//    CHECK_PARSER_RET(ret);
    uint8_t hmac_buf[SHA256_DIGEST_LENGTH];
    hmac_sha256(ga.hmacSecretKeyAgreement, SHARED_SECRET_SIZE, ga.hmacSecretSaltEnc, ga.hmacSecretSaltLen, hmac_buf);
    if (memcmp(hmac_buf, ga.hmacSecretSaltAuth, HMAC_SECRET_SALT_AUTH_SIZE) != 0) return CTAP2_ERR_EXTENSION_FIRST;
    cfg.key = ga.hmacSecretKeyAgreement;
    cfg.in_size = ga.hmacSecretSaltLen;
    cfg.in = ga.hmacSecretSaltEnc;
    cfg.out = ga.hmacSecretSaltEnc;
    block_cipher_dec(&cfg);
  }

  if (ga.parsedParams & PARAM_hmacSecret) {
    ret = make_hmac_secret_output(rk.credential_id.nonce, ga.hmacSecretSaltEnc, ga.hmacSecretSaltLen,
                                  ga.hmacSecretSaltEnc);
    if (ret) return ret;
    DBG_MSG("hmac-secret(plain): ");
    PRINT_HEX(ga.hmacSecretSaltEnc, ga.hmacSecretSaltLen);
    cfg.key = ga.hmacSecretKeyAgreement;
    cfg.in_size = ga.hmacSecretSaltLen;
    cfg.in = ga.hmacSecretSaltEnc;
    cfg.out = ga.hmacSecretSaltEnc;
    block_cipher_enc(&cfg);
    memzero(ga.hmacSecretKeyAgreement, sizeof(ga.hmacSecretKeyAgreement));

    CborEncoder extensionEncoder;
    CborEncoder map;
    // build extensions
    cbor_encoder_init(&extensionEncoder, extensionBuffer, sizeof(extensionBuffer), 0);
    ret = cbor_encoder_create_map(&extensionEncoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&map, "hmac-secret");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, ga.hmacSecretSaltEnc, ga.hmacSecretSaltLen);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(&extensionEncoder, &map);
    CHECK_CBOR_RET(ret);

    extensionSize = cbor_encoder_get_buffer_size(&extensionEncoder, extensionBuffer);
    DBG_MSG("extensionSize=%hhu\n", extensionSize);
  }

  // 13. Sign the clientDataHash along with authData with the selected credential.
  CborEncoder map, sub_map;
  uint8_t map_items = 3;
  if (ga.allowListSize == 0) ++map_items;
  if (credential_idx == 0 && credential_numbers > 1) ++map_items;
  ret = cbor_encoder_create_map(encoder, &map, map_items);
  CHECK_CBOR_RET(ret);

  // build credential id
  ret = cbor_encode_int(&map, RESP_credential);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_map(&map, &sub_map, 2);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "id");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&sub_map, (const uint8_t *)&rk.credential_id, sizeof(CredentialId));
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "type");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&sub_map, "public-key");
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&map, &sub_map);
  CHECK_CBOR_RET(ret);

  // auth data
  len = sizeof(data_buf);
  uint8_t flags = ((ga.parsedParams & PARAM_hmacSecret) ? FLAGS_ED : 0) | (uv > 0 ? FLAGS_UV : 0) | (up ? FLAGS_UP : 0);
  ret = ctap_make_auth_data(ga.rpIdHash, data_buf, flags, extensionSize, extensionBuffer, &len, rk.credential_id.alg_type);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, RESP_authData);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // signature
  ret = cbor_encode_int(&map, RESP_signature);
  CHECK_CBOR_RET(ret);
  if (rk.credential_id.alg_type == COSE_ALG_ES256) {
    sha256_init();
    sha256_update(data_buf, len);
    sha256_update(ga.clientDataHash, sizeof(ga.clientDataHash));
    sha256_final(data_buf);
    len = sign_with_ecdsa_private_key(pri_key, data_buf, data_buf);
  } else if (rk.credential_id.alg_type == COSE_ALG_EDDSA) {
    memcpy(data_buf + len, ga.clientDataHash, CLIENT_DATA_HASH_SIZE);
    len = sign_with_ed25519_private_key(pri_key, data_buf, len + CLIENT_DATA_HASH_SIZE, data_buf);
  }
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // user
  if (ga.allowListSize == 0) {
    // CTAP Spec: User identifiable information (name, DisplayName, icon) MUST not
    // be returned if user verification is not done by the authenticator.
    bool user_details = (ga.parsedParams & PARAM_pinUvAuthParam) && credential_numbers > 1;
    ret = cbor_encode_int(&map, RESP_publicKeyCredentialUserEntity);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_create_map(&map, &sub_map, user_details ? 4 : 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&sub_map, rk.user.id, rk.user.id_size);
    CHECK_CBOR_RET(ret);
    if (user_details) {
      ret = cbor_encode_text_stringz(&sub_map, "icon");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, (char *)rk.user.icon);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "name");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, (char *)rk.user.name);
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, "displayName");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&sub_map, (char *)rk.user.displayName);
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&map, &sub_map);
    CHECK_CBOR_RET(ret);
  }

  if (credential_idx == 0 && credential_numbers > 1) {
    ret = cbor_encode_int(&map, RESP_numberOfCredentials);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, credential_numbers);
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
  if (credential_idx >= credential_numbers) return CTAP2_ERR_NOT_ALLOWED;
  // 3. [TODO] If timer since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than
  //    30 seconds, discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED.
  //    This step is OPTIONAL if transport is done over NFC.
  // 4. Select the credential indexed by credentialCounter. (I.e. credentials[n] assuming a zero-based array.)
  // 5. Update the response to include the selected credential’s publicKeyCredentialUserEntity information.
  //    User identifiable information (name, DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be
  //    returned if user verification was not done by the authenticator in the original authenticatorGetAssertion call.
  // 6. Sign the clientDataHash along with authData with the selected credential.
  // 7. [TODO] Reset the timer. This step is OPTIONAL if transport is done over NFC.
  // 8. Increment credentialCounter.
  return ctap_get_assertion(encoder, NULL, 0);
}

static uint8_t ctap_get_info(CborEncoder *encoder) {
  // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
  CborEncoder map;
  int ret = cbor_encoder_create_map(encoder, &map, 6);
  CHECK_CBOR_RET(ret);

  // versions
  ret = cbor_encode_int(&map, RESP_versions);
  CHECK_CBOR_RET(ret);
  CborEncoder array;
  ret = cbor_encoder_create_array(&map, &array, 2);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&array, "FIDO_2_1");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&array, "U2F_V2");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // extensions
  ret = cbor_encode_int(&map, RESP_extensions);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 1);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_text_stringz(&array, "hmac-secret");
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  // aaguid
  ret = cbor_encode_int(&map, RESP_aaguid);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, aaguid, sizeof(aaguid));
  CHECK_CBOR_RET(ret);

  // options
  ret = cbor_encode_int(&map, RESP_options);
  CHECK_CBOR_RET(ret);
  CborEncoder option_map;
  ret = cbor_encoder_create_map(&map, &option_map, 4);
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
  ret = cbor_encoder_close_container(&map, &option_map);
  CHECK_CBOR_RET(ret);

  // max message length
  ret = cbor_encode_int(&map, RESP_maxMsgSize);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, MAX_CTAP_BUFSIZE);
  CHECK_CBOR_RET(ret);

  // pin protocol
  ret = cbor_encode_int(&map, RESP_pinUvAuthProtocols);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_create_array(&map, &array, 1);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_int(&array, 1);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_encoder_close_container(&map, &array);
  CHECK_CBOR_RET(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t ctap_client_pin(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_clientPin cp;
  int ret = parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);

  CborEncoder map, key_map;
  uint8_t iv[16], buf[80], i;
  memzero(iv, sizeof(iv));
  uint8_t *ptr;
  int err, retries;
  switch (cp.subCommand) {
  case CP_cmdGetPINRetries:
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, RESP_pinRetries);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, get_pin_retries());
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;

  case CP_cmdGetKeyAgreement:
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, RESP_keyAgreement);
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

  case CP_cmdSetPin:
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err > 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    ret = cp_decapsulate(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    DBG_MSG("Shared Secret: ");
    PRINT_HEX(cp.keyAgreement, SHARED_SECRET_SIZE);
    if (!cp_verify(cp.keyAgreement, SHARED_SECRET_SIZE, cp.newPinEnc, sizeof(cp.newPinEnc), cp.pinUvAuthParam))
      return CTAP2_ERR_PIN_AUTH_INVALID;
    if (cp_decrypt(cp.keyAgreement, cp.newPinEnc, MAX_PIN_SIZE + 1, cp.newPinEnc)) return CTAP2_ERR_UNHANDLED_REQUEST;
    i = 63;
    while (i > 0 && cp.newPinEnc[i] == 0)
      --i;
    if (i < 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = set_pin(cp.newPinEnc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CP_cmdChangePin:
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    retries = err - 1;
#endif
    ret = cp_decapsulate(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    memcpy(buf, cp.newPinEnc, sizeof(cp.newPinEnc));
    memcpy(buf + sizeof(cp.newPinEnc), cp.pinHashEnc, sizeof(cp.pinHashEnc));
    if (!cp_verify(cp.keyAgreement, SHARED_SECRET_SIZE, buf, sizeof(cp.newPinEnc) + sizeof(cp.pinHashEnc), cp.pinUvAuthParam))
      return CTAP2_ERR_PIN_AUTH_INVALID;
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cp_decrypt(cp.keyAgreement, cp.pinHashEnc, PIN_HASH_SIZE, cp.pinHashEnc)) return CTAP2_ERR_UNHANDLED_REQUEST;
    err = verify_pin_hash(cp.pinHashEnc);
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
    if (cp_decrypt(cp.keyAgreement, cp.newPinEnc, MAX_PIN_SIZE + 1, cp.newPinEnc)) return CTAP2_ERR_UNHANDLED_REQUEST;
    i = 63;
    while (i > 0 && cp.newPinEnc[i] == 0)
      --i;
    if (i < 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = set_pin(cp.newPinEnc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CP_cmdGetPinToken:
  case CP_cmdGetPinUvAuthTokenUsingPinWithPermissions:
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    retries = err - 1;
#endif
    ret = cp_decapsulate(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (cp_decrypt(cp.keyAgreement, cp.pinHashEnc, PIN_HASH_SIZE, cp.pinHashEnc)) return CTAP2_ERR_UNHANDLED_REQUEST;
    err = verify_pin_hash(cp.pinHashEnc);
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
    // TODO: set permission and rpid
    cp_set_permission(CP_PERMISSION_MC | CP_PERMISSION_GA);
    cp_encrypt_pin_token(cp.keyAgreement, buf);
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, RESP_pinUvAuthToken);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, buf, PIN_TOKEN_SIZE);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;
  }

  return 0;
}

static uint8_t ctap_credential_management(CborEncoder *encoder, const uint8_t *params, size_t len) {
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
    *resp = ctap_get_assertion(&encoder, req, req_len);
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
