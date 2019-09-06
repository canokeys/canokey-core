#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-parser.h"
#include "secret.h"
#include <cbor.h>
#include <common.h>
#include <ctap.h>
#include <ecc.h>
#include <hmac.h>
#include <rand.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if (ret > 0) return ret;                                                                                           \
  } while (0)
#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if (ret != 0) return CTAP2_ERR_INVALID_CBOR;                                                                       \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};
static uint8_t key_agreement_pri_key[ECC_KEY_SIZE];

static void build_cose_key(uint8_t *data) {
  // format public key as
  // A5
  // 01 02
  // 03 26
  // 20 01
  // 21 58 20 x
  // 22 58 20 y
  memmove(data + 45, data + 32, 32);
  memmove(data + 10, data, 32);
  data[0] = 0xA5;
  data[1] = 0x01;
  data[2] = 0x02;
  data[3] = 0x03;
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

static uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t at, size_t *len) {
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
  CTAP_authData *ad = (CTAP_authData *)buf;
  memcpy(ad->rpIdHash, rpIdHash, sizeof(ad->rpIdHash));
  ad->flags = (at << 6) | 1;

  uint32_t ctr;
  int ret = get_sign_counter(&ctr);
  if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  ad->signCount = htobe32(ctr);

  *len = 37; // without attCred

  if (at) {
    memcpy(ad->at.aaguid, aaguid, sizeof(aaguid));
    ad->at.credentialIdLength = htobe16(sizeof(KeyHandle));
    memcpy(ad->at.credentialId.rpIdHash, rpIdHash, sizeof(ad->at.credentialId.rpIdHash));
    if (generate_key_handle(&ad->at.credentialId, ad->at.publicKey) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

    build_cose_key(ad->at.publicKey);
    *len += sizeof(ad->at);
  }
  // TODO: extensions
  return 0;
}

static int get_pin_retries(void) {
  return 3;
}

static uint8_t ctap_make_credential(CborEncoder *encoder, const uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
  CborParser parser;
  CTAP_makeCredential mc;
  uint8_t ret = parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);

  uint8_t data_buf[sizeof(CTAP_authData)];
  if (mc.excludeListSize > 0) {
    for (size_t i = 0; i < mc.excludeListSize; ++i) {
      parse_credential_descriptor(&mc.excludeList, data_buf);
      DBG_MSG("Exclude ID found\n");
      // TODO: check id
      ret = cbor_value_advance(&mc.excludeList);
      CHECK_CBOR_RET(ret);
    }
  }
  // TODO: check options
  // TODO: verify pin
  // TODO: wait for user

  // build response
  CborEncoder map;
  ret = cbor_encoder_create_map(encoder, &map, 3);
  CHECK_CBOR_RET(ret);

  // fmt
  ret = cbor_encode_int(&map, RESP_fmt);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&map, "packed");
  CHECK_CBOR_RET(ret);

  // auth data
  ret = ctap_make_auth_data(mc.rpIdHash, data_buf, 1, &len);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, RESP_authData);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // attestation statement
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

static uint8_t ctap_get_assertion(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_getAssertion ga;
  uint8_t ret = parse_get_assertion(&parser, &ga, params, len);
  CHECK_PARSER_RET(ret);

  // we do not support rk yet, so allow list is required
  if (ga.allowListSize == 0) return CTAP2_ERR_MISSING_PARAMETER;

  uint8_t data_buf[sizeof(CTAP_authData)];
  KeyHandle *kh = (KeyHandle *)data_buf;
  size_t i;
  for (i = 0; i < ga.allowListSize; ++i) {
    parse_credential_descriptor(&ga.allowList, data_buf);
    // compare rpId first
    if (memcmp(kh->rpIdHash, ga.rpIdHash, sizeof(kh->rpIdHash)) != 0) continue;
    // then verify key handle and get private key in rpIdHash
    int err = verify_key_handle(kh);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) break; // only handle one allow entry for now
    ret = cbor_value_advance(&ga.allowList);
    CHECK_CBOR_RET(ret);
  }
  if (i == ga.allowListSize) return CTAP2_ERR_NO_CREDENTIALS;

  // TODO: verify PIN
  // TODO: check options
  // TODO: wait for user

  // build response
  CborEncoder map;
  ret = cbor_encoder_create_map(encoder, &map, 2);
  CHECK_CBOR_RET(ret);

  // auth data
  ret = ctap_make_auth_data(ga.rpIdHash, data_buf, 0, &len);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, RESP_authData);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // signature
  ret = cbor_encode_int(&map, RESP_signature);
  CHECK_CBOR_RET(ret);
  sha256_init();
  sha256_update(data_buf, len);
  sha256_update(ga.clientDataHash, sizeof(ga.clientDataHash));
  sha256_final(data_buf);
  len = sign_with_private_key(kh->rpIdHash, data_buf, data_buf);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  return 0;
}

static uint8_t ctap_get_info(CborEncoder *encoder) {
  // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
  // Currently, we respond versions and aaguid.
  CborEncoder map;
  int ret = cbor_encoder_create_map(encoder, &map, 2);
  CHECK_CBOR_RET(ret);

  // versions
  ret = cbor_encode_int(&map, RESP_versions);
  CHECK_CBOR_RET(ret);
  {
    CborEncoder array;
    ret = cbor_encoder_create_array(&map, &array, 2);
    CHECK_CBOR_RET(ret);
    {
      ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
      CHECK_CBOR_RET(ret);
      ret = cbor_encode_text_stringz(&array, "U2F_V2");
      CHECK_CBOR_RET(ret);
    }
    ret = cbor_encoder_close_container(&map, &array);
    CHECK_CBOR_RET(ret);
  }

  // aaguid
  ret = cbor_encode_int(&map, RESP_aaguid);
  CHECK_CBOR_RET(ret);
  {
    ret = cbor_encode_byte_string(&map, aaguid, sizeof(aaguid));
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}


static uint8_t ctap_client_pin(CborEncoder *encoder, const uint8_t *params, size_t len) {
  CborParser parser;
  CTAP_clientPin cp;
  uint8_t ret = parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);

  CborEncoder map, key_map;
  uint8_t *ptr;
  switch (cp.subCommand) {
  case CP_cmdGetRetries:
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, RESP_retries);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, get_pin_retries());
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
    ret = ecc_generate(ECC_SECP256R1, key_agreement_pri_key, ptr);
    if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    build_cose_key(ptr);
    key_map.data.ptr = ptr + COSE_KEY_SIZE;
    ret = cbor_encoder_close_container(&map, &key_map);
    CHECK_CBOR_RET(ret);
    break;

  case CP_cmdSetPin:
    break;

  case CP_cmdChangePin:
    break;

  case CP_cmdGetPinToken:
    break;
  }

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

int ctap_process(const uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len) {
  if (req_len-- == 0) return -1;
  CborEncoder encoder;
  cbor_encoder_init(&encoder, resp + 1, *resp_len - 1, 0);

  switch (*req++) {
  case CTAP_MAKE_CREDENTIAL:
    *resp = ctap_make_credential(&encoder, req, req_len);
    if (*resp == 0)
      *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1);
    else
      *resp_len = 1;
    break;
  case CTAP_GET_ASSERTION:
    *resp = ctap_get_assertion(&encoder, req, req_len);
    if (*resp == 0)
      *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1);
    else
      *resp_len = 1;
    break;
    case CTAP_GET_INFO:
      *resp = ctap_get_info(&encoder);
      if (*resp == 0)
        *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1);
      else
        *resp_len = 1;
      break;
    case CTAP_CLIENT_PIN:
      *resp = ctap_client_pin(&encoder, req, req_len);
      if (*resp == 0)
        *resp_len = 1 + cbor_encoder_get_buffer_size(&encoder, resp + 1);
      else
        *resp_len = 1;
      break;
  }
  return 0;
}
