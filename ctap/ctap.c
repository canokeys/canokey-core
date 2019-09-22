#include "cose-key.h"
#include "ctap-errors.h"
#include "ctap-parser.h"
#include "secret.h"
#include <aes.h>
#include <block-cipher.h>
#include <cbor.h>
#include <common.h>
#include <ctap.h>
#include <device.h>
#include <ecc.h>
#include <hmac.h>
#include <memzero.h>
#include <rand.h>
#include <u2f.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if (ret != 0) DBG_MSG("CHECK_PARSER_RET %#x\n", ret);                                                              \
    if (ret > 0) return ret;                                                                                           \
  } while (0)
#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if (ret != 0) DBG_MSG("CHECK_CBOR_RET %#x\n", ret);                                                                \
    if (ret != 0) return CTAP2_ERR_INVALID_CBOR;                                                                       \
  } while (0)

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};
static uint8_t key_agreement_pri_key[ECC_KEY_SIZE];
static uint8_t pin_token[PIN_TOKEN_SIZE];
static uint8_t consecutive_pin_counter = 3;

uint8_t ctap_install(uint8_t reset) {
  if (!reset && get_file_size(CTAP_CERT_FILE) >= 0) return 0;
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_file(CTAP_CERT_FILE, NULL, 0, 0, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, kh_key, 4) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(RK_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  return 0;
}

int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC != ECC_KEY_SIZE) EXCEPT(SW_WRONG_LENGTH);
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

static uint8_t get_shared_secret(uint8_t *pub_key) {
  int ret = ecdh_decrypt(ECC_SECP256R1, key_agreement_pri_key, pub_key, pub_key);
  if (ret < 0) return 1;
  sha256_raw(pub_key, ECC_KEY_SIZE, pub_key);
  return 0;
}

static uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t at, uint8_t uv, uint8_t up, size_t *len) {
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
  ad->flags = (at << 6) | (uv << 2) | up;

  uint32_t ctr;
  int ret = get_sign_counter(&ctr);
  if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  ad->signCount = htobe32(ctr);

  *len = 37; // without attCred

  if (at) {
    memcpy(ad->at.aaguid, aaguid, sizeof(aaguid));
    ad->at.credentialIdLength = htobe16(sizeof(CredentialId));
    memcpy(ad->at.credentialId.rpIdHash, rpIdHash, sizeof(ad->at.credentialId.rpIdHash));
    if (generate_key_handle(&ad->at.credentialId, ad->at.publicKey) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

    build_cose_key(ad->at.publicKey, 0);
    *len += sizeof(ad->at) - 1; // ecdsa public key is 1 byte shorter than max value
  }
  // TODO: extensions
  return 0;
}

static uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *params, size_t len) {
  // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
  CborParser parser;
  CTAP_makeCredential mc;
  int ret = parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);

  uint8_t data_buf[sizeof(CTAP_authData)], pri_key[ECC_KEY_SIZE];
  if (mc.excludeListSize > 0) {
    for (size_t i = 0; i < mc.excludeListSize; ++i) {
      parse_credential_descriptor(&mc.excludeList, data_buf); // save credential id in data_buf
      CredentialId *kh = (CredentialId *)data_buf;
      // compare rpId first
      if (memcmp(kh->rpIdHash, mc.rpIdHash, sizeof(kh->rpIdHash)) != 0) continue;
      // then verify key handle and get private key in rpIdHash
      ret = verify_key_handle(kh, pri_key);
      if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (ret == 0) {
        DBG_MSG("Exclude ID found\n");
        wait_for_user_presence();
        return CTAP2_ERR_CREDENTIAL_EXCLUDED;
      }
      ret = cbor_value_advance(&mc.excludeList);
      CHECK_CBOR_RET(ret);
    }
  }

  if (has_pin() && (mc.parsedParams & PARAM_pinAuth) == 0) return CTAP2_ERR_PIN_REQUIRED;
  if (mc.parsedParams & PARAM_pinAuth) {
    if (mc.pinAuthLength == 0) {
      wait_for_user_presence();
      if (has_pin())
        return CTAP2_ERR_PIN_INVALID;
      else
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if ((mc.parsedParams & PARAM_pinProtocol) == 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    hmac_sha256(pin_token, PIN_TOKEN_SIZE, mc.clientDataHash, sizeof(mc.clientDataHash), params);
    if (memcmp(params, mc.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  wait_for_user_presence();

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
  ret = ctap_make_auth_data(mc.rpIdHash, data_buf, 1, has_pin() > 0, 1, &len);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, RESP_authData);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // process rk
  //  if (mc.rk) {
  //    ret = write_rk((CTAP_residentKey *)(data_buf + 55), -1);
  //    if (ret == -1) return CTAP2_ERR_KEY_STORE_FULL;
  //    if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  //  }

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

  if (ga.parsedParams & PARAM_pinAuth) {
    if (ga.pinAuthLength == 0) {
      wait_for_user_presence();
      if (has_pin())
        return CTAP2_ERR_PIN_INVALID;
      else
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if ((ga.parsedParams & PARAM_pinProtocol) == 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    hmac_sha256(pin_token, PIN_TOKEN_SIZE, ga.clientDataHash, sizeof(ga.clientDataHash), params);
    if (memcmp(params, ga.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  // build response
  CborEncoder map;
  ret = cbor_encoder_create_map(encoder, &map, 3);
  CHECK_CBOR_RET(ret);

  uint8_t data_buf[sizeof(CTAP_authData)], pri_key[ECC_KEY_SIZE];
  CredentialId kh;
  size_t i;
  for (i = 0; i < ga.allowListSize; ++i) {
    parse_credential_descriptor(&ga.allowList, (uint8_t *)&kh);
    // compare rpId first
    if (memcmp(kh.rpIdHash, ga.rpIdHash, sizeof(kh.rpIdHash)) != 0) {
      ret = cbor_value_advance(&ga.allowList);
      CHECK_CBOR_RET(ret);
      continue;
    }

    // build credential id
    ret = cbor_encode_int(&map, RESP_credential);
    CHECK_CBOR_RET(ret);
    CborEncoder credential_map;
    ret = cbor_encoder_create_map(&map, &credential_map, 2);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&credential_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&credential_map, (const uint8_t *)&kh, sizeof(kh));
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&credential_map, "type");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&credential_map, "public-key");
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(&map, &credential_map);
    CHECK_CBOR_RET(ret);

    // then verify key handle and get private key in rpIdHash
    int err = verify_key_handle(&kh, pri_key);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) break; // only handle one allow entry for now
  }
  if (i == ga.allowListSize) return CTAP2_ERR_NO_CREDENTIALS;

  if (ga.uv) return CTAP2_ERR_UNSUPPORTED_OPTION;
  if (ga.up) wait_for_user_presence();

  // auth data
  ret = ctap_make_auth_data(ga.rpIdHash, data_buf, 0, has_pin() > 0 && (ga.parsedParams & PARAM_pinAuth), ga.up, &len);
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
  len = sign_with_private_key(pri_key, data_buf, data_buf);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  ret = cbor_encoder_close_container(encoder, &map);
  CHECK_CBOR_RET(ret);

  memzero(pri_key, sizeof(pri_key));

  return 0;
}

static uint8_t ctap_get_info(CborEncoder *encoder) {
  // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
  // Currently, we respond versions, aaguid, pin protocol.
  CborEncoder map;
  int ret = cbor_encoder_create_map(encoder, &map, 4);
  CHECK_CBOR_RET(ret);

  // versions
  ret = cbor_encode_int(&map, RESP_versions);
  CHECK_CBOR_RET(ret);
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

  // aaguid
  ret = cbor_encode_int(&map, RESP_aaguid);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, aaguid, sizeof(aaguid));
  CHECK_CBOR_RET(ret);

  // options
  ret = cbor_encode_int(&map, RESP_options);
  CHECK_CBOR_RET(ret);
  CborEncoder option_map;
  ret = cbor_encoder_create_map(&map, &option_map, 1);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&option_map, "clientPin");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_boolean(&option_map, has_pin() > 0);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&map, &option_map);
  CHECK_CBOR_RET(ret);

  // pin protocol
  ret = cbor_encode_int(&map, RESP_pinProtocols);
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
  uint8_t ret = parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);

  CborEncoder map, key_map;
  uint8_t iv[16], hmac_buf[80], i;
  memzero(iv, sizeof(iv));
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  uint8_t *ptr;
  int err, retries;
  switch (cp.subCommand) {
  case CP_cmdGetRetries:
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, RESP_retries);
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
    ret = ecc_generate(ECC_SECP256R1, key_agreement_pri_key, ptr);
    if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
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
    ret = get_shared_secret(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    hmac_sha256(cp.keyAgreement, SHARED_SECRET_SIZE, cp.newPinEnc, sizeof(cp.newPinEnc), hmac_buf);
    if (memcmp(hmac_buf, cp.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    cfg.key = cp.keyAgreement;
    cfg.in_size = MAX_PIN_SIZE + 1;
    cfg.in = cp.newPinEnc;
    cfg.out = cp.newPinEnc;
    block_cipher_dec(&cfg);
    i = 63;
    while (i > 0 && cp.newPinEnc[i] == 0)
      --i;
    if (i <= 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = set_pin(cp.newPinEnc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CP_cmdChangePin:
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    retries = err - 1;
    ret = get_shared_secret(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    memcpy(hmac_buf, cp.newPinEnc, sizeof(cp.newPinEnc));
    memcpy(hmac_buf + sizeof(cp.newPinEnc), cp.pinHashEnc, sizeof(cp.pinHashEnc));
    hmac_sha256(cp.keyAgreement, SHARED_SECRET_SIZE, hmac_buf, sizeof(cp.newPinEnc) + sizeof(cp.pinHashEnc), hmac_buf);
    if (memcmp(hmac_buf, cp.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cfg.key = cp.keyAgreement;
    cfg.in_size = PIN_HASH_SIZE;
    cfg.in = cp.pinHashEnc;
    cfg.out = cp.pinHashEnc;
    block_cipher_dec(&cfg);
    err = verify_pin_hash(cp.pinHashEnc);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err > 0) {
      if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
      if (consecutive_pin_counter == 1) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      --consecutive_pin_counter;
      return CTAP2_ERR_PIN_INVALID;
    }
    consecutive_pin_counter = 3;
    cfg.key = cp.keyAgreement;
    cfg.in_size = MAX_PIN_SIZE + 1;
    cfg.in = cp.newPinEnc;
    cfg.out = cp.newPinEnc;
    block_cipher_dec(&cfg);
    i = 63;
    while (i > 0 && cp.newPinEnc[i] == 0)
      --i;
    if (i <= 3 || i >= 63) return CTAP2_ERR_PIN_POLICY_VIOLATION;
    err = set_pin(cp.newPinEnc, i + 1);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    break;

  case CP_cmdGetPinToken:
    err = has_pin();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_NOT_SET;
    err = get_pin_retries();
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    retries = err - 1;
    ret = get_shared_secret(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cfg.key = cp.keyAgreement;
    cfg.in_size = PIN_HASH_SIZE;
    cfg.in = cp.pinHashEnc;
    cfg.out = cp.pinHashEnc;
    block_cipher_dec(&cfg);
    err = verify_pin_hash(cp.pinHashEnc);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    if (err > 0) {
      if (retries == 0) return CTAP2_ERR_PIN_BLOCKED;
      if (consecutive_pin_counter == 1) return CTAP2_ERR_PIN_AUTH_BLOCKED;
      --consecutive_pin_counter;
      return CTAP2_ERR_PIN_INVALID;
    }
    consecutive_pin_counter = 3;
    err = set_pin_retries(8);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    random_buffer(pin_token, sizeof(pin_token));
    cfg.in_size = PIN_TOKEN_SIZE;
    cfg.in = pin_token;
    cfg.out = hmac_buf;
    block_cipher_enc(&cfg);
    ret = cbor_encoder_create_map(encoder, &map, 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_int(&map, RESP_pinToken);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&map, hmac_buf, PIN_TOKEN_SIZE);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_close_container(encoder, &map);
    CHECK_CBOR_RET(ret);
    break;
  }

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
  case CTAP_RESET:
    *resp = ctap_install(1);
    *resp_len = 1;
    break;
  }
  return 0;
}

int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (CLA != 0x00) EXCEPT(SW_CLA_NOT_SUPPORTED);

  int ret = 0;
  size_t len;
  switch (INS) {
  case U2F_REGISTER:
    //    ret = u2f_register(capdu, rapdu);
    break;
  case U2F_AUTHENTICATE:
    //    ret = u2f_authenticate(capdu, rapdu);
    break;
  case U2F_VERSION:
    //    ret = u2f_version(capdu, rapdu);
    break;
  case U2F_SELECT:
    //    ret = u2f_select(capdu, rapdu);
    break;
  case CTAP_INS_MSG:
    ctap_process(DATA, LC, RDATA, &len);
    LL = len;
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  else
    return 0;
}
