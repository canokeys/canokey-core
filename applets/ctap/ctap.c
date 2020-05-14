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
#include <ecc.h>
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

#ifdef TEST
#define WAIT()                                                                                                         \
  do {                                                                                                                 \
  } while (0)
#else
#define WAIT()                                                                                                         \
  do {                                                                                                                 \
    if (is_nfc()) break;                                                                                               \
    start_blinking(0);                                                                                                 \
    switch (wait_for_user_presence()) {                                                                                \
    case USER_PRESENCE_CANCEL:                                                                                         \
      stop_blinking();                                                                                                 \
      return CTAP2_ERR_KEEPALIVE_CANCEL;                                                                               \
    case USER_PRESENCE_TIMEOUT:                                                                                        \
      stop_blinking();                                                                                                 \
      return CTAP2_ERR_USER_ACTION_TIMEOUT;                                                                            \
    }                                                                                                                  \
    stop_blinking();                                                                                                   \
  } while (0)
#endif

static const uint8_t aaguid[] = {0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49,
                                 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4};
// pin related
static uint8_t key_agreement_pri_key[ECC_KEY_SIZE];
static uint8_t pin_token[PIN_TOKEN_SIZE];
static uint8_t consecutive_pin_counter;
// assertion related
static uint8_t credential_list[MAX_RK_NUM], credential_numbers, credential_idx, last_cmd;

uint8_t ctap_install(uint8_t reset) {
  consecutive_pin_counter = 3;
  credential_numbers = 0;
  credential_idx = 0;
  last_cmd = 0xff;
  if (!reset && get_file_size(CTAP_CERT_FILE) >= 0) return 0;
  uint8_t kh_key[KH_KEY_SIZE] = {0};
  if (write_file(CTAP_CERT_FILE, NULL, 0, 0, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, SIGN_CTR_ATTR, kh_key, 4) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_attr(CTAP_CERT_FILE, PIN_ATTR, NULL, 0) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  if (write_file(RK_FILE, NULL, 0, 0, 1) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, KH_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  random_buffer(kh_key, sizeof(kh_key));
  if (write_attr(CTAP_CERT_FILE, HE_KEY_ATTR, kh_key, sizeof(kh_key)) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  memzero(kh_key, sizeof(kh_key));
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

uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t flags, uint8_t extensionSize,
                            const uint8_t *extension, size_t *len) {
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
    if (generate_key_handle(&ad->at.credentialId, ad->at.publicKey) < 0) return CTAP2_ERR_UNHANDLED_REQUEST;

    build_cose_key(ad->at.publicKey, 0);
    outLen += sizeof(ad->at) - 1; // ecdsa public key is 1 byte shorter than max value
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
  // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
  CborParser parser;
  CTAP_makeCredential mc;
  // CBOR of {"hmac-secret": true}
  const uint8_t hmacExt[] = {0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0xF5};
  int ret = parse_make_credential(&parser, &mc, params, len);
  CHECK_PARSER_RET(ret);

  uint8_t data_buf[sizeof(CTAP_authData)];
  if (mc.excludeListSize > 0) {
    for (size_t i = 0; i < mc.excludeListSize; ++i) {
      uint8_t pri_key[ECC_KEY_SIZE];
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
        WAIT();
        return CTAP2_ERR_CREDENTIAL_EXCLUDED;
      }
      ret = cbor_value_advance(&mc.excludeList);
      CHECK_CBOR_RET(ret);
    }
  }

  if (has_pin() && (mc.parsedParams & PARAM_pinAuth) == 0) return CTAP2_ERR_PIN_REQUIRED;
  if (mc.parsedParams & PARAM_pinAuth) {
    if (mc.pinAuthLength == 0) {
      WAIT();
      if (has_pin())
        return CTAP2_ERR_PIN_INVALID;
      else
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if ((mc.parsedParams & PARAM_pinProtocol) == 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    hmac_sha256(pin_token, PIN_TOKEN_SIZE, mc.clientDataHash, sizeof(mc.clientDataHash), params);
    if (memcmp(params, mc.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
  }

  WAIT();

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
  len = sizeof(data_buf);
  uint8_t flags = FLAGS_AT | (mc.extension_hmac_secret ? FLAGS_ED : 0) | (has_pin() > 0 ? FLAGS_UV : 0) | FLAGS_UP;
  ret = ctap_make_auth_data(mc.rpIdHash, data_buf, flags, sizeof(hmacExt), hmacExt, &len);
  if (ret != 0) return ret;
  ret = cbor_encode_int(&map, RESP_authData);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_byte_string(&map, data_buf, len);
  CHECK_CBOR_RET(ret);

  // process rk
  if (mc.rk) {
    CTAP_residentKey rk;
    int size = get_file_size(RK_FILE);
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    size_t nRk = size / sizeof(CTAP_residentKey), i;
    for (i = 0; i != nRk; ++i) {
      size = read_file(RK_FILE, &rk, i * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey));
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (memcmp(mc.rpIdHash, rk.credential_id.rpIdHash, SHA256_DIGEST_LENGTH) == 0 &&
          mc.user.id_size == rk.user.id_size && memcmp(mc.user.id, rk.user.id, mc.user.id_size) == 0)
        break;
    }
    if (i >= MAX_RK_NUM) return CTAP2_ERR_KEY_STORE_FULL;
    memcpy(&rk.credential_id, data_buf + 55, sizeof(rk.credential_id));
    memcpy(&rk.user, &mc.user, sizeof(UserEntity));
    ret = write_file(RK_FILE, &rk, i * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey), 0);
    if (ret < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

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

static uint8_t ctap_get_assertion(CborEncoder *encoder, uint8_t *params, size_t len) {
  static CTAP_getAssertion ga;
  CborParser parser;
  int ret;
  uint8_t pinAuth[SHA256_DIGEST_LENGTH];
  if (credential_idx == 0) {
    ret = parse_get_assertion(&parser, &ga, params, len);
    CHECK_PARSER_RET(ret);
  }

  if (ga.parsedParams & PARAM_pinAuth) {
    if (ga.pinAuthLength == 0) {
      WAIT();
      if (has_pin())
        return CTAP2_ERR_PIN_INVALID;
      else
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if ((ga.parsedParams & PARAM_pinProtocol) == 0) return CTAP2_ERR_PIN_AUTH_INVALID;
    hmac_sha256(pin_token, PIN_TOKEN_SIZE, ga.clientDataHash, sizeof(ga.clientDataHash), pinAuth);
#ifndef FUZZ
    if (memcmp(pinAuth, ga.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
#endif
  }

  uint8_t data_buf[sizeof(CTAP_authData)], pri_key[ECC_KEY_SIZE];
  CTAP_residentKey rk;
  if (ga.allowListSize > 0) {
    size_t i;
    for (i = 0; i < ga.allowListSize; ++i) {
      parse_credential_descriptor(&ga.allowList, (uint8_t *)&rk.credential_id);
      // compare rpId first
      if (memcmp(rk.credential_id.rpIdHash, ga.rpIdHash, sizeof(rk.credential_id.rpIdHash)) != 0) goto next;
      // then verify key handle and get private key
      int err = verify_key_handle(&rk.credential_id, pri_key);
      if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      if (err == 0) break; // only process one support credential
    next:
      ret = cbor_value_advance(&ga.allowList);
      CHECK_CBOR_RET(ret);
    }
    if (i == ga.allowListSize) return CTAP2_ERR_NO_CREDENTIALS;
  } else {
    int size;
    if (credential_idx == 0) {
      size = get_file_size(RK_FILE);
      if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
      size_t nRk = size / sizeof(CTAP_residentKey);
      credential_numbers = 0;
      for (size_t i = 0; i != nRk; ++i) {
        size = read_file(RK_FILE, &rk, i * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey));
        if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
        if (memcmp(ga.rpIdHash, rk.credential_id.rpIdHash, SHA256_DIGEST_LENGTH) == 0)
          credential_list[credential_numbers++] = i;
      }
      if (credential_numbers == 0) return CTAP2_ERR_NO_CREDENTIALS;
    }
    // fetch rk and get private key
    size =
        read_file(RK_FILE, &rk, credential_list[credential_idx] * sizeof(CTAP_residentKey), sizeof(CTAP_residentKey));
    if (size < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    int err = verify_key_handle(&rk.credential_id, pri_key);
    if (err != 0) return CTAP2_ERR_UNHANDLED_REQUEST;
  }

  uint8_t extensionBuffer[79], extensionSize = 0;
  uint8_t iv[16] = {0};
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  if (ga.parsedParams & PARAM_hmacSecret) {
    ret = get_shared_secret(ga.hmacSecretKeyAgreement);
    CHECK_PARSER_RET(ret);
    uint8_t hmac_buf[SHA256_DIGEST_LENGTH];
    hmac_sha256(ga.hmacSecretKeyAgreement, SHARED_SECRET_SIZE, ga.hmacSecretSaltEnc, ga.hmacSecretSaltLen, hmac_buf);
    if (memcmp(hmac_buf, ga.hmacSecretSaltAuth, HMAC_SECRET_SALT_AUTH_SIZE) != 0) return CTAP2_ERR_EXTENSION_FIRST;
    cfg.key = ga.hmacSecretKeyAgreement;
    cfg.in_size = ga.hmacSecretSaltLen;
    cfg.in = ga.hmacSecretSaltEnc;
    cfg.out = ga.hmacSecretSaltEnc;
    block_cipher_dec(&cfg);
  }

  if (ga.uv) return CTAP2_ERR_UNSUPPORTED_OPTION;
  if (ga.up) WAIT();

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

  // build response
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
  uint8_t flags = ((ga.parsedParams & PARAM_hmacSecret) ? FLAGS_ED : 0) |
                  (has_pin() && (ga.parsedParams & PARAM_pinAuth) > 0 ? FLAGS_UV : 0) | (ga.up ? FLAGS_UP : 0);
  ret = ctap_make_auth_data(ga.rpIdHash, data_buf, flags, extensionSize, extensionBuffer, &len);
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

  // user
  if (ga.allowListSize == 0) {
    ret = cbor_encode_int(&map, RESP_publicKeyCredentialUserEntity);
    CHECK_CBOR_RET(ret);
    ret = cbor_encoder_create_map(&map, &sub_map, credential_numbers > 1 ? 4 : 1);
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_text_stringz(&sub_map, "id");
    CHECK_CBOR_RET(ret);
    ret = cbor_encode_byte_string(&sub_map, rk.user.id, rk.user.id_size);
    CHECK_CBOR_RET(ret);
    if (credential_numbers > 1) {
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
  if (last_cmd != CTAP_GET_ASSERTION && last_cmd != CTAP_GET_NEXT_ASSERTION) return CTAP2_ERR_NOT_ALLOWED;
  if (credential_idx >= credential_numbers) return CTAP2_ERR_NOT_ALLOWED;
  return ctap_get_assertion(encoder, NULL, 0);
}

static uint8_t ctap_get_info(CborEncoder *encoder) {
  // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo
  // Currently, we respond versions, aaguid, pin protocol.
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
    ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
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
  ret = cbor_encoder_create_map(&map, &option_map, 1);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_text_stringz(&option_map, "clientPin");
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_boolean(&option_map, has_pin() > 0);
  CHECK_CBOR_RET(ret);
  ret = cbor_encoder_close_container(&map, &option_map);
  CHECK_CBOR_RET(ret);

  // max message length
  ret = cbor_encode_int(&map, RESP_maxMsgSize);
  CHECK_CBOR_RET(ret);
  ret = cbor_encode_int(&map, MAX_CTAP_BUFSIZE);
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
  int ret = parse_client_pin(&parser, &cp, params, len);
  CHECK_PARSER_RET(ret);

  CborEncoder map, key_map;
  uint8_t iv[16], hmac_buf[80], i;
  memzero(iv, sizeof(iv));
  block_cipher_config cfg = {.block_size = 16, .mode = CBC, .iv = iv, .encrypt = aes256_enc, .decrypt = aes256_dec};
  uint8_t *ptr;
  int err, retries = 0;
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
#ifndef FUZZ
    if (memcmp(hmac_buf, cp.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
#endif
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
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    retries = err - 1;
#endif
    ret = get_shared_secret(cp.keyAgreement);
    CHECK_PARSER_RET(ret);
    memcpy(hmac_buf, cp.newPinEnc, sizeof(cp.newPinEnc));
    memcpy(hmac_buf + sizeof(cp.newPinEnc), cp.pinHashEnc, sizeof(cp.pinHashEnc));
    hmac_sha256(cp.keyAgreement, SHARED_SECRET_SIZE, hmac_buf, sizeof(cp.newPinEnc) + sizeof(cp.pinHashEnc), hmac_buf);
#ifndef FUZZ
    if (memcmp(hmac_buf, cp.pinAuth, PIN_AUTH_SIZE) != 0) return CTAP2_ERR_PIN_AUTH_INVALID;
#endif
    err = set_pin_retries(retries);
    if (err < 0) return CTAP2_ERR_UNHANDLED_REQUEST;
    cfg.key = cp.keyAgreement;
    cfg.in_size = PIN_HASH_SIZE;
    cfg.in = cp.pinHashEnc;
    cfg.out = cp.pinHashEnc;
    block_cipher_dec(&cfg);
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
#ifndef FUZZ
    if (err == 0) return CTAP2_ERR_PIN_BLOCKED;
    retries = err - 1;
#endif
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
  default:
    *resp = CTAP2_ERR_UNHANDLED_REQUEST;
    *resp_len = 1;
    break;
  }
  last_cmd = cmd;
  return 0;
}

int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (CLA != 0x00 && (CLA != 0x80 || INS != CTAP_INS_MSG)) EXCEPT(SW_CLA_NOT_SUPPORTED);

  int ret = 0;
  size_t len = 0;
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
    // ignore the ret of ctap_process_cbor
    // because it has its own error report
    ctap_process_cbor(DATA, LC, RDATA, &len);
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
