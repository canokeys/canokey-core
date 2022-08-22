// SPDX-License-Identifier: Apache-2.0
#include "ctap-parser.h"
#include "cose-key.h"
#include "ctap-errors.h"
#include <cbor.h>
#include <ctap.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if (ret > 0) DBG_MSG("CHECK_PARSER_RET %#x\n", ret);                                                               \
    if (ret > 0) return ret;                                                                                           \
  } while (0)
#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if (ret != CborNoError) DBG_MSG("CHECK_CBOR_RET %#x\n", ret);                                                      \
    if (ret != CborNoError) return CTAP2_ERR_INVALID_CBOR;                                                             \
  } while (0)

uint8_t parse_rp(uint8_t *rpIdHash, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  char key[4], domain[DOMAIN_NAME_MAX_SIZE];
  size_t map_length, len;

  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    len = sizeof(key);
    ret = cbor_value_copy_text_string(&map, key, &len, NULL);
    if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    if (strcmp(key, "id") == 0) {
      len = DOMAIN_NAME_MAX_SIZE;
      ret = cbor_value_copy_text_string(&map, domain, &len, NULL);
      CHECK_CBOR_RET(ret);
      domain[DOMAIN_NAME_MAX_SIZE - 1] = 0;
      DBG_MSG("rpId: %s\n", domain);
      sha256_raw((uint8_t *)domain, len, rpIdHash);
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_user(UserEntity *user, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  char key[12];
  size_t map_length, len;

  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    len = sizeof(key);
    ret = cbor_value_copy_text_string(&map, key, &len, NULL);
    if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    if (strcmp(key, "id") == 0) {
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = USER_ID_MAX_SIZE;
      ret = cbor_value_copy_byte_string(&map, user->id, &len, NULL);
      if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;
      CHECK_CBOR_RET(ret);
      user->id_size = len;
      DBG_MSG("id: ");
      PRINT_HEX(user->id, len);
    } else if (strcmp(key, "name") == 0) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = USER_NAME_LIMIT;
      ret = cbor_value_copy_text_string(&map, (char *)user->name, &len, NULL);
      CHECK_CBOR_RET(ret);
      user->name[USER_NAME_LIMIT - 1] = 0;
      DBG_MSG("name: %s\n", user->name);
    } else if (strcmp(key, "displayName") == 0) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = DISPLAY_NAME_LIMIT;
      ret = cbor_value_copy_text_string(&map, (char *)user->displayName, &len, NULL);
      CHECK_CBOR_RET(ret);
      user->displayName[DISPLAY_NAME_LIMIT - 1] = 0;
      DBG_MSG("displayName: %s\n", user->displayName);
    } else if (strcmp(key, "icon") == 0) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = ICON_LIMIT;
      ret = cbor_value_copy_text_string(&map, (char *)user->icon, &len, NULL);
      CHECK_CBOR_RET(ret);
      user->icon[ICON_LIMIT - 1] = 0;
      DBG_MSG("icon: %s\n", user->icon);
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

static uint8_t parse_pub_key_cred_param(CborValue *val, int32_t *alg_type) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue cred, alg;
  int ret = cbor_value_map_find_value(val, "type", &cred);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_map_find_value(val, "alg", &alg);
  CHECK_CBOR_RET(ret);

  if (cbor_value_get_type(&cred) != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;
  if (cbor_value_get_type(&alg) != CborIntegerType) return CTAP2_ERR_MISSING_PARAMETER;

  bool is_public_key;
  ret = cbor_value_text_string_equals(&cred, "public-key", &is_public_key);
  CHECK_CBOR_RET(ret);

  // required by FIDO Conformance Tool
  if (!is_public_key) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;

  ret = cbor_value_get_int_checked(&alg, (int *)alg_type);
  CHECK_CBOR_RET(ret);
  return 0;
}

uint8_t parse_verify_pub_key_cred_params(CborValue *val, int32_t *alg_type) {
  if (cbor_value_get_type(val) != CborArrayType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue arr;
  size_t arr_length;
  int ret = cbor_value_enter_container(val, &arr);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_array_length(val, &arr_length);
  CHECK_CBOR_RET(ret);

  int32_t cur_alg_type;
  size_t chosen = arr_length;
  // all elements in array must be examined
  for (size_t i = 0; i < arr_length; ++i) {
    ret = parse_pub_key_cred_param(&arr, &cur_alg_type);
    CHECK_PARSER_RET(ret);
    if (ret == 0 && (cur_alg_type == COSE_ALG_ES256 || cur_alg_type == COSE_ALG_EDDSA)) {
      // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
      //
      // > This sequence is ordered from most preferred (by the RP) to least preferred.

      if (chosen == arr_length) {
        *alg_type = cur_alg_type;
        chosen = i;
      }
    }
    ret = cbor_value_advance(&arr);
    CHECK_CBOR_RET(ret);
  }
  if (chosen == arr_length) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;

  return 0;
}

uint8_t parse_credential_descriptor(CborValue *arr, uint8_t *id) {
  if (cbor_value_get_type(arr) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue val;
  int ret = cbor_value_map_find_value(arr, "id", &val);
  CHECK_CBOR_RET(ret);
  if (cbor_value_get_type(&val) != CborByteStringType) return CTAP2_ERR_MISSING_PARAMETER;
  size_t len = sizeof(CredentialId);
  if (id) {
    ret = cbor_value_copy_byte_string(&val, id, &len, NULL);
    CHECK_CBOR_RET(ret);
  }

  ret = cbor_value_map_find_value(arr, "type", &val);
  CHECK_CBOR_RET(ret);
  if (cbor_value_get_type(&val) != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

// In this function, we check if the exclude list contains only
// public-key-type credential IDs.
uint8_t parse_public_key_credential_list(CborValue *lst) {
  CborValue arr;
  size_t size;
  if (cbor_value_get_type(lst) != CborArrayType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_array_length(lst, &size);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(lst, &arr);
  CHECK_CBOR_RET(ret);
  for (size_t i = 0; i < size; ++i) {
    ret = parse_credential_descriptor(&arr, NULL);
    CHECK_PARSER_RET(ret);
    ret = cbor_value_advance(&arr);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_options(CTAP_options *options, CborValue *val) {
  size_t map_length;
  CborValue map;

  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    size_t sz;
    char key[2];
    bool b;
    ret = cbor_value_calculate_string_length(&map, &sz);
    CHECK_CBOR_RET(ret);
    if (sz == sizeof(key)) {
      ret = cbor_value_copy_text_string(&map, key, &sz, NULL);
      CHECK_CBOR_RET(ret);
    } else {
      key[0] = key[1] = 0;
    }
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    if (memcmp(key, "rk", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("rk: %d\n", b);
      options->rk = b;
    } else if (memcmp(key, "uv", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("uv: %d\n", b);
      options->uv = b;
    } else if (memcmp(key, "up", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("up: %d\n", b);
      options->up = b;
    } else {
      DBG_MSG("ignoring option specified %c%c\n", key[0], key[1]);
    }
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_cose_key(CborValue *val, uint8_t *public_key) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  size_t map_length, len;
  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  int key;
  uint8_t parsed_keys = 0;
  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
    case COSE_KEY_LABEL_ALG:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      if (key != COSE_ALG_ES256 && key != COSE_ALG_ECDH_ES_HKDF_256) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    case COSE_KEY_LABEL_KTY:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      if (key != COSE_KEY_KTY_EC2) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    case COSE_KEY_LABEL_CRV:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      if (key != COSE_KEY_CRV_P256) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    case COSE_KEY_LABEL_X:
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = PRI_KEY_SIZE;
      ret = cbor_value_copy_byte_string(&map, public_key, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != PRI_KEY_SIZE) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    case COSE_KEY_LABEL_Y:
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = PRI_KEY_SIZE;
      ret = cbor_value_copy_byte_string(&map, public_key + PRI_KEY_SIZE, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != PRI_KEY_SIZE) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    default:
      DBG_MSG("Unknown cose key label: %d\n", key);
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  DBG_MSG("parsed_keys=%x\n", parsed_keys);
  if (parsed_keys < 4) return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t parse_mc_extensions(uint8_t *hmac_secret, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  size_t map_length;
  CborValue map;
  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    bool is_hmac_secret;
    ret = cbor_value_text_string_equals(&map, "hmac-secret", &is_hmac_secret);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    if (is_hmac_secret) {
      bool b;
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("hmac-secret: %d\n", b);
      if (hmac_secret) *hmac_secret = b;
    } else {
      DBG_MSG("ignoring option specified\n");
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_ga_extensions(CTAP_getAssertion *ga, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  size_t map_length;
  CborValue map;
  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    bool is_hmac_secret;
    ret = cbor_value_text_string_equals(&map, "hmac-secret", &is_hmac_secret);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    if (is_hmac_secret) {
      DBG_MSG("hmac-secret found\n");
      ga->parsedParams |= PARAM_hmacSecret;
      if (cbor_value_get_type(&map) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t hmac_map_length;
      CborValue hmac_map;
      ret = cbor_value_enter_container(&map, &hmac_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_get_map_length(&map, &hmac_map_length);
      CHECK_CBOR_RET(ret);
      enum {
        GA_HS_MAP_ENTRY_NONE = 0,
        GA_HS_MAP_ENTRY_keyAgreement = 0b001,
        GA_HS_MAP_ENTRY_saltEnc = 0b010,
        GA_HS_MAP_ENTRY_saltAuth = 0b100,
        GA_HS_MAP_ENTRY_ALL_REQUIRED = 0b111,
      } map_has_entry = GA_HS_MAP_ENTRY_NONE;
      if (hmac_map_length < 3) return CTAP2_ERR_MISSING_PARAMETER;
      for (size_t j = 0; j < hmac_map_length; ++j) {
        if (cbor_value_get_type(&hmac_map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        size_t len;
        int hmac_key;
        ret = cbor_value_get_int_checked(&hmac_map, &hmac_key);
        CHECK_CBOR_RET(ret);
        ret = cbor_value_advance(&hmac_map);
        CHECK_CBOR_RET(ret);
        switch (hmac_key) {
        case HMAC_SECRET_keyAgreement:
          ret = parse_cose_key(&hmac_map, ga->hmacSecretKeyAgreement);
          CHECK_CBOR_RET(ret);
          map_has_entry |= GA_HS_MAP_ENTRY_keyAgreement;
          DBG_MSG("keyAgreement: ");
          PRINT_HEX(ga->hmacSecretKeyAgreement, 64);
          break;
        case HMAC_SECRET_saltEnc:
          if (cbor_value_get_type(&hmac_map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
          len = sizeof(ga->hmacSecretSaltEnc);
          ret = cbor_value_copy_byte_string(&hmac_map, ga->hmacSecretSaltEnc, &len, NULL);
          if (ret == CborErrorOutOfMemory) return CTAP1_ERR_INVALID_LENGTH;
          CHECK_CBOR_RET(ret);
          if (len != HMAC_SECRET_SALT_SIZE && len != HMAC_SECRET_SALT_SIZE / 2) return CTAP1_ERR_INVALID_LENGTH;
          ga->hmacSecretSaltLen = len;
          map_has_entry |= GA_HS_MAP_ENTRY_saltEnc;
          DBG_MSG("saltEnc: ");
          PRINT_HEX(ga->hmacSecretSaltEnc, ga->hmacSecretSaltLen);
          break;
        case HMAC_SECRET_saltAuth:
          if (cbor_value_get_type(&hmac_map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
          len = sizeof(ga->hmacSecretSaltAuth);
          ret = cbor_value_copy_byte_string(&hmac_map, ga->hmacSecretSaltAuth, &len, NULL);
          CHECK_CBOR_RET(ret);
          if (len != HMAC_SECRET_SALT_AUTH_SIZE) return CTAP1_ERR_INVALID_LENGTH;
          map_has_entry |= GA_HS_MAP_ENTRY_saltAuth;
          DBG_MSG("saltAuth: ");
          PRINT_HEX(ga->hmacSecretSaltAuth, 16);
          break;
        default:
          // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding
          DBG_MSG("Ignoring unsupported entry %0x\n", hmac_key);
          break;
        }
        ret = cbor_value_advance(&hmac_map);
        CHECK_CBOR_RET(ret);
      }
      if ((map_has_entry & GA_HS_MAP_ENTRY_ALL_REQUIRED) != GA_HS_MAP_ENTRY_ALL_REQUIRED)
        return CTAP2_ERR_MISSING_PARAMETER;
    } else {
      DBG_MSG("ignoring option specified\n");
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_cm_params(CTAP_credentialManagement *cm, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  size_t map_length, len;
  CborValue map;
  int key;
  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
      case CM_paramRpIdHash:
        DBG_MSG("rpIDHash found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if (len != SHA256_DIGEST_LENGTH) return CTAP2_ERR_INVALID_CBOR;
        ret = cbor_value_copy_byte_string(&map, cm->rpIdHash, &len, NULL);
        CHECK_CBOR_RET(ret);
        cm->parsedParams |= PARAM_rpId;
        break;

      case CM_paramCredentialId:
        DBG_MSG("credentialId found\n");
        ret = parse_credential_descriptor(&map, (uint8_t *) &cm->credentialId);
        CHECK_CBOR_RET(ret);
//        cm->parsedParams |= ;
        break;

      case CM_paramUser:
        DBG_MSG("user found\n");
        ret = parse_user(&cm->user, &map);
        CHECK_CBOR_RET(ret);
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  return 0;
}

uint8_t parse_make_credential(CborParser *parser, CTAP_makeCredential *mc, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, pinProtocol;
  memset(mc, 0, sizeof(CTAP_makeCredential));

  // options are absent by default
  mc->options.rk = OPTION_ABSENT;
  mc->options.uv = OPTION_ABSENT;
  mc->options.up = OPTION_ABSENT;

  int ret = cbor_parser_init(buf, len, CborValidateCanonicalFormat, parser, &it);
  CHECK_CBOR_RET(ret);
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
    case MC_clientDataHash:
      DBG_MSG("clientDataHash found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = CLIENT_DATA_HASH_SIZE;
      ret = cbor_value_copy_byte_string(&map, mc->clientDataHash, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      DBG_MSG("clientDataHash: ");
      PRINT_HEX(mc->clientDataHash, len);
      mc->parsedParams |= PARAM_clientDataHash;
      break;

    case MC_rp:
      DBG_MSG("rpId found\n");
      ret = parse_rp(mc->rpIdHash, &map);
      CHECK_PARSER_RET(ret);
      DBG_MSG("rpIdHash: ");
      PRINT_HEX(mc->rpIdHash, len);
      mc->parsedParams |= PARAM_rpId;
      break;

    case MC_user:
      DBG_MSG("user found\n");
      ret = parse_user(&mc->user, &map);
      CHECK_PARSER_RET(ret);
      mc->parsedParams |= PARAM_user;
      break;

    case MC_pubKeyCredParams:
      DBG_MSG("pubKeyCredParams found\n");
      ret = parse_verify_pub_key_cred_params(&map, &mc->alg_type);
      CHECK_PARSER_RET(ret);
      if (mc->alg_type == COSE_ALG_ES256) DBG_MSG("EcDSA found\n");
      else if (mc->alg_type == COSE_ALG_EDDSA) DBG_MSG("EdDSA found\n");
      else DBG_MSG("Found other algorithm\n");
      mc->parsedParams |= PARAM_pubKeyCredParams;
      break;

    case MC_excludeList:
      DBG_MSG("excludeList found\n");
      ret = parse_public_key_credential_list(&map);
      CHECK_PARSER_RET(ret);
      ret = cbor_value_enter_container(&map, &mc->excludeList);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_get_array_length(&map, &mc->excludeListSize);
      CHECK_CBOR_RET(ret);
      DBG_MSG("excludeList size: %d\n", (int)mc->excludeListSize);
      break;

    case MC_extensions:
      DBG_MSG("extensions found\n");
      ret = parse_mc_extensions(&mc->extension_hmac_secret, &map);
      CHECK_PARSER_RET(ret);
      mc->parsedParams |= PARAM_extensions;
      break;

    case MC_options:
      DBG_MSG("options found\n");
      ret = parse_options(&mc->options, &map);
      CHECK_PARSER_RET(ret);
      mc->parsedParams |= PARAM_options;
      break;

    case MC_pinUvAuthParam:
      DBG_MSG("pinUvAuthParam found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &mc->pinUvAuthParamLength);
      CHECK_CBOR_RET(ret);
      if (mc->pinUvAuthParamLength != 0 && mc->pinUvAuthParamLength > SHA256_DIGEST_LENGTH) return CTAP2_ERR_PIN_AUTH_INVALID;
      ret = cbor_value_copy_byte_string(&map, mc->pinUvAuthParam, &mc->pinUvAuthParamLength, NULL);
      CHECK_CBOR_RET(ret);
      DBG_MSG("pinUvAuthParam: ");
      PRINT_HEX(mc->pinUvAuthParam, mc->pinUvAuthParamLength);
      mc->parsedParams |= PARAM_pinUvAuthParam;
      break;

    case MC_pinProtocol:
      DBG_MSG("pinProtocol found\n");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &pinProtocol);
      CHECK_CBOR_RET(ret);
      DBG_MSG("pinProtocol: %d\n", pinProtocol);
      mc->pinUvAuthProtocol = pinProtocol;
      mc->parsedParams |= PARAM_pinUvAuthProtocol;
      break;

    case MC_enterpriseAttestation:
      DBG_MSG("enterpriseAttestation found\n");
      mc->parsedParams |= PARAM_enterpriseAttestation;
      // TODO: parse enterpriseAttestation
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((mc->parsedParams & MC_requiredMask) != MC_requiredMask) return CTAP2_ERR_MISSING_PARAMETER;
  return 0;
}

uint8_t parse_get_assertion(CborParser *parser, CTAP_getAssertion *ga, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, pinProtocol;
  char domain[DOMAIN_NAME_MAX_SIZE];
  memset(ga, 0, sizeof(CTAP_getAssertion));

  // options are absent by default
  ga->options.rk = OPTION_ABSENT;
  ga->options.uv = OPTION_ABSENT;
  ga->options.up = OPTION_ABSENT;

  int ret = cbor_parser_init(buf, len, CborValidateCanonicalFormat, parser, &it);
  CHECK_CBOR_RET(ret);
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
    case GA_rpId:
      DBG_MSG("rpId found\n");
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = DOMAIN_NAME_MAX_SIZE;
      ret = cbor_value_copy_text_string(&map, domain, &len, NULL);
      CHECK_CBOR_RET(ret);
      domain[DOMAIN_NAME_MAX_SIZE - 1] = 0;
      DBG_MSG("rpId: %s; hash: ", domain);
      sha256_raw((uint8_t *)domain, len, ga->rpIdHash);
      PRINT_HEX(ga->rpIdHash, SHA256_DIGEST_LENGTH);
      ga->parsedParams |= PARAM_rpId;
      break;

    case GA_clientDataHash:
      DBG_MSG("clientDataHash found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = CLIENT_DATA_HASH_SIZE;
      ret = cbor_value_copy_byte_string(&map, ga->clientDataHash, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      DBG_MSG("clientDataHash: ");
      PRINT_HEX(ga->clientDataHash, len);
      ga->parsedParams |= PARAM_clientDataHash;
      break;

    case GA_allowList:
      DBG_MSG("allowList found\n");
      ret = parse_public_key_credential_list(&map);
      CHECK_PARSER_RET(ret);
      ret = cbor_value_enter_container(&map, &ga->allowList);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_get_array_length(&map, &ga->allowListSize);
      CHECK_CBOR_RET(ret);
      DBG_MSG("allowList size: %d\n", (int)ga->allowListSize);
      break;

    case GA_extensions:
      DBG_MSG("extensions found\n");
      ret = parse_ga_extensions(ga, &map);
      CHECK_PARSER_RET(ret);
      break;

    case GA_options:
      DBG_MSG("options found\n");
      ret = parse_options(&ga->options, &map);
      CHECK_PARSER_RET(ret);
      ga->parsedParams |= PARAM_options;
      break;

    case GA_pinUvAuthParam:
      DBG_MSG("pinUvAuthParam found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &ga->pinUvAuthParamLength);
      CHECK_CBOR_RET(ret);
      if (ga->pinUvAuthParamLength != 0 && ga->pinUvAuthParamLength  > SHA256_DIGEST_LENGTH) return CTAP2_ERR_PIN_AUTH_INVALID;
      ret = cbor_value_copy_byte_string(&map, ga->pinUvAuthParam, &ga->pinUvAuthParamLength, NULL);
      CHECK_CBOR_RET(ret);
      DBG_MSG("pinUvAuthParam: ");
      PRINT_HEX(ga->pinUvAuthParam, ga->pinUvAuthParamLength);
      ga->parsedParams |= PARAM_pinUvAuthParam;
      break;

    case GA_pinUvAuthProtocol:
      DBG_MSG("pinProtocol found\n");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &pinProtocol);
      CHECK_CBOR_RET(ret);
      DBG_MSG("pinProtocol: %d\n", pinProtocol);
      ga->pinUvAuthProtocol = pinProtocol;
      ga->parsedParams |= PARAM_pinUvAuthProtocol;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((ga->parsedParams & GA_requiredMask) != GA_requiredMask) return CTAP2_ERR_MISSING_PARAMETER;
  return 0;
}

uint8_t parse_client_pin(CborParser *parser, CTAP_clientPin *cp, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key;
  memset(cp, 0, sizeof(CTAP_clientPin));

  int ret = cbor_parser_init(buf, len, CborValidateCanonicalFormat, parser, &it);
  CHECK_CBOR_RET(ret);
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
    case CP_pinUvAuthProtocol:
      DBG_MSG("pinProtocol found\n");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      DBG_MSG("pinProtocol: %d\n", key);
      if (key != 1 && key != 2) {
        ERR_MSG("Invalid pinProtocol\n");
        return CTAP1_ERR_INVALID_PARAMETER;
      }
      cp->pinUvAuthProtocol = key;
      cp->parsedParams |= PARAM_pinUvAuthProtocol;
      break;

    case CP_subCommand:
      DBG_MSG("subCommand found\n");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      cp->subCommand = key;
      DBG_MSG("subCommand: %d\n", cp->subCommand);
      cp->parsedParams |= PARAM_subCommand;
      break;

    case CP_keyAgreement:
      DBG_MSG("keyAgreement found\n");
      ret = parse_cose_key(&map, cp->keyAgreement);
      CHECK_PARSER_RET(ret);
      DBG_MSG("keyAgreement: ");
      PRINT_HEX(cp->keyAgreement, PUB_KEY_SIZE);
      cp->parsedParams |= PARAM_keyAgreement;
      break;

    case CP_pinUvAuthParam:
      DBG_MSG("pinUvAuthParam found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if (len > SHA256_DIGEST_LENGTH) return CTAP2_ERR_INVALID_CBOR;
      ret = cbor_value_copy_byte_string(&map, cp->pinUvAuthParam, &len, NULL);
      CHECK_CBOR_RET(ret);
      cp->parsedParams |= PARAM_pinUvAuthParam;
      break;

    case CP_newPinEnc:
      DBG_MSG("newPinEnc found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if ((cp->pinUvAuthProtocol == 1 && len != PIN_ENC_SIZE_P1) ||
          (cp->pinUvAuthProtocol == 2 && len != PIN_ENC_SIZE_P2)) {
        ERR_MSG("Invalid newPinEnc length\n");
        return CTAP2_ERR_INVALID_CBOR;
      }
      ret = cbor_value_copy_byte_string(&map, cp->newPinEnc, &len, NULL);
      CHECK_CBOR_RET(ret);
      DBG_MSG("newPinEnc: ");
      PRINT_HEX(cp->newPinEnc, len);
      cp->parsedParams |= PARAM_newPinEnc;
      break;

    case CP_pinHashEnc:
      DBG_MSG("pinHashEnc found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if ((cp->pinUvAuthProtocol == 1 && len != PIN_HASH_SIZE_P1) ||
          (cp->pinUvAuthProtocol == 2 && len != PIN_HASH_SIZE_P2)) {
        ERR_MSG("Invalid pinHashEnc length\n");
        return CTAP2_ERR_INVALID_CBOR;
      }
      ret = cbor_value_copy_byte_string(&map, cp->pinHashEnc, &len, NULL);
      CHECK_CBOR_RET(ret);
      cp->parsedParams |= PARAM_pinHashEnc;
      break;

    case CP_permissions:
      DBG_MSG("permissions found\n");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      cp->permissions = key;
      DBG_MSG("permissions: %d\n", cp->permissions);
      if (cp->permissions == 0) {
        ERR_MSG("Invalid permissions\n");
        return CTAP1_ERR_INVALID_PARAMETER;
      }
      // TODO: check permissions
      cp->parsedParams |= PARAM_permissions;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((cp->parsedParams & CP_requiredMask) != CP_requiredMask) return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->subCommand == CP_cmdGetKeyAgreement && (cp->parsedParams & PARAM_pinUvAuthProtocol) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->subCommand == CP_cmdSetPin &&
      ((cp->parsedParams & PARAM_pinUvAuthProtocol) == 0 ||
       (cp->parsedParams & PARAM_keyAgreement) == 0 ||
       (cp->parsedParams & PARAM_newPinEnc) == 0 ||
       (cp->parsedParams & PARAM_pinUvAuthParam) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->subCommand == CP_cmdChangePin &&
      ((cp->parsedParams & PARAM_pinUvAuthProtocol) == 0 ||
       (cp->parsedParams & PARAM_keyAgreement) == 0 ||
       (cp->parsedParams & PARAM_pinHashEnc) == 0 ||
       (cp->parsedParams & PARAM_newPinEnc) == 0 ||
       (cp->parsedParams & PARAM_pinUvAuthParam) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->subCommand == CP_cmdGetPinToken &&
      ((cp->parsedParams & PARAM_pinUvAuthProtocol) == 0 ||
       (cp->parsedParams & PARAM_keyAgreement) == 0 ||
       (cp->parsedParams & PARAM_pinHashEnc) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cp->subCommand == CP_cmdGetPinToken &&
      ((cp->parsedParams & PARAM_permissions) != 0 ||
       (cp->parsedParams & PARAM_rpId) != 0))
    return CTAP1_ERR_INVALID_PARAMETER;

  if (cp->subCommand == CP_cmdGetPinUvAuthTokenUsingPinWithPermissions &&
      ((cp->parsedParams & PARAM_pinUvAuthProtocol) == 0 ||
       (cp->parsedParams & PARAM_keyAgreement) == 0 ||
       (cp->parsedParams & PARAM_pinHashEnc) == 0 ||
       (cp->parsedParams & PARAM_permissions) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t parse_credential_management(CborParser *parser, CTAP_credentialManagement *cm, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, tmp;
  memset(cm, 0, sizeof(CTAP_credentialManagement));

  int ret = cbor_parser_init(buf, len, CborValidateCanonicalFormat, parser, &it);
  CHECK_CBOR_RET(ret);
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
      case CM_subCommand:
        DBG_MSG("subCommand found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        cm->subCommand = tmp;
        DBG_MSG("subCommand: %d\n", cm->subCommand);
        cm->parsedParams |= PARAM_subCommand;
        break;

      case CM_subCommandParams:
        DBG_MSG("subCommandParams found\n");
        ret = parse_cm_params(cm, &map);
        CHECK_CBOR_RET(ret);
        break;

      case CM_pinUvAuthProtocol:
        DBG_MSG("pinUvAuthProtocol found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pinUvAuthProtocol: %d\n", tmp);
        if (tmp != 1) return CTAP1_ERR_INVALID_PARAMETER;
        cm->parsedParams |= PARAM_pinUvAuthProtocol;
        break;

      case CM_pinUvAuthParam:
        DBG_MSG("pinUvAuthParam found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if (len > SHA256_DIGEST_LENGTH) return CTAP2_ERR_INVALID_CBOR;
        ret = cbor_value_copy_byte_string(&map, cm->pinUvAuthParam, &len, NULL);
        CHECK_CBOR_RET(ret);
        cm->parsedParams |= PARAM_pinUvAuthParam;
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((cm->subCommand == CM_cmdGetCredsMetadata || cm->subCommand == CM_cmdEnumerateRPsBegin) &&
      (cm->parsedParams & PARAM_pinUvAuthParam) == 0)
    return CTAP2_ERR_PUAT_REQUIRED; // See Section 6.8.2 and 6.8.3
  if ((cm->subCommand == CM_cmdGetCredsMetadata || cm->subCommand == CM_cmdEnumerateRPsBegin) &&
      (cm->parsedParams & PARAM_pinUvAuthProtocol) == 0)
    return CTAP2_ERR_MISSING_PARAMETER; // See Section 6.8.2 and 6.8.3

  return 0;
}
