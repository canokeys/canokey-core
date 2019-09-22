#include "ctap-parser.h"
#include "cose-key.h"
#include "ctap-errors.h"
#include <cbor.h>
#include <common.h>
#include <ctap.h>

#define CHECK_PARSER_RET(ret)                                                                                          \
  do {                                                                                                                 \
    if (ret > 0) DBG_MSG("CHECK_PARSER_RET %#x\n", ret);                                                            \
    if (ret > 0) return ret;                                                                                           \
  } while (0)
#define CHECK_CBOR_RET(ret)                                                                                            \
  do {                                                                                                                 \
    if (ret != CborNoError) DBG_MSG("CHECK_CBOR_RET %#x\n", ret);                                                            \
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
  size_t map_length, len = sizeof(key);

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

  char type_str[10];
  size_t sz = sizeof(type_str);
  ret = cbor_value_copy_text_string(&cred, type_str, &sz, NULL);
  CHECK_CBOR_RET(ret);

  if (strncmp(type_str, "public-key", 10) != 0) return CTAP2_ERR_INVALID_CBOR;

  ret = cbor_value_get_int_checked(&alg, (int *)alg_type);
  CHECK_CBOR_RET(ret);
  return 0;
}

uint8_t parse_verify_pub_key_cred_params(CborValue *val) {
  if (cbor_value_get_type(val) != CborArrayType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue arr;
  size_t arr_length;
  int ret = cbor_value_enter_container(val, &arr);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_array_length(val, &arr_length);
  CHECK_CBOR_RET(ret);

  int32_t alg_type;
  for (size_t i = 0; i < arr_length; ++i) {
    ret = parse_pub_key_cred_param(&arr, &alg_type);
    CHECK_PARSER_RET(ret);
    if (ret == 0 && alg_type == COSE_ALG_ES256) return 0;
    ret = cbor_value_advance(&arr);
    CHECK_CBOR_RET(ret);
  }
  return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

uint8_t parse_credential_descriptor(CborValue *arr, uint8_t *id) {
  if (cbor_value_get_type(arr) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue val;
  uint8_t ret = cbor_value_map_find_value(arr, "id", &val);
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

  char type_str[10];
  len = sizeof(type_str);
  ret = cbor_value_copy_text_string(&val, type_str, &len, NULL);
  CHECK_CBOR_RET(ret);

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
  for (size_t i = 0; i < size; i++) {
    ret = parse_credential_descriptor(&arr, NULL);
    CHECK_PARSER_RET(ret);
    ret = cbor_value_advance(&arr);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_options(uint8_t *rk, uint8_t *uv, uint8_t *up, CborValue *val) {
  size_t map_length;
  char key[2];
  bool b;
  CborValue map;

  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; i++) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    size_t sz = sizeof(key);
    ret = cbor_value_copy_text_string(&map, key, &sz, NULL);
    if (ret != CborErrorOutOfMemory) CHECK_CBOR_RET(ret);

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    if (strncmp(key, "rk", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("rk: %d\n", b);
      if (rk) *rk = b;
    } else if (strncmp(key, "uv", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("uv: %d\n", b);
      if (uv) *uv = b;
    } else if (strncmp(key, "up", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("up: %d\n", b);
      if (up) *up = b;
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
  for (size_t i = 0; i < map_length; i++) {
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
      len = ECC_KEY_SIZE;
      ret = cbor_value_copy_byte_string(&map, public_key, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != ECC_KEY_SIZE) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    case COSE_KEY_LABEL_Y:
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = ECC_KEY_SIZE;
      ret = cbor_value_copy_byte_string(&map, public_key + ECC_KEY_SIZE, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != ECC_KEY_SIZE) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    default:
      DBG_MSG("Unknown cose key label: %d\n", key);
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  DBG_MSG("parsed_keys=%x\n",parsed_keys);
  if (parsed_keys < 4) return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t parse_extensions(uint8_t *hmac_secret, CborValue *val) {
  size_t map_length;
  char key[11];
  bool b;
  CborValue map;

  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  int ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; i++) {
    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    size_t sz = sizeof(key);
    ret = cbor_value_copy_text_string(&map, key, &sz, NULL);
    CHECK_CBOR_RET(ret);

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    if (strncmp(key, "hmac-secret", 11) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      DBG_MSG("hmac-secret: %d\n", b);
      if (hmac_secret) *hmac_secret = b;
    } else {
      DBG_MSG("ignoring option specified %c%c\n", key[0], key[1]);
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
      DBG_MSG("clientDataHash: ");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = CLIENT_DATA_HASH_SIZE;
      ret = cbor_value_copy_byte_string(&map, mc->clientDataHash, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      PRINT_HEX(mc->clientDataHash, len);
      mc->parsedParams |= PARAM_clientDataHash;
      break;

    case MC_rp:
      DBG_MSG("rpIdHash: ");
      ret = parse_rp(mc->rpIdHash, &map);
      CHECK_PARSER_RET(ret);
      PRINT_HEX(mc->rpIdHash, len);
      mc->parsedParams |= PARAM_rpId;
      break;

    case MC_user:
      DBG_MSG("user: ");
      ret = parse_user(&mc->user, &map);
      CHECK_PARSER_RET(ret);
      mc->parsedParams |= PARAM_user;
      break;

    case MC_pubKeyCredParams:
      DBG_MSG("pubKeyCredParams: ");
      ret = parse_verify_pub_key_cred_params(&map);
      CHECK_PARSER_RET(ret);
      DBG_MSG("EcDSA found\n");
      mc->parsedParams |= PARAM_pubKeyCredParams;
      break;

    case MC_excludeList:
      DBG_MSG("exclude list: ");
      ret = parse_public_key_credential_list(&map);
      CHECK_PARSER_RET(ret);
      ret = cbor_value_enter_container(&map, &mc->excludeList);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_get_array_length(&map, &mc->excludeListSize);
      CHECK_CBOR_RET(ret);
      DBG_MSG("%lu\n", mc->excludeListSize);
      break;

    case MC_extensions:
      DBG_MSG("extensions: ");
      ret = parse_extensions(NULL, &map);
      CHECK_PARSER_RET(ret);
      mc->parsedParams |= PARAM_extensions;
      break;

    case MC_options:
      DBG_MSG("options:\n");
      ret = parse_options(&mc->rk, &mc->uv, NULL, &map);
      CHECK_PARSER_RET(ret);
      mc->parsedParams |= PARAM_options;
      break;

    case MC_pinAuth:
      DBG_MSG("pinAuth: ");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &mc->pinAuthLength);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_copy_byte_string(&map, mc->pinAuth, &mc->pinAuthLength, NULL);
      CHECK_CBOR_RET(ret);
      mc->parsedParams |= PARAM_pinAuth;
      break;

    case MC_pinProtocol:
      DBG_MSG("pinProtocol: ");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &pinProtocol);
      CHECK_CBOR_RET(ret);
      DBG_MSG("%d\n", pinProtocol);
      if (pinProtocol != 1) return CTAP2_ERR_PIN_AUTH_INVALID;
      mc->parsedParams |= PARAM_pinProtocol;
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
      DBG_MSG("rpId: ");
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = DOMAIN_NAME_MAX_SIZE;
      ret = cbor_value_copy_text_string(&map, domain, &len, NULL);
      CHECK_CBOR_RET(ret);
      domain[DOMAIN_NAME_MAX_SIZE - 1] = 0;
      DBG_MSG("%s ", domain);
      sha256_raw((uint8_t *)domain, len, ga->rpIdHash);
      PRINT_HEX(ga->rpIdHash, SHA256_DIGEST_LENGTH);
      ga->parsedParams |= PARAM_rpId;
      break;

    case GA_clientDataHash:
      DBG_MSG("clientDataHash: ");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = CLIENT_DATA_HASH_SIZE;
      ret = cbor_value_copy_byte_string(&map, ga->clientDataHash, &len, NULL);
      CHECK_CBOR_RET(ret);
      if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      PRINT_HEX(ga->clientDataHash, len);
      ga->parsedParams |= PARAM_clientDataHash;
      break;

    case GA_allowList:
      DBG_MSG("allow list: ");
      ret = parse_public_key_credential_list(&map);
      CHECK_PARSER_RET(ret);
      ret = cbor_value_enter_container(&map, &ga->allowList);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_get_array_length(&map, &ga->allowListSize);
      CHECK_CBOR_RET(ret);
      DBG_MSG("%lu\n", ga->allowListSize);
      break;

    case GA_extensions:
      DBG_MSG("Ignore Extensions\n");
      break;

    case GA_options:
      DBG_MSG("options:\n");
      ret = parse_options(NULL, &ga->uv, &ga->up, &map);
      CHECK_PARSER_RET(ret);
      ga->parsedParams |= PARAM_options;
      break;

    case GA_pinAuth:
      DBG_MSG("pinAuth: ");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &ga->pinAuthLength);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_copy_byte_string(&map, ga->pinAuth, &ga->pinAuthLength, NULL);
      CHECK_CBOR_RET(ret);
      ga->parsedParams |= PARAM_pinAuth;
      break;

    case GA_pinProtocol:
      DBG_MSG("pinProtocol: ");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &pinProtocol);
      CHECK_CBOR_RET(ret);
      DBG_MSG("%d\n", pinProtocol);
      if (pinProtocol != 1) return CTAP2_ERR_PIN_AUTH_INVALID;
      ga->parsedParams |= PARAM_pinProtocol;
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
  int key, pinProtocol;
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
    case CP_pinProtocol:
      DBG_MSG("pinProtocol: ");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &pinProtocol);
      CHECK_CBOR_RET(ret);
      DBG_MSG("%d\n", pinProtocol);
      if (pinProtocol != 1) return CTAP2_ERR_PIN_AUTH_INVALID;
      cp->parsedParams |= PARAM_pinProtocol;
      break;

    case CP_subCommand:
      DBG_MSG("subCommand: ");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &pinProtocol); // use pinProtocol as a buffer
      CHECK_CBOR_RET(ret);
      cp->subCommand = pinProtocol;
      DBG_MSG("%d\n", cp->subCommand);
      cp->parsedParams |= PARAM_subCommand;
      break;

    case CP_keyAgreement:
      DBG_MSG("keyAgreement: ");
      ret = parse_cose_key(&map, cp->keyAgreement);
      CHECK_PARSER_RET(ret);
      cp->parsedParams |= PARAM_keyAgreement;
      break;

    case CP_pinAuth:
      DBG_MSG("pinAuth\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if (len != PIN_AUTH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      ret = cbor_value_copy_byte_string(&map, cp->pinAuth, &len, NULL);
      CHECK_CBOR_RET(ret);
      cp->parsedParams |= PARAM_pinAuth;
      break;

    case CP_newPinEnc:
      DBG_MSG("newPinEnc\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if (len != MAX_PIN_SIZE + 1) return CTAP2_ERR_INVALID_CBOR;
      ret = cbor_value_copy_byte_string(&map, cp->newPinEnc, &len, NULL);
      CHECK_CBOR_RET(ret);
      cp->parsedParams |= PARAM_newPinEnc;
      break;

    case CP_pinHashEnc:
      DBG_MSG("pinHashEnc\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if (len != PIN_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      ret = cbor_value_copy_byte_string(&map, cp->pinHashEnc, &len, NULL);
      CHECK_CBOR_RET(ret);
      cp->parsedParams |= PARAM_pinHashEnc;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((cp->parsedParams & CP_requiredMask) != CP_requiredMask) return CTAP2_ERR_MISSING_PARAMETER;
  if (cp->subCommand == CP_cmdSetPin &&
      ((cp->parsedParams & PARAM_keyAgreement) == 0 || (cp->parsedParams & PARAM_newPinEnc) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cp->subCommand == CP_cmdChangePin &&
      ((cp->parsedParams & PARAM_keyAgreement) == 0 || (cp->parsedParams & PARAM_pinHashEnc) == 0 ||
       (cp->parsedParams & PARAM_newPinEnc) == 0 || (cp->parsedParams & PARAM_pinAuth) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cp->subCommand == CP_cmdGetPinToken &&
      ((cp->parsedParams & PARAM_keyAgreement) == 0 || (cp->parsedParams & PARAM_pinHashEnc) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}
