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

extern CTAP_sm2_attr ctap_sm2_attr;

static void maybe_truncate_rpid(uint8_t stored_rpid[MAX_STORED_RPID_LENGTH], size_t *stored_len, const uint8_t *rpid,
                                size_t rpid_len) {
  if (rpid_len <= MAX_STORED_RPID_LENGTH) {
    memcpy(stored_rpid, rpid, rpid_len);
    *stored_len = rpid_len;
    return;
  }

  size_t used = 0;
  const uint8_t *colon_position = memchr(rpid, ':', rpid_len);
  if (colon_position != NULL) {
    const size_t protocol_len = colon_position - rpid + 1;
    const size_t to_copy = protocol_len <= MAX_STORED_RPID_LENGTH ? protocol_len : MAX_STORED_RPID_LENGTH;
    memcpy(stored_rpid, rpid, to_copy);
    used += to_copy;
  }

  if (MAX_STORED_RPID_LENGTH - used < 3) {
    *stored_len = used;
    return;
  }

  // U+2026, horizontal ellipsis.
  stored_rpid[used++] = 0xe2;
  stored_rpid[used++] = 0x80;
  stored_rpid[used++] = 0xa6;

  const size_t to_copy = MAX_STORED_RPID_LENGTH - used;
  memcpy(&stored_rpid[used], rpid + rpid_len - to_copy, to_copy);
  assert(used + to_copy == MAX_STORED_RPID_LENGTH);
  *stored_len = MAX_STORED_RPID_LENGTH;
}

static uint8_t parse_rp(CTAP_make_credential *mc, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  char key[4], domain[DOMAIN_NAME_MAX_SIZE + 1];
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
      domain[len] = 0;
      DBG_MSG("rp_id: %s\n", domain);
      maybe_truncate_rpid(mc->rp_id, &mc->rp_id_len, (const uint8_t *) domain, len);
      sha256_raw((uint8_t *) domain, len, mc->rp_id_hash);
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_user(user_entity *user, CborValue *val) {
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
    } else if (strcmp(key, "displayName") == 0) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = DISPLAY_NAME_LIMIT - 1;
      ret = cbor_value_copy_text_string(&map, (char *) user->display_name, &len, NULL);
      CHECK_CBOR_RET(ret);
      user->display_name[len] = 0;
      DBG_MSG("displayName: %s\n", user->display_name);
    } else if (strcmp(key, "name") == 0) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = USER_NAME_LIMIT - 1;
      ret = cbor_value_copy_text_string(&map, (char *) user->name, &len, NULL);
      CHECK_CBOR_RET(ret);
      user->name[len] = 0;
      DBG_MSG("name: %s\n", user->name);
    } else if (strcmp(key, "icon") == 0) {
      // We do not store it
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
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

  ret = cbor_value_get_int_checked(&alg, (int *) alg_type);
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
    if (ret == 0 && (cur_alg_type == COSE_ALG_ES256 ||
                     cur_alg_type == COSE_ALG_EDDSA ||
                     (ctap_sm2_attr.enabled && cur_alg_type == ctap_sm2_attr.algo_id))) {
      // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
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
  size_t len = sizeof(credential_id);
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
      options->rk = b;
    } else if (memcmp(key, "uv", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      options->uv = b;
    } else if (memcmp(key, "up", 2) == 0) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      options->up = b;
    } else {
      DBG_MSG("ignoring option specified %c%c\n", key[0], key[1]);
    }
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  DBG_MSG("up: %hhu, uv: %hhu, rk: %hhu\n", options->up, options->uv, options->rk);
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
        if (key != COSE_ALG_ECDH_ES_HKDF_256) return CTAP2_ERR_UNHANDLED_REQUEST;
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

uint8_t parse_mc_extensions(CTAP_make_credential *mc, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  char key[13];
  size_t map_length, len;
  int tmp;

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

    if (strcmp(key, "credProtect") == 0) {
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &tmp);
      CHECK_CBOR_RET(ret);
      if (tmp < 1 || tmp > 3) return CTAP2_ERR_INVALID_OPTION;
      mc->ext_cred_protect = tmp;
      DBG_MSG("credProtect: %d\n", tmp);
    } else if (strcmp(key, "credBlob") == 0) {
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      mc->ext_has_cred_blob = 1;
      len = MAX_CRED_BLOB_LENGTH;
      ret = cbor_value_copy_byte_string(&map, mc->ext_cred_blob, &len, NULL);
      if (ret == CborErrorOutOfMemory) {
        ERR_MSG("credBlob is too long\n");
        // use this value to mark that credBlob is too long
        mc->ext_cred_blob_len = MAX_CRED_BLOB_LENGTH + 1;
        // return CTAP2_ERR_LIMIT_EXCEEDED;
      } else {
        CHECK_CBOR_RET(ret);
        mc->ext_cred_blob_len = len;
        DBG_MSG("credBlob: ");
        PRINT_HEX(mc->ext_cred_blob, len);
      }
    } else if (strcmp(key, "largeBlobKey") == 0) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &mc->ext_large_blob_key);
      CHECK_CBOR_RET(ret);
      DBG_MSG("largeBlobKey: %d\n", mc->ext_large_blob_key);
      if (!mc->ext_large_blob_key) return CTAP2_ERR_INVALID_OPTION;
    } else if (strcmp(key, "hmac-secret") == 0) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &mc->ext_hmac_secret);
      CHECK_CBOR_RET(ret);
      DBG_MSG("hmac-secret: %d\n", mc->ext_hmac_secret);
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_ga_extensions(CTAP_get_assertion *ga, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  char key[13];
  size_t map_length, len;
  int tmp;

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

    if (strcmp(key, "hmac-secret") == 0) {
      DBG_MSG("hmac-secret found\n");
      ga->ext_hmac_secret_pin_protocol = 1; // pinUvAuthProtocol(0x04): (optional) as selected when getting the shared secret. CTAP2.1 platforms MUST include this parameter if the value of pinUvAuthProtocol is not 1.
      if (cbor_value_get_type(&map) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t hmac_map_length;
      CborValue hmac_map;
      ret = cbor_value_enter_container(&map, &hmac_map);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_get_map_length(&map, &hmac_map_length);
      CHECK_CBOR_RET(ret);
      enum {
        GA_HS_MAP_ENTRY_NONE = 0,
        GA_HS_MAP_ENTRY_KEY_AGREEMENT = 0b001,
        GA_HS_MAP_ENTRY_SALT_ENC = 0b010,
        GA_HS_MAP_ENTRY_SALT_AUTH = 0b100,
        GA_HS_MAP_ENTRY_ALL_REQUIRED = 0b111,
      } map_has_entry = GA_HS_MAP_ENTRY_NONE;
      for (size_t j = 0; j < hmac_map_length; ++j) {
        if (cbor_value_get_type(&hmac_map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        int hmac_key;
        ret = cbor_value_get_int_checked(&hmac_map, &hmac_key);
        CHECK_CBOR_RET(ret);
        ret = cbor_value_advance(&hmac_map);
        CHECK_CBOR_RET(ret);
        switch (hmac_key) {
          case GA_REQ_HMAC_SECRET_KEY_AGREEMENT:
            ret = parse_cose_key(&hmac_map, ga->ext_hmac_secret_key_agreement);
            CHECK_CBOR_RET(ret);
            map_has_entry |= GA_HS_MAP_ENTRY_KEY_AGREEMENT;
            DBG_MSG("key_agreement: ");
            PRINT_HEX(ga->ext_hmac_secret_key_agreement, 64);
            break;
          case GA_REQ_HMAC_SECRET_SALT_ENC:
            if (cbor_value_get_type(&hmac_map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            len = sizeof(ga->ext_hmac_secret_salt_enc);
            ret = cbor_value_copy_byte_string(&hmac_map, ga->ext_hmac_secret_salt_enc, &len, NULL);
            if (ret == CborErrorOutOfMemory) {
              ERR_MSG("ext_hmac_secret_salt_enc is too long\n");
              return CTAP1_ERR_INVALID_LENGTH;
            }
            CHECK_CBOR_RET(ret);
            ga->ext_hmac_secret_salt_enc_len = len;
            map_has_entry |= GA_HS_MAP_ENTRY_SALT_ENC;
            DBG_MSG("salt_enc: ");
            PRINT_HEX(ga->ext_hmac_secret_salt_enc, ga->ext_hmac_secret_salt_enc_len);
            break;
          case GA_REQ_HMAC_SECRET_SALT_AUTH:
            if (cbor_value_get_type(&hmac_map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            len = sizeof(ga->ext_hmac_secret_salt_auth);
            ret = cbor_value_copy_byte_string(&hmac_map, ga->ext_hmac_secret_salt_auth, &len, NULL);
            CHECK_CBOR_RET(ret);
            ga->ext_hmac_secret_salt_auth_len = len;
            map_has_entry |= GA_HS_MAP_ENTRY_SALT_AUTH;
            DBG_MSG("salt_auth: ");
            PRINT_HEX(ga->ext_hmac_secret_salt_auth, ga->ext_hmac_secret_salt_auth_len);
            break;
          case GA_REQ_HMAC_SECRET_PIN_PROTOCOL:
            if (cbor_value_get_type(&hmac_map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            ret = cbor_value_get_int_checked(&hmac_map, &tmp);
            CHECK_CBOR_RET(ret);
            ga->ext_hmac_secret_pin_protocol = tmp;
            DBG_MSG("pin_protocol: %d\n", tmp);
            break;
          default:
            DBG_MSG("Ignoring unsupported entry %0x\n", hmac_key);
            break;
        }
        ret = cbor_value_advance(&hmac_map);
        CHECK_CBOR_RET(ret);
      }
      if ((map_has_entry & GA_HS_MAP_ENTRY_ALL_REQUIRED) != GA_HS_MAP_ENTRY_ALL_REQUIRED)
        return CTAP2_ERR_MISSING_PARAMETER;
      if ((ga->ext_hmac_secret_pin_protocol == 1 && ga->ext_hmac_secret_salt_enc_len != HMAC_SECRET_SALT_SIZE &&
           ga->ext_hmac_secret_salt_enc_len != HMAC_SECRET_SALT_SIZE / 2) ||
          (ga->ext_hmac_secret_pin_protocol == 2 && ga->ext_hmac_secret_salt_enc_len != HMAC_SECRET_SALT_SIZE + HMAC_SECRET_SALT_IV_SIZE &&
           ga->ext_hmac_secret_salt_enc_len != HMAC_SECRET_SALT_SIZE / 2 + HMAC_SECRET_SALT_IV_SIZE)) {
        ERR_MSG("Invalid hmac_secret_salt_enc_len %hhu\n", ga->ext_hmac_secret_salt_enc_len);
        return CTAP1_ERR_INVALID_LENGTH;
      }
      if ((ga->ext_hmac_secret_pin_protocol == 1 && ga->ext_hmac_secret_salt_auth_len != HMAC_SECRET_SALT_AUTH_SIZE_P1) ||
          (ga->ext_hmac_secret_pin_protocol == 2 && ga->ext_hmac_secret_salt_auth_len != HMAC_SECRET_SALT_AUTH_SIZE_P2)) {
        ERR_MSG("Invalid hmac_secret_salt_auth_len %hhu\n", ga->ext_hmac_secret_salt_auth_len);
        return CTAP1_ERR_INVALID_LENGTH;
      }
      ga->parsed_params |= PARAM_HMAC_SECRET;
    } else if (strcmp(key, "credBlob") == 0) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &ga->ext_cred_blob);
      CHECK_CBOR_RET(ret);
      DBG_MSG("credBlob: %d\n", ga->ext_cred_blob);
    } else if (strcmp(key, "largeBlobKey") == 0) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &ga->ext_large_blob_key);
      CHECK_CBOR_RET(ret);
      DBG_MSG("largeBlobKey: %d\n", ga->ext_large_blob_key);
      if (!ga->ext_large_blob_key) return CTAP2_ERR_INVALID_OPTION;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

uint8_t parse_cm_params(CTAP_credential_management *cm, CborValue *val, size_t *total_length) {
  *total_length = 0;
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
      case CM_PARAM_RP_ID_HASH:
        DBG_MSG("rp_id_hash found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if (len != SHA256_DIGEST_LENGTH) return CTAP2_ERR_INVALID_CBOR;
        ret = cbor_value_copy_byte_string(&map, cm->rp_id_hash, &len, NULL);
        CHECK_CBOR_RET(ret);
        cm->parsed_params |= PARAM_RP;
        break;

      case CM_PARAM_CREDENTIAL_ID:
        DBG_MSG("credential_id found\n");
        ret = parse_credential_descriptor(&map, (uint8_t *) &cm->credential_id);
        CHECK_CBOR_RET(ret);
        cm->parsed_params |= PARAM_CREDENTIAL_ID;
        break;

      case CM_PARAM_USER:
        DBG_MSG("user found\n");
        ret = parse_user(&cm->user, &map);
        CHECK_CBOR_RET(ret);
        cm->parsed_params |= PARAM_USER;
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  *total_length = map.source.ptr - val->source.ptr;
  return 0;
}

uint8_t parse_make_credential(CborParser *parser, CTAP_make_credential *mc, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, pin_uv_auth_protocol;
  memset(mc, 0, sizeof(CTAP_make_credential));

  // options are absent by default
  mc->options.rk = OPTION_ABSENT;
  mc->options.uv = OPTION_ABSENT;
  mc->options.up = OPTION_ABSENT;

  int ret = cbor_parser_init(buf, len, 0, parser, &it);
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
      case MC_REQ_CLIENT_DATA_HASH:
        DBG_MSG("client_data_hash found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        len = CLIENT_DATA_HASH_SIZE;
        ret = cbor_value_copy_byte_string(&map, mc->client_data_hash, &len, NULL);
        CHECK_CBOR_RET(ret);
        if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
        DBG_MSG("client_data_hash: ");
        PRINT_HEX(mc->client_data_hash, len);
        mc->parsed_params |= PARAM_CLIENT_DATA_HASH;
        break;

      case MC_REQ_RP:
        DBG_MSG("rp_id found\n");
        ret = parse_rp(mc, &map);
        CHECK_PARSER_RET(ret);
        DBG_MSG("rp_id_hash: ");
        PRINT_HEX(mc->rp_id_hash, len);
        mc->parsed_params |= PARAM_RP;
        break;

      case MC_REQ_USER:
        DBG_MSG("user found\n");
        ret = parse_user(&mc->user, &map);
        CHECK_PARSER_RET(ret);
        mc->parsed_params |= PARAM_USER;
        break;

      case MC_REQ_PUB_KEY_CRED_PARAMS:
        DBG_MSG("pubKeyCredParams found\n");
        ret = parse_verify_pub_key_cred_params(&map, &mc->alg_type);
        CHECK_PARSER_RET(ret);
        if (mc->alg_type == COSE_ALG_ES256) DBG_MSG("EcDSA found\n");
        else if (mc->alg_type == COSE_ALG_EDDSA) DBG_MSG("EdDSA found\n");
        else if (mc->alg_type == ctap_sm2_attr.algo_id) DBG_MSG("SM2 found\n");
        else
          DBG_MSG("Found other algorithm\n");
        mc->parsed_params |= PARAM_PUB_KEY_CRED_PARAMS;
        break;

      case MC_REQ_EXCLUDE_LIST:
        DBG_MSG("exclude_list found\n");
        ret = parse_public_key_credential_list(&map);
        CHECK_PARSER_RET(ret);
        ret = cbor_value_enter_container(&map, &mc->exclude_list);
        CHECK_CBOR_RET(ret);
        ret = cbor_value_get_array_length(&map, &mc->exclude_list_size);
        CHECK_CBOR_RET(ret);
        DBG_MSG("exclude_list size: %d\n", (int) mc->exclude_list_size);
        break;

      case MC_REQ_EXTENSIONS:
        DBG_MSG("extensions found\n");
        ret = parse_mc_extensions(mc, &map);
        CHECK_PARSER_RET(ret);
        mc->parsed_params |= PARAM_EXTENSIONS;
        break;

      case MC_REQ_OPTIONS:
        DBG_MSG("options found\n");
        ret = parse_options(&mc->options, &map);
        CHECK_PARSER_RET(ret);
        mc->parsed_params |= PARAM_OPTIONS;
        break;

      case MC_REQ_PIN_UV_AUTH_PARAM:
        DBG_MSG("pin_uv_auth_param found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &mc->pin_uv_auth_param_len);
        CHECK_CBOR_RET(ret);
        if (mc->pin_uv_auth_param_len > SHA256_DIGEST_LENGTH) {
          DBG_MSG("pin_uv_auth_param is too long\n");
          return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (mc->pin_uv_auth_param_len > 0) {
          ret = cbor_value_copy_byte_string(&map, mc->pin_uv_auth_param, &mc->pin_uv_auth_param_len, NULL);
          CHECK_CBOR_RET(ret);
          DBG_MSG("pin_uv_auth_param: ");
          PRINT_HEX(mc->pin_uv_auth_param, mc->pin_uv_auth_param_len);
        }
        mc->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
        break;

      case MC_REQ_PIN_PROTOCOL:
        DBG_MSG("pin_uv_auth_protocol found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &pin_uv_auth_protocol);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pin_uv_auth_protocol: %d\n", pin_uv_auth_protocol);
        if (pin_uv_auth_protocol != 1 && pin_uv_auth_protocol != 2) {
          DBG_MSG("Unknown pin_uv_auth_protocol\n");
          return CTAP1_ERR_INVALID_PARAMETER;
        }
        mc->pin_uv_auth_protocol = pin_uv_auth_protocol;
        mc->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
        break;

      case MC_REQ_ENTERPRISE_ATTESTATION:
        DBG_MSG("enterpriseAttestation found\n");
        mc->parsed_params |= PARAM_ENTERPRISE_ATTESTATION;
        // TODO: parse enterpriseAttestation
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((mc->parsed_params & MC_REQUIRED_MASK) != MC_REQUIRED_MASK) {
    DBG_MSG("Missing required params\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }
  return 0;
}

uint8_t parse_get_assertion(CborParser *parser, CTAP_get_assertion *ga, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, pin_uv_auth_protocol;
  char domain[DOMAIN_NAME_MAX_SIZE];
  memset(ga, 0, sizeof(CTAP_get_assertion));

  // options are absent by default
  ga->options.rk = OPTION_ABSENT;
  ga->options.uv = OPTION_ABSENT;
  ga->options.up = OPTION_ABSENT;

  int ret = cbor_parser_init(buf, len, 0, parser, &it);
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
      case GA_REQ_RP_ID:
        DBG_MSG("rp_id found\n");
        if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        len = DOMAIN_NAME_MAX_SIZE;
        ret = cbor_value_copy_text_string(&map, domain, &len, NULL);
        CHECK_CBOR_RET(ret);
        domain[DOMAIN_NAME_MAX_SIZE - 1] = 0;
        DBG_MSG("rp_id: %s; hash: ", domain);
        sha256_raw((uint8_t *) domain, len, ga->rp_id_hash);
        PRINT_HEX(ga->rp_id_hash, SHA256_DIGEST_LENGTH);
        ga->parsed_params |= PARAM_RP;
        break;

      case GA_REQ_CLIENT_DATA_HASH:
        DBG_MSG("client_data_hash found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        len = CLIENT_DATA_HASH_SIZE;
        ret = cbor_value_copy_byte_string(&map, ga->client_data_hash, &len, NULL);
        CHECK_CBOR_RET(ret);
        if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
        DBG_MSG("client_data_hash: ");
        PRINT_HEX(ga->client_data_hash, len);
        ga->parsed_params |= PARAM_CLIENT_DATA_HASH;
        break;

      case GA_REQ_ALLOW_LIST:
        DBG_MSG("allow_list found\n");
        ret = parse_public_key_credential_list(&map);
        CHECK_PARSER_RET(ret);
        ret = cbor_value_enter_container(&map, &ga->allow_list);
        CHECK_CBOR_RET(ret);
        ret = cbor_value_get_array_length(&map, &ga->allow_list_size);
        CHECK_CBOR_RET(ret);
        DBG_MSG("allow_list size: %d\n", (int) ga->allow_list_size);
        break;

      case GA_REQ_EXTENSIONS:
        DBG_MSG("extensions found\n");
        ret = parse_ga_extensions(ga, &map);
        CHECK_PARSER_RET(ret);
        break;

      case GA_REQ_OPTIONS:
        DBG_MSG("options found\n");
        ret = parse_options(&ga->options, &map);
        CHECK_PARSER_RET(ret);
        ga->parsed_params |= PARAM_OPTIONS;
        break;

      case GA_REQ_PIN_UV_AUTH_PARAM:
        DBG_MSG("pin_uv_auth_param found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &ga->pin_uv_auth_param_len);
        CHECK_CBOR_RET(ret);
        if (ga->pin_uv_auth_param_len > SHA256_DIGEST_LENGTH)
          return CTAP2_ERR_PIN_AUTH_INVALID;
        if (ga->pin_uv_auth_param_len > 0) {
          ret = cbor_value_copy_byte_string(&map, ga->pin_uv_auth_param, &ga->pin_uv_auth_param_len, NULL);
          CHECK_CBOR_RET(ret);
          DBG_MSG("pin_uv_auth_param: ");
          PRINT_HEX(ga->pin_uv_auth_param, ga->pin_uv_auth_param_len);
        }
        ga->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
        break;

      case GA_REQ_PIN_UV_AUTH_PROTOCOL:
        DBG_MSG("pin_uv_auth_protocol found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &pin_uv_auth_protocol);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pin_uv_auth_protocol: %d\n", pin_uv_auth_protocol);
        if (pin_uv_auth_protocol != 1 && pin_uv_auth_protocol != 2) {
          DBG_MSG("Unknown pin_uv_auth_protocol\n");
          return CTAP1_ERR_INVALID_PARAMETER;
        }
        ga->pin_uv_auth_protocol = pin_uv_auth_protocol;
        ga->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((ga->parsed_params & GA_REQUIRED_MASK) != GA_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;
  return 0;
}

uint8_t parse_client_pin(CborParser *parser, CTAP_client_pin *cp, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key;
  char domain[DOMAIN_NAME_MAX_SIZE + 1];
  memset(cp, 0, sizeof(CTAP_client_pin));

  int ret = cbor_parser_init(buf, len, 0, parser, &it);
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
      case CP_REQ_PIN_UV_AUTH_PROTOCOL:
        DBG_MSG("pinProtocol found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &key);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pinProtocol: %d\n", key);
        if (key != 1 && key != 2) {
          ERR_MSG("Invalid pinProtocol\n");
          return CTAP1_ERR_INVALID_PARAMETER;
        }
        cp->pin_uv_auth_protocol = key;
        cp->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
        break;

      case CP_REQ_SUB_COMMAND:
        DBG_MSG("sub_command found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &key);
        CHECK_CBOR_RET(ret);
        cp->sub_command = key;
        DBG_MSG("sub_command: %d\n", cp->sub_command);
        cp->parsed_params |= PARAM_SUB_COMMAND;
        break;

      case CP_REQ_KEY_AGREEMENT:
        DBG_MSG("key_agreement found\n");
        ret = parse_cose_key(&map, cp->key_agreement);
        CHECK_PARSER_RET(ret);
        DBG_MSG("key_agreement: ");
        PRINT_HEX(cp->key_agreement, PUB_KEY_SIZE);
        cp->parsed_params |= PARAM_KEY_AGREEMENT;
        break;

      case CP_REQ_PIN_UV_AUTH_PARAM:
        DBG_MSG("pin_uv_auth_param found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if (len == 0 || len > SHA256_DIGEST_LENGTH) return CTAP2_ERR_PIN_AUTH_INVALID;
        ret = cbor_value_copy_byte_string(&map, cp->pin_uv_auth_param, &len, NULL);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pin_uv_auth_param: ");
        PRINT_HEX(cp->pin_uv_auth_param, len);
        cp->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
        break;

      case CP_REQ_NEW_PIN_ENC:
        DBG_MSG("new_pin_enc found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if ((cp->pin_uv_auth_protocol == 1 && len != PIN_ENC_SIZE_P1) ||
            (cp->pin_uv_auth_protocol == 2 && len != PIN_ENC_SIZE_P2)) {
          ERR_MSG("Invalid new_pin_enc length\n");
          return CTAP2_ERR_INVALID_CBOR;
        }
        ret = cbor_value_copy_byte_string(&map, cp->new_pin_enc, &len, NULL);
        CHECK_CBOR_RET(ret);
        DBG_MSG("new_pin_enc: ");
        PRINT_HEX(cp->new_pin_enc, len);
        cp->parsed_params |= PARAM_NEW_PIN_ENC;
        break;

      case CP_REQ_PIN_HASH_ENC:
        DBG_MSG("pin_hash_enc found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if ((cp->pin_uv_auth_protocol == 1 && len != PIN_HASH_SIZE_P1) ||
            (cp->pin_uv_auth_protocol == 2 && len != PIN_HASH_SIZE_P2)) {
          ERR_MSG("Invalid pin_hash_enc length\n");
          return CTAP2_ERR_INVALID_CBOR;
        }
        ret = cbor_value_copy_byte_string(&map, cp->pin_hash_enc, &len, NULL);
        CHECK_CBOR_RET(ret);
        cp->parsed_params |= PARAM_PIN_HASH_ENC;
        break;

      case CP_REQ_PERMISSIONS:
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
        if (cp->permissions & (CP_PERMISSION_BE | CP_PERMISSION_ACFG)) {
          DBG_MSG("Unsupported permissions\n");
          return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
        }
        cp->parsed_params |= PARAM_PERMISSIONS;
        break;

      case CP_REQ_RP_ID:
        DBG_MSG("rp id found\n");
        if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        len = DOMAIN_NAME_MAX_SIZE;
        ret = cbor_value_copy_text_string(&map, domain, &len, NULL);
        CHECK_CBOR_RET(ret);
        domain[len] = 0;
        DBG_MSG("rp_id: %s\n", domain);
        sha256_raw((uint8_t *) domain, len, cp->rp_id_hash);
        cp->parsed_params |= PARAM_RP;
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((cp->parsed_params & CP_REQUIRED_MASK) != CP_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_GET_KEY_AGREEMENT && (cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_SET_PIN &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 ||
       (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_NEW_PIN_ENC) == 0 ||
       (cp->parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_CHANGE_PIN &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 ||
       (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_PIN_HASH_ENC) == 0 ||
       (cp->parsed_params & PARAM_NEW_PIN_ENC) == 0 ||
       (cp->parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_GET_PIN_TOKEN &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 ||
       (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_PIN_HASH_ENC) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cp->sub_command == CP_CMD_GET_PIN_TOKEN &&
      ((cp->parsed_params & PARAM_PERMISSIONS) != 0 ||
       (cp->parsed_params & PARAM_RP) != 0))
    return CTAP1_ERR_INVALID_PARAMETER;

  if (cp->sub_command == CP_CMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 ||
       (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_PIN_HASH_ENC) == 0 ||
       (cp->parsed_params & PARAM_PERMISSIONS) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t
parse_credential_management(CborParser *parser, CTAP_credential_management *cm, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, tmp;
  memset(cm, 0, sizeof(CTAP_credential_management));

  int ret = cbor_parser_init(buf, len, 0, parser, &it);
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
      case CM_REQ_SUB_COMMAND:
        DBG_MSG("sub_command found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        cm->sub_command = tmp;
        DBG_MSG("sub_command: %d\n", cm->sub_command);
        cm->parsed_params |= PARAM_SUB_COMMAND;
        break;

      case CM_REQ_SUB_COMMAND_PARAMS:
        DBG_MSG("subCommandParams found\n");
        cm->sub_command_params_ptr = (uint8_t *) map.source.ptr;
        ret = parse_cm_params(cm, &map, &cm->param_len);
        DBG_MSG("sub_command_params (%zu): ", cm->param_len);
        PRINT_HEX(cm->sub_command_params_ptr, cm->param_len);
        CHECK_CBOR_RET(ret);
        break;

      case CM_REQ_PIN_UV_AUTH_PROTOCOL:
        DBG_MSG("pin_uv_auth_protocol found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pin_uv_auth_protocol: %d\n", tmp);
        if (tmp != 1 && tmp != 2) return CTAP1_ERR_INVALID_PARAMETER;
        cm->pin_uv_auth_protocol = tmp;
        cm->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
        break;

      case CM_REQ_PIN_UV_AUTH_PARAM:
        DBG_MSG("pin_uv_auth_param found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if (len == 0 || len > SHA256_DIGEST_LENGTH) return CTAP2_ERR_PIN_AUTH_INVALID;
        ret = cbor_value_copy_byte_string(&map, cm->pin_uv_auth_param, &len, NULL);
        CHECK_CBOR_RET(ret);
        PRINT_HEX(cm->pin_uv_auth_param, len);
        cm->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if ((cm->parsed_params & CM_REQUIRED_MASK) != CM_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;

  if ((cm->sub_command == CM_CMD_GET_CREDS_METADATA ||
       cm->sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
       cm->sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN ||
       cm->sub_command == CM_CMD_DELETE_CREDENTIAL ||
       cm->sub_command == CM_CMD_UPDATE_USER_INFORMATION) &&
      (cm->parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0)
    return CTAP2_ERR_PUAT_REQUIRED; // See Section 6.8.2, 6.8.3, 6.8.4, 6.8.5, 6.8.6
  if ((cm->sub_command == CM_CMD_GET_CREDS_METADATA ||
       cm->sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
       cm->sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN ||
       cm->sub_command == CM_CMD_DELETE_CREDENTIAL ||
       cm->sub_command == CM_CMD_UPDATE_USER_INFORMATION) &&
      (cm->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0)
    return CTAP2_ERR_MISSING_PARAMETER; // See Section 6.8.2, 6.8.3, 6.8.4, 6.8.5, 6.8.6
  if (cm->sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN && (cm->parsed_params & PARAM_RP) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cm->sub_command == CM_CMD_DELETE_CREDENTIAL && (cm->parsed_params & PARAM_CREDENTIAL_ID) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cm->sub_command == CM_CMD_UPDATE_USER_INFORMATION && (cm->parsed_params & (PARAM_USER|PARAM_CREDENTIAL_ID)) != (PARAM_USER|PARAM_CREDENTIAL_ID))
    return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t parse_large_blobs(CborParser *parser, CTAP_large_blobs *lb, const uint8_t *buf, size_t len) {
  CborValue it, map;
  size_t map_length;
  int key, tmp;
  memset(lb, 0, sizeof(CTAP_large_blobs));

  int ret = cbor_parser_init(buf, len, 0, parser, &it);
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
      case LB_REQ_GET:
        DBG_MSG("get found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        DBG_MSG("get: %d\n", tmp);
        if (tmp < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; // should be unsigned integer
        if (tmp > UINT16_MAX) tmp = UINT16_MAX;
        lb->get = tmp;
        lb->parsed_params |= PARAM_GET;
        break;

      case LB_REQ_SET:
        DBG_MSG("set found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &lb->set_len);
        CHECK_CBOR_RET(ret);
        lb->set = (uint8_t *) map.source.ptr + 1;
        if (lb->set_len >= 24) ++lb->set;
        if (lb->set_len >= 256) ++lb->set;
        DBG_MSG("set(%zuB): ", lb->set_len);
        PRINT_HEX(lb->set, lb->set_len < 17 ? lb->set_len : 17);
        lb->parsed_params |= PARAM_SET;
        break;

      case LB_REQ_OFFSET:
        DBG_MSG("offset found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        DBG_MSG("offset: %d\n", tmp);
        if (tmp < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; // should be unsigned integer
        if (tmp > UINT16_MAX) tmp = UINT16_MAX;
        lb->offset = tmp;
        lb->parsed_params |= PARAM_OFFSET;
        break;

      case LB_REQ_LENGTH:
        DBG_MSG("length found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        DBG_MSG("length: %d\n", tmp);
        if (tmp < 0) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; // should be unsigned integer
        if (tmp > UINT16_MAX) tmp = UINT16_MAX;
        lb->length = tmp;
        lb->parsed_params |= PARAM_LENGTH;
        break;

      case LB_REQ_PIN_UV_AUTH_PROTOCOL:
        DBG_MSG("pin_uv_auth_protocol found\n");
        if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_int_checked(&map, &tmp);
        CHECK_CBOR_RET(ret);
        DBG_MSG("pin_uv_auth_protocol: %d\n", tmp);
        if (tmp != 1 && tmp != 2) return CTAP1_ERR_INVALID_PARAMETER;
        lb->pin_uv_auth_protocol = tmp;
        lb->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
        break;

      case LB_REQ_PIN_UV_AUTH_PARAM:
        DBG_MSG("pin_uv_auth_param found\n");
        if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        ret = cbor_value_get_string_length(&map, &len);
        CHECK_CBOR_RET(ret);
        if (len == 0 || len > SHA256_DIGEST_LENGTH) return CTAP2_ERR_PIN_AUTH_INVALID;
        ret = cbor_value_copy_byte_string(&map, lb->pin_uv_auth_param, &len, NULL);
        CHECK_CBOR_RET(ret);
        lb->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
        break;

      default:
        DBG_MSG("Unknown key: %d\n", key);
        break;
    }

    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }

  if (!(lb->parsed_params & PARAM_OFFSET)) return CTAP1_ERR_INVALID_PARAMETER;
  if (!((lb->parsed_params & PARAM_GET) ^ (lb->parsed_params & PARAM_SET))) return CTAP1_ERR_INVALID_PARAMETER;
  if (lb->parsed_params & PARAM_GET) {
    if (lb->parsed_params & PARAM_LENGTH) return CTAP1_ERR_INVALID_PARAMETER;
    if ((lb->parsed_params & PARAM_PIN_UV_AUTH_PARAM) || (lb->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL))
      return CTAP1_ERR_INVALID_PARAMETER;
    if (lb->get > MAX_FRAGMENT_LENGTH) return CTAP1_ERR_INVALID_LENGTH;
  }
  if (lb->parsed_params & PARAM_SET) {
    if (lb->set_len > MAX_FRAGMENT_LENGTH) return CTAP1_ERR_INVALID_LENGTH;
    if (lb->offset == 0) {
      if (!(lb->parsed_params & PARAM_LENGTH)) return CTAP1_ERR_INVALID_PARAMETER;
      if (lb->length > LARGE_BLOB_SIZE_LIMIT) return CTAP2_ERR_LARGE_BLOB_STORAGE_FULL;
      if (lb->length < 17) return CTAP1_ERR_INVALID_PARAMETER;
    } else {
      if (lb->parsed_params & PARAM_LENGTH) return CTAP1_ERR_INVALID_PARAMETER;
    }
  }

  return 0;
}
