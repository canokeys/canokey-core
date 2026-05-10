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

typedef struct {
  const ctap_req_src_t *src;
  size_t offset;
  uint8_t scratch[MAX_CTAP_EXTERNAL_STRING_CHUNK];
} ctap_cbor_reader_t;

static bool ctap_cbor_source_cancelled(const ctap_req_src_t *src) {
  return src && src->cancelled && src->cancelled(src->ctx);
}

static uint8_t ctap_cbor_value_cancel_status(const CborValue *val) {
  if (!val || !val->parser || (val->parser->flags & CborParserFlag_ExternalSource) == 0) return 0;
  const ctap_cbor_reader_t *reader = (const ctap_cbor_reader_t *)val->source.token;
  return reader && ctap_cbor_source_cancelled(reader->src) ? CTAP2_ERR_KEEPALIVE_CANCEL : 0;
}

#define CHECK_CANCELLED_VALUE(val)                                                                                     \
  do {                                                                                                                 \
    uint8_t _cancel_status = ctap_cbor_value_cancel_status((val));                                                     \
    if (_cancel_status != 0) return _cancel_status;                                                                    \
  } while (0)

static bool ctap_cbor_can_read_bytes(void *token, size_t len) {
  ctap_cbor_reader_t *reader = (ctap_cbor_reader_t *)token;
  if (!reader->src) return false;
  (void)ctap_cbor_source_cancelled(reader->src);
  if (reader->offset > reader->src->len) return false;
  return len <= reader->src->len - reader->offset;
}

static void *ctap_cbor_read_bytes(void *token, void *dst, size_t offset, size_t len) {
  ctap_cbor_reader_t *reader = (ctap_cbor_reader_t *)token;
  uint8_t *buf = dst != NULL ? (uint8_t *)dst : reader->scratch;
  if (!reader->src || !reader->src->read || !buf) return NULL;
  (void)ctap_cbor_source_cancelled(reader->src);
  if (reader->offset > reader->src->len) return NULL;
  if (len > sizeof(reader->scratch) && dst == NULL) return NULL;
  if (offset > reader->src->len - reader->offset || len > reader->src->len - reader->offset - offset) return NULL;
  if (reader->src->read(reader->src->ctx, reader->src->base_offset + reader->offset + offset, buf, len) < 0)
    return NULL;
  return buf;
}

static void ctap_cbor_advance_bytes(void *token, size_t len) {
  ctap_cbor_reader_t *reader = (ctap_cbor_reader_t *)token;
  if (reader->src && reader->offset <= reader->src->len && len <= reader->src->len - reader->offset)
    reader->offset += len;
}

static CborError ctap_cbor_transfer_string(void *token, const void **userptr, size_t offset, size_t len) {
  ctap_cbor_reader_t *reader = (ctap_cbor_reader_t *)token;
  if (!reader->src || !reader->src->read) return CborErrorIO;
  (void)ctap_cbor_source_cancelled(reader->src);
  if (reader->offset > reader->src->len) return CborErrorUnexpectedEOF;
  if (offset > reader->src->len - reader->offset || len > reader->src->len - reader->offset - offset)
    return CborErrorUnexpectedEOF;
  if (len > sizeof(reader->scratch)) return CborErrorOutOfMemory;
  if (reader->src->read(reader->src->ctx, reader->src->base_offset + reader->offset + offset, reader->scratch, len) < 0)
    return CborErrorIO;
  if (userptr != NULL) *userptr = reader->scratch;
  reader->offset += offset + len;
  return CborNoError;
}

static const struct CborParserOperations ctap_cbor_reader_ops = {
    .can_read_bytes = ctap_cbor_can_read_bytes,
    .read_bytes = ctap_cbor_read_bytes,
    .advance_bytes = ctap_cbor_advance_bytes,
    .transfer_string = ctap_cbor_transfer_string,
};

static uint8_t ctap_parser_init(CborParser *parser, CborValue *it, const uint8_t *buf, size_t len) {
  const int ret = cbor_parser_init(buf, len, 0, parser, it);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t ctap_parser_init_src(CborParser *parser, CborValue *it, ctap_cbor_reader_t *reader,
                                    const ctap_req_src_t *src) {
  if (!src || !src->read) return CTAP2_ERR_INVALID_CBOR;
  memset(reader, 0, sizeof(*reader));
  reader->src = src;
  const int ret = cbor_parser_init_reader(&ctap_cbor_reader_ops, parser, it, reader);
  CHECK_CBOR_RET(ret);
  return 0;
}

static CborError ctap_cbor_copy_text(CborValue *val, char *buf, size_t *len) {
  return cbor_value_copy_text_string(val, buf, len, val);
}

static CborError ctap_cbor_copy_bytes(CborValue *val, uint8_t *buf, size_t *len) {
  return cbor_value_copy_byte_string(val, buf, len, val);
}

typedef enum {
  CTAP_TEXT_KEY_UNKNOWN = 0,
  CTAP_TEXT_KEY_ALG,
  CTAP_TEXT_KEY_CRED_BLOB,
  CTAP_TEXT_KEY_CRED_PROTECT,
  CTAP_TEXT_KEY_DISPLAY_NAME,
  CTAP_TEXT_KEY_HMAC_SECRET,
  CTAP_TEXT_KEY_HMAC_SECRET_MC,
  CTAP_TEXT_KEY_ICON,
  CTAP_TEXT_KEY_ID,
  CTAP_TEXT_KEY_LARGE_BLOB_KEY,
  CTAP_TEXT_KEY_MIN_PIN_LENGTH,
  CTAP_TEXT_KEY_NAME,
  CTAP_TEXT_KEY_RK,
  CTAP_TEXT_KEY_THIRD_PARTY_PAYMENT,
  CTAP_TEXT_KEY_TYPE,
  CTAP_TEXT_KEY_UP,
  CTAP_TEXT_KEY_UV,
} ctap_text_key_t;

static int ctap_text_key_error(CborError ret) {
  return -(int)(ret == CborErrorOutOfMemory ? CTAP2_ERR_LIMIT_EXCEEDED : CTAP2_ERR_INVALID_CBOR);
}

static int ctap_text_key_id(CborValue *val) {
  if (cbor_value_get_type(val) != CborTextStringType) return -(int)CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  size_t len;
  CborError ret = cbor_value_get_string_length(val, &len);
  if (ret != CborNoError) return ctap_text_key_error(ret);

  if (len > sizeof("thirdPartyPayment") - 1) {
    ret = cbor_value_advance(val);
    if (ret != CborNoError) return ctap_text_key_error(ret);
    return CTAP_TEXT_KEY_UNKNOWN;
  }

  char key_buf[sizeof("thirdPartyPayment")];
  size_t key_len = sizeof(key_buf);
  ret = ctap_cbor_copy_text(val, key_buf, &key_len);
  if (ret != CborNoError) return ctap_text_key_error(ret);

  int key = CTAP_TEXT_KEY_UNKNOWN;
  switch (len) {
  case 2:
    if (memcmp(key_buf, "id", 2) == 0)
      key = CTAP_TEXT_KEY_ID;
    else if (memcmp(key_buf, "rk", 2) == 0)
      key = CTAP_TEXT_KEY_RK;
    else if (memcmp(key_buf, "up", 2) == 0)
      key = CTAP_TEXT_KEY_UP;
    else if (memcmp(key_buf, "uv", 2) == 0)
      key = CTAP_TEXT_KEY_UV;
    break;
  case 3:
    if (memcmp(key_buf, "alg", 3) == 0) key = CTAP_TEXT_KEY_ALG;
    break;
  case 4:
    if (memcmp(key_buf, "icon", 4) == 0)
      key = CTAP_TEXT_KEY_ICON;
    else if (memcmp(key_buf, "name", 4) == 0)
      key = CTAP_TEXT_KEY_NAME;
    else if (memcmp(key_buf, "type", 4) == 0)
      key = CTAP_TEXT_KEY_TYPE;
    break;
  case 8:
    if (memcmp(key_buf, "credBlob", 8) == 0) key = CTAP_TEXT_KEY_CRED_BLOB;
    break;
  case 11:
    if (memcmp(key_buf, "credProtect", 11) == 0)
      key = CTAP_TEXT_KEY_CRED_PROTECT;
    else if (memcmp(key_buf, "displayName", 11) == 0)
      key = CTAP_TEXT_KEY_DISPLAY_NAME;
    else if (memcmp(key_buf, "hmac-secret", 11) == 0)
      key = CTAP_TEXT_KEY_HMAC_SECRET;
    break;
  case 14:
    if (memcmp(key_buf, "hmac-secret-mc", 14) == 0) key = CTAP_TEXT_KEY_HMAC_SECRET_MC;
    break;
  case 17:
    if (memcmp(key_buf, "thirdPartyPayment", 17) == 0) key = CTAP_TEXT_KEY_THIRD_PARTY_PAYMENT;
    break;
  case 12:
    if (memcmp(key_buf, "largeBlobKey", 12) == 0) key = CTAP_TEXT_KEY_LARGE_BLOB_KEY;
    if (memcmp(key_buf, "minPinLength", 12) == 0) key = CTAP_TEXT_KEY_MIN_PIN_LENGTH;
    break;
  default:
    break;
  }
  return key;
}

static uint8_t ctap_parse_pin_uv_auth_protocol(CborValue *val, uint8_t *out) {
  if (cbor_value_get_type(val) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int tmp;
  int ret = cbor_value_get_int_checked(val, &tmp);
  CHECK_CBOR_RET(ret);
  if (tmp != 1 && tmp != 2) return CTAP1_ERR_INVALID_PARAMETER;
  *out = (uint8_t)tmp;
  ret = cbor_value_advance(val);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t ctap_parse_pin_uv_auth_param(CborValue *val, uint8_t *dst, size_t *len, bool allow_empty) {
  if (cbor_value_get_type(val) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_string_length(val, len);
  CHECK_CBOR_RET(ret);
  if ((!allow_empty && *len == 0) || *len > SHA256_DIGEST_LENGTH) return CTAP2_ERR_PIN_AUTH_INVALID;
  if (*len > 0) {
    ret = ctap_cbor_copy_bytes(val, dst, len);
    CHECK_CBOR_RET(ret);
  } else {
    ret = cbor_value_advance(val);
    CHECK_CBOR_RET(ret);
  }
  return 0;
}

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
  char domain[DOMAIN_NAME_MAX_SIZE + 1];
  size_t map_length, len;

  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    if (key < 0) return (uint8_t)-key;

    if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    if (key == CTAP_TEXT_KEY_ID) {
      len = DOMAIN_NAME_MAX_SIZE;
      ret = ctap_cbor_copy_text(&map, domain, &len);
      CHECK_CBOR_RET(ret);
      domain[len] = 0;
      DBG_MSG("rp_id: %s\n", domain);
      memcpy(mc->rp_id_full, domain, len);
      mc->rp_id_full_len = len;
      maybe_truncate_rpid(mc->rp_id, &mc->rp_id_len, (const uint8_t *)domain, len);
      sha256_raw((uint8_t *)domain, len, mc->rp_id_hash);
    } else {
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

uint8_t parse_user(user_entity *user, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  size_t map_length, len;

  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    if (key < 0) return (uint8_t)-key;

    if (key == CTAP_TEXT_KEY_ID) {
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = USER_ID_MAX_SIZE;
      ret = ctap_cbor_copy_bytes(&map, user->id, &len);
      if (ret == CborErrorOutOfMemory) return CTAP2_ERR_LIMIT_EXCEEDED;
      CHECK_CBOR_RET(ret);
      user->id_size = len;
      DBG_MSG("id: ");
      PRINT_HEX(user->id, len);
    } else if (key == CTAP_TEXT_KEY_DISPLAY_NAME) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = DISPLAY_NAME_LIMIT - 1;
      ret = ctap_cbor_copy_text(&map, (char *)user->display_name, &len);
      CHECK_CBOR_RET(ret);
      user->display_name[len] = 0;
      DBG_MSG("displayName: %s\n", user->display_name);
    } else if (key == CTAP_TEXT_KEY_NAME) {
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = USER_NAME_LIMIT - 1;
      ret = ctap_cbor_copy_text(&map, (char *)user->name, &len);
      CHECK_CBOR_RET(ret);
      user->name[len] = 0;
      DBG_MSG("name: %s\n", user->name);
    } else if (key == CTAP_TEXT_KEY_ICON) {
      // We do not store it
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else {
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t parse_pub_key_cred_param(CborValue *val, int32_t *alg_type) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  char cred[11];
  size_t map_length, len;
  bool found_type = false, found_alg = false, is_public_key = false;
  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    if (key < 0) return (uint8_t)-key;

    if (key == CTAP_TEXT_KEY_TYPE) {
      found_type = true;
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;
      len = sizeof(cred);
      ret = ctap_cbor_copy_text(&map, cred, &len);
      if (ret == CborNoError)
        is_public_key = strcmp(cred, "public-key") == 0;
      else if (ret != CborErrorOutOfMemory)
        CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_ALG) {
      found_alg = true;
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_MISSING_PARAMETER;
      ret = cbor_value_get_int_checked(&map, (int *)alg_type);
      CHECK_CBOR_RET(ret);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else {
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }

  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);

  if (!found_type || !found_alg) return CTAP2_ERR_MISSING_PARAMETER;

  // required by FIDO Conformance Tool
  if (!is_public_key) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
  return 0;
}

uint8_t parse_verify_pub_key_cred_params(CborValue *val, int32_t *alg_type) {
  if (cbor_value_get_type(val) != CborArrayType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue arr;
  size_t arr_length;
  int ret = cbor_value_get_array_length(val, &arr_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &arr);
  CHECK_CBOR_RET(ret);

  int32_t cur_alg_type;
  size_t chosen = arr_length;
  // all elements in array must be examined
  for (size_t i = 0; i < arr_length; ++i) {
    CHECK_CANCELLED_VALUE(&arr);
    ret = parse_pub_key_cred_param(&arr, &cur_alg_type);
    CHECK_PARSER_RET(ret);
    if (ret == 0 && (cur_alg_type == COSE_ALG_ES256 || cur_alg_type == COSE_ALG_EDDSA ||
                     cur_alg_type == COSE_ALG_ML_DSA_65 || cur_alg_type == ctap_sm2_attr.algo_id)) {
      // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential
      //
      // > This sequence is ordered from most preferred (by the RP) to least preferred.

      if (chosen == arr_length) {
        *alg_type = cur_alg_type;
        chosen = i;
      }
    }
  }
  ret = cbor_value_leave_container(val, &arr);
  CHECK_CBOR_RET(ret);
  if (chosen == arr_length) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;

  return 0;
}

uint8_t parse_credential_descriptor(CborValue *arr, uint8_t *id) {
  if (cbor_value_get_type(arr) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  size_t map_length, len;
  bool found_id = false, found_type = false;
  int ret = cbor_value_get_map_length(arr, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(arr, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    if (key < 0) return (uint8_t)-key;

    if (key == CTAP_TEXT_KEY_ID) {
      found_id = true;
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_MISSING_PARAMETER;
      if (id) {
        len = sizeof(credential_id);
        ret = ctap_cbor_copy_bytes(&map, id, &len);
        CHECK_CBOR_RET(ret);
      } else {
        ret = cbor_value_advance(&map);
        CHECK_CBOR_RET(ret);
      }
    } else if (key == CTAP_TEXT_KEY_TYPE) {
      found_type = true;
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_MISSING_PARAMETER;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else {
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }

  ret = cbor_value_leave_container(arr, &map);
  CHECK_CBOR_RET(ret);
  if (!found_id || !found_type) return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

// In this function, we check if the exclude list contains only
// public-key-type credential IDs.
uint8_t parse_public_key_credential_list(CborValue *lst, credential_id *ids, size_t capacity, size_t *count) {
  CborValue arr;
  size_t size;
  if (cbor_value_get_type(lst) != CborArrayType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_array_length(lst, &size);
  CHECK_CBOR_RET(ret);
  if (size > capacity) return CTAP2_ERR_LIMIT_EXCEEDED;
  ret = cbor_value_enter_container(lst, &arr);
  CHECK_CBOR_RET(ret);
  for (size_t i = 0; i < size; ++i) {
    CHECK_CANCELLED_VALUE(&arr);
    ret = parse_credential_descriptor(&arr, ids ? (uint8_t *)&ids[i] : NULL);
    CHECK_PARSER_RET(ret);
  }
  ret = cbor_value_leave_container(lst, &arr);
  CHECK_CBOR_RET(ret);
  if (count) *count = size;
  return 0;
}

uint8_t parse_options(CTAP_options *options, CborValue *val) {
  size_t map_length;
  CborValue map;

  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    bool b;
    if (key < 0) return (uint8_t)-key;
    if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

    if (key == CTAP_TEXT_KEY_RK) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      options->rk = b;
    } else if (key == CTAP_TEXT_KEY_UV) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      options->uv = b;
    } else if (key == CTAP_TEXT_KEY_UP) {
      ret = cbor_value_get_boolean(&map, &b);
      CHECK_CBOR_RET(ret);
      options->up = b;
    } else {
      DBG_MSG("ignoring unknown option\n");
    }
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
  }
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  DBG_MSG("up: %hhu, uv: %hhu, rk: %hhu\n", options->up, options->uv, options->rk);
  return 0;
}

uint8_t parse_cose_key(CborValue *val, uint8_t *public_key) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  size_t map_length, len;
  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  int key;
  uint8_t parsed_keys = 0;
  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
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
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case COSE_KEY_LABEL_KTY:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      if (key != COSE_KEY_KTY_EC2) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case COSE_KEY_LABEL_CRV:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &key);
      CHECK_CBOR_RET(ret);
      if (key != COSE_KEY_CRV_P256) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case COSE_KEY_LABEL_X:
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = PRI_KEY_SIZE;
      ret = ctap_cbor_copy_bytes(&map, public_key, &len);
      CHECK_CBOR_RET(ret);
      if (len != PRI_KEY_SIZE) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    case COSE_KEY_LABEL_Y:
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = PRI_KEY_SIZE;
      ret = ctap_cbor_copy_bytes(&map, public_key + PRI_KEY_SIZE, &len);
      CHECK_CBOR_RET(ret);
      if (len != PRI_KEY_SIZE) return CTAP2_ERR_UNHANDLED_REQUEST;
      ++parsed_keys;
      break;

    default:
      DBG_MSG("Unknown cose key label: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }

  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  DBG_MSG("parsed_keys=%x\n", parsed_keys);
  if (parsed_keys < 4) return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

static uint8_t parse_hmac_secret_params(CborValue *val, CTAP_hmac_secret_ext *ext) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  ext->pin_protocol =
      1; // pinUvAuthProtocol(0x04) is optional only when the selected protocol value is the CTAP2.0 default.
  size_t hmac_map_length, len;
  CborValue hmac_map;
  int tmp;
  int ret = cbor_value_get_map_length(val, &hmac_map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &hmac_map);
  CHECK_CBOR_RET(ret);
  enum {
    HS_MAP_ENTRY_NONE = 0,
    HS_MAP_ENTRY_KEY_AGREEMENT = 0b001,
    HS_MAP_ENTRY_SALT_ENC = 0b010,
    HS_MAP_ENTRY_SALT_AUTH = 0b100,
    HS_MAP_ENTRY_ALL_REQUIRED = 0b111,
  } map_has_entry = HS_MAP_ENTRY_NONE;
  for (size_t j = 0; j < hmac_map_length; ++j) {
    CHECK_CANCELLED_VALUE(&hmac_map);
    if (cbor_value_get_type(&hmac_map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    int hmac_key;
    ret = cbor_value_get_int_checked(&hmac_map, &hmac_key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&hmac_map);
    CHECK_CBOR_RET(ret);
    switch (hmac_key) {
    case GA_REQ_HMAC_SECRET_KEY_AGREEMENT:
      ret = parse_cose_key(&hmac_map, ext->key_agreement);
      CHECK_PARSER_RET(ret);
      map_has_entry |= HS_MAP_ENTRY_KEY_AGREEMENT;
      DBG_MSG("key_agreement: ");
      PRINT_HEX(ext->key_agreement, PUB_KEY_SIZE);
      break;
    case GA_REQ_HMAC_SECRET_SALT_ENC:
      if (cbor_value_get_type(&hmac_map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = sizeof(ext->salt_enc);
      ret = ctap_cbor_copy_bytes(&hmac_map, ext->salt_enc, &len);
      if (ret == CborErrorOutOfMemory) {
        ERR_MSG("ext_hmac_secret_salt_enc is too long\n");
        return CTAP1_ERR_INVALID_LENGTH;
      }
      CHECK_CBOR_RET(ret);
      ext->salt_enc_len = len;
      map_has_entry |= HS_MAP_ENTRY_SALT_ENC;
      DBG_MSG("salt_enc: ");
      PRINT_HEX(ext->salt_enc, ext->salt_enc_len);
      break;
    case GA_REQ_HMAC_SECRET_SALT_AUTH:
      if (cbor_value_get_type(&hmac_map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = sizeof(ext->salt_auth);
      ret = ctap_cbor_copy_bytes(&hmac_map, ext->salt_auth, &len);
      CHECK_CBOR_RET(ret);
      ext->salt_auth_len = len;
      map_has_entry |= HS_MAP_ENTRY_SALT_AUTH;
      DBG_MSG("salt_auth: ");
      PRINT_HEX(ext->salt_auth, ext->salt_auth_len);
      break;
    case GA_REQ_HMAC_SECRET_PIN_PROTOCOL:
      if (cbor_value_get_type(&hmac_map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&hmac_map, &tmp);
      CHECK_CBOR_RET(ret);
      if (tmp != 1 && tmp != 2) return CTAP1_ERR_INVALID_PARAMETER;
      ext->pin_protocol = (uint8_t)tmp;
      DBG_MSG("pin_protocol: %d\n", tmp);
      ret = cbor_value_advance(&hmac_map);
      CHECK_CBOR_RET(ret);
      break;
    default:
      DBG_MSG("Ignoring unsupported entry %0x\n", hmac_key);
      ret = cbor_value_advance(&hmac_map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }
  ret = cbor_value_leave_container(val, &hmac_map);
  CHECK_CBOR_RET(ret);
  if ((map_has_entry & HS_MAP_ENTRY_ALL_REQUIRED) != HS_MAP_ENTRY_ALL_REQUIRED) return CTAP2_ERR_MISSING_PARAMETER;
  if ((ext->pin_protocol == 1 && ext->salt_enc_len != HMAC_SECRET_SALT_SIZE &&
       ext->salt_enc_len != HMAC_SECRET_SALT_SIZE / 2) ||
      (ext->pin_protocol == 2 && ext->salt_enc_len != HMAC_SECRET_SALT_SIZE + HMAC_SECRET_SALT_IV_SIZE &&
       ext->salt_enc_len != HMAC_SECRET_SALT_SIZE / 2 + HMAC_SECRET_SALT_IV_SIZE)) {
    ERR_MSG("Invalid hmac_secret_salt_enc_len %hhu\n", ext->salt_enc_len);
    return CTAP1_ERR_INVALID_LENGTH;
  }
  if ((ext->pin_protocol == 1 && ext->salt_auth_len != HMAC_SECRET_SALT_AUTH_SIZE_P1) ||
      (ext->pin_protocol == 2 && ext->salt_auth_len != HMAC_SECRET_SALT_AUTH_SIZE_P2)) {
    ERR_MSG("Invalid hmac_secret_salt_auth_len %hhu\n", ext->salt_auth_len);
    return CTAP1_ERR_INVALID_LENGTH;
  }
  return 0;
}

uint8_t parse_mc_extensions(CTAP_make_credential *mc, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  size_t map_length, len;
  int tmp;
  bool saw_hmac_secret_mc = false;
  bool saw_hmac_secret = false;

  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    if (key < 0) return (uint8_t)-key;

    if (key == CTAP_TEXT_KEY_CRED_PROTECT) {
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &tmp);
      CHECK_CBOR_RET(ret);
      if (tmp < 1 || tmp > 3) return CTAP2_ERR_INVALID_OPTION;
      mc->ext_cred_protect = tmp;
      DBG_MSG("credProtect: %d\n", tmp);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_CRED_BLOB) {
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      mc->ext_has_cred_blob = 1;
      ret = cbor_value_get_string_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if (len > MAX_CRED_BLOB_LENGTH) {
        ERR_MSG("credBlob is too long\n");
        // use this value to mark that credBlob is too long
        mc->ext_cred_blob_len = MAX_CRED_BLOB_LENGTH + 1;
        ret = cbor_value_advance(&map);
        CHECK_CBOR_RET(ret);
        continue;
      }
      ret = ctap_cbor_copy_bytes(&map, mc->ext_cred_blob, &len);
      if (ret == CborErrorOutOfMemory) {
        ERR_MSG("credBlob is too long\n");
        // use this value to mark that credBlob is too long
        mc->ext_cred_blob_len = MAX_CRED_BLOB_LENGTH + 1;
        ret = cbor_value_advance(&map);
        CHECK_CBOR_RET(ret);
      } else {
        CHECK_CBOR_RET(ret);
        mc->ext_cred_blob_len = len;
        DBG_MSG("credBlob: ");
        PRINT_HEX(mc->ext_cred_blob, len);
      }
    } else if (key == CTAP_TEXT_KEY_LARGE_BLOB_KEY) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &mc->ext_large_blob_key);
      CHECK_CBOR_RET(ret);
      DBG_MSG("largeBlobKey: %d\n", mc->ext_large_blob_key);
      if (!mc->ext_large_blob_key) return CTAP2_ERR_INVALID_OPTION;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_MIN_PIN_LENGTH) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &mc->ext_min_pin_length);
      CHECK_CBOR_RET(ret);
      DBG_MSG("minPinLength: %d\n", mc->ext_min_pin_length);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_THIRD_PARTY_PAYMENT) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &mc->ext_third_party_payment);
      CHECK_CBOR_RET(ret);
      DBG_MSG("thirdPartyPayment: %d\n", mc->ext_third_party_payment);
      if (!mc->ext_third_party_payment) return CTAP2_ERR_INVALID_OPTION;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_HMAC_SECRET) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &mc->ext_hmac_secret);
      CHECK_CBOR_RET(ret);
      saw_hmac_secret = true;
      DBG_MSG("hmac-secret: %d\n", mc->ext_hmac_secret);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_HMAC_SECRET_MC) {
      DBG_MSG("hmac-secret-mc found\n");
      ret = parse_hmac_secret_params(&map, &mc->ext_hmac_secret_data);
      CHECK_PARSER_RET(ret);
      mc->ext_hmac_secret_mc = true;
      saw_hmac_secret_mc = true;
    } else {
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  if (saw_hmac_secret_mc && (!saw_hmac_secret || !mc->ext_hmac_secret)) return CTAP2_ERR_MISSING_PARAMETER;
  return 0;
}

uint8_t parse_ga_extensions(CTAP_get_assertion *ga, CborValue *val) {
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue map;
  size_t map_length;

  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    int key = ctap_text_key_id(&map);
    if (key < 0) return (uint8_t)-key;

    if (key == CTAP_TEXT_KEY_HMAC_SECRET) {
      DBG_MSG("hmac-secret found\n");
      ret = parse_hmac_secret_params(&map, &ga->ext_hmac_secret_data);
      CHECK_PARSER_RET(ret);
      ga->parsed_params |= PARAM_HMAC_SECRET;
    } else if (key == CTAP_TEXT_KEY_CRED_BLOB) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &ga->ext_cred_blob);
      CHECK_CBOR_RET(ret);
      DBG_MSG("credBlob: %d\n", ga->ext_cred_blob);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_LARGE_BLOB_KEY) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &ga->ext_large_blob_key);
      CHECK_CBOR_RET(ret);
      DBG_MSG("largeBlobKey: %d\n", ga->ext_large_blob_key);
      if (!ga->ext_large_blob_key) return CTAP2_ERR_INVALID_OPTION;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else if (key == CTAP_TEXT_KEY_THIRD_PARTY_PAYMENT) {
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &ga->ext_third_party_payment);
      CHECK_CBOR_RET(ret);
      DBG_MSG("thirdPartyPayment: %d\n", ga->ext_third_party_payment);
      if (!ga->ext_third_party_payment) return CTAP2_ERR_INVALID_OPTION;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    } else {
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
    }
  }
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

uint8_t parse_cm_params(CTAP_credential_management *cm, CborValue *val, size_t *total_length) {
  if (total_length) *total_length = 0;
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  size_t map_length, len;
  CborValue map;
  int key;
  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
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
      ret = ctap_cbor_copy_bytes(&map, cm->rp_id_hash, &len);
      CHECK_CBOR_RET(ret);
      cm->parsed_params |= PARAM_RP;
      break;

    case CM_PARAM_CREDENTIAL_ID:
      DBG_MSG("credential_id found\n");
      ret = parse_credential_descriptor(&map, (uint8_t *)&cm->credential_id);
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
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  if ((val->parser->flags & CborParserFlag_ExternalSource) == 0 && total_length != NULL)
    *total_length = map.source.ptr - val->source.ptr;
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t parse_make_credential_impl(CborParser *parser, CTAP_make_credential *mc, const uint8_t *buf, size_t len,
                                          const ctap_req_src_t *src) {
  CborValue it, map;
  ctap_cbor_reader_t reader;
  size_t map_length;
  int key;
  memset(mc, 0, sizeof(CTAP_make_credential));

  // options are absent by default
  mc->options.rk = OPTION_ABSENT;
  mc->options.uv = OPTION_ABSENT;
  mc->options.up = OPTION_ABSENT;

  uint8_t init_ret = src ? ctap_parser_init_src(parser, &it, &reader, src) : ctap_parser_init(parser, &it, buf, len);
  if (init_ret != 0) return init_ret;
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
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
      ret = ctap_cbor_copy_bytes(&map, mc->client_data_hash, &len);
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
      if (mc->alg_type == COSE_ALG_ES256)
        DBG_MSG("EcDSA found\n");
      else if (mc->alg_type == COSE_ALG_EDDSA)
        DBG_MSG("EdDSA found\n");
      else if (mc->alg_type == COSE_ALG_ML_DSA_65)
        DBG_MSG("ML-DSA-65 found\n");
      else if (mc->alg_type == ctap_sm2_attr.algo_id)
        DBG_MSG("SM2 found\n");
      else
        DBG_MSG("Found other algorithm\n");
      mc->parsed_params |= PARAM_PUB_KEY_CRED_PARAMS;
      break;

    case MC_REQ_EXCLUDE_LIST:
      DBG_MSG("exclude_list found\n");
      ret = parse_public_key_credential_list(&map, mc->exclude_list, MAX_CREDENTIAL_COUNT_IN_LIST,
                                             &mc->exclude_list_size);
      CHECK_PARSER_RET(ret);
      DBG_MSG("exclude_list size: %d\n", (int)mc->exclude_list_size);
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
      ret = ctap_parse_pin_uv_auth_param(&map, mc->pin_uv_auth_param, &mc->pin_uv_auth_param_len, true);
      CHECK_PARSER_RET(ret);
      if (mc->pin_uv_auth_param_len > 0) {
        DBG_MSG("pin_uv_auth_param: ");
        PRINT_HEX(mc->pin_uv_auth_param, mc->pin_uv_auth_param_len);
      }
      mc->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
      break;

    case MC_REQ_PIN_PROTOCOL:
      DBG_MSG("pin_uv_auth_protocol found\n");
      ret = ctap_parse_pin_uv_auth_protocol(&map, &mc->pin_uv_auth_protocol);
      if (ret == CTAP1_ERR_INVALID_PARAMETER) {
        DBG_MSG("Unknown pin_uv_auth_protocol\n");
      }
      CHECK_PARSER_RET(ret);
      DBG_MSG("pin_uv_auth_protocol: %d\n", mc->pin_uv_auth_protocol);
      mc->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
      break;

    case MC_REQ_ENTERPRISE_ATTESTATION:
      DBG_MSG("enterpriseAttestation found\n");
      mc->parsed_params |= PARAM_ENTERPRISE_ATTESTATION;
      // TODO: parse enterpriseAttestation
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  ret = cbor_value_leave_container(&it, &map);
  CHECK_CBOR_RET(ret);
  if ((mc->parsed_params & MC_REQUIRED_MASK) != MC_REQUIRED_MASK) {
    DBG_MSG("Missing required params\n");
    return CTAP2_ERR_MISSING_PARAMETER;
  }
  return 0;
}

uint8_t parse_make_credential(CborParser *parser, CTAP_make_credential *mc, const uint8_t *buf, size_t len) {
  return parse_make_credential_impl(parser, mc, buf, len, NULL);
}

uint8_t parse_make_credential_src(CborParser *parser, CTAP_make_credential *mc, const ctap_req_src_t *src, size_t len) {
  return parse_make_credential_impl(parser, mc, NULL, len, src);
}

static uint8_t parse_get_assertion_impl(CborParser *parser, CTAP_get_assertion *ga, const uint8_t *buf, size_t len,
                                        const ctap_req_src_t *src) {
  CborValue it, map;
  ctap_cbor_reader_t reader;
  size_t map_length;
  int key;
  char domain[DOMAIN_NAME_MAX_SIZE];
  memset(ga, 0, sizeof(CTAP_get_assertion));

  // options are absent by default
  ga->options.rk = OPTION_ABSENT;
  ga->options.uv = OPTION_ABSENT;
  ga->options.up = OPTION_ABSENT;

  uint8_t init_ret = src ? ctap_parser_init_src(parser, &it, &reader, src) : ctap_parser_init(parser, &it, buf, len);
  if (init_ret != 0) return init_ret;
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
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
      ret = ctap_cbor_copy_text(&map, domain, &len);
      CHECK_CBOR_RET(ret);
      domain[DOMAIN_NAME_MAX_SIZE - 1] = 0;
      DBG_MSG("rp_id: %s; hash: ", domain);
      sha256_raw((uint8_t *)domain, len, ga->rp_id_hash);
      PRINT_HEX(ga->rp_id_hash, SHA256_DIGEST_LENGTH);
      ga->parsed_params |= PARAM_RP;
      break;

    case GA_REQ_CLIENT_DATA_HASH:
      DBG_MSG("client_data_hash found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = CLIENT_DATA_HASH_SIZE;
      ret = ctap_cbor_copy_bytes(&map, ga->client_data_hash, &len);
      CHECK_CBOR_RET(ret);
      if (len != CLIENT_DATA_HASH_SIZE) return CTAP2_ERR_INVALID_CBOR;
      DBG_MSG("client_data_hash: ");
      PRINT_HEX(ga->client_data_hash, len);
      ga->parsed_params |= PARAM_CLIENT_DATA_HASH;
      break;

    case GA_REQ_ALLOW_LIST:
      DBG_MSG("allow_list found\n");
      ret = parse_public_key_credential_list(&map, ga->allow_list, MAX_CREDENTIAL_COUNT_IN_LIST, &ga->allow_list_size);
      CHECK_PARSER_RET(ret);
      DBG_MSG("allow_list size: %d\n", (int)ga->allow_list_size);
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
      ret = ctap_parse_pin_uv_auth_param(&map, ga->pin_uv_auth_param, &ga->pin_uv_auth_param_len, true);
      CHECK_PARSER_RET(ret);
      if (ga->pin_uv_auth_param_len > 0) {
        DBG_MSG("pin_uv_auth_param: ");
        PRINT_HEX(ga->pin_uv_auth_param, ga->pin_uv_auth_param_len);
      }
      ga->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
      break;

    case GA_REQ_PIN_UV_AUTH_PROTOCOL:
      DBG_MSG("pin_uv_auth_protocol found\n");
      ret = ctap_parse_pin_uv_auth_protocol(&map, &ga->pin_uv_auth_protocol);
      if (ret == CTAP1_ERR_INVALID_PARAMETER) {
        DBG_MSG("Unknown pin_uv_auth_protocol\n");
      }
      CHECK_PARSER_RET(ret);
      DBG_MSG("pin_uv_auth_protocol: %d\n", ga->pin_uv_auth_protocol);
      ga->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  ret = cbor_value_leave_container(&it, &map);
  CHECK_CBOR_RET(ret);
  if ((ga->parsed_params & GA_REQUIRED_MASK) != GA_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;
  return 0;
}

uint8_t parse_get_assertion(CborParser *parser, CTAP_get_assertion *ga, const uint8_t *buf, size_t len) {
  return parse_get_assertion_impl(parser, ga, buf, len, NULL);
}

uint8_t parse_get_assertion_src(CborParser *parser, CTAP_get_assertion *ga, const ctap_req_src_t *src, size_t len) {
  return parse_get_assertion_impl(parser, ga, NULL, len, src);
}

static uint8_t parse_client_pin_impl(CborParser *parser, CTAP_client_pin *cp, const uint8_t *buf, size_t len,
                                     const ctap_req_src_t *src) {
  CborValue it, map;
  ctap_cbor_reader_t reader;
  size_t map_length;
  int key;
  char domain[DOMAIN_NAME_MAX_SIZE + 1];
  memset(cp, 0, sizeof(CTAP_client_pin));

  uint8_t init_ret = src ? ctap_parser_init_src(parser, &it, &reader, src) : ctap_parser_init(parser, &it, buf, len);
  if (init_ret != 0) return init_ret;
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
    case CP_REQ_PIN_UV_AUTH_PROTOCOL:
      DBG_MSG("pinProtocol found\n");
      ret = ctap_parse_pin_uv_auth_protocol(&map, &cp->pin_uv_auth_protocol);
      if (ret == CTAP1_ERR_INVALID_PARAMETER) {
        ERR_MSG("Invalid pinProtocol\n");
      }
      CHECK_PARSER_RET(ret);
      DBG_MSG("pinProtocol: %d\n", cp->pin_uv_auth_protocol);
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
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
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
      ret = ctap_parse_pin_uv_auth_param(&map, cp->pin_uv_auth_param, &len, false);
      CHECK_PARSER_RET(ret);
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
      ret = ctap_cbor_copy_bytes(&map, cp->new_pin_enc, &len);
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
      ret = ctap_cbor_copy_bytes(&map, cp->pin_hash_enc, &len);
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
      if (cp->permissions & CP_PERMISSION_BE) {
        DBG_MSG("Unsupported permissions\n");
        return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
      }
      cp->parsed_params |= PARAM_PERMISSIONS;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case CP_REQ_RP_ID:
      DBG_MSG("rp id found\n");
      if (cbor_value_get_type(&map) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      len = DOMAIN_NAME_MAX_SIZE;
      ret = ctap_cbor_copy_text(&map, domain, &len);
      CHECK_CBOR_RET(ret);
      domain[len] = 0;
      DBG_MSG("rp_id: %s\n", domain);
      sha256_raw((uint8_t *)domain, len, cp->rp_id_hash);
      cp->parsed_params |= PARAM_RP;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  ret = cbor_value_leave_container(&it, &map);
  CHECK_CBOR_RET(ret);
  if ((cp->parsed_params & CP_REQUIRED_MASK) != CP_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_GET_KEY_AGREEMENT && (cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_SET_PIN &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 || (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_NEW_PIN_ENC) == 0 || (cp->parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_CHANGE_PIN &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 || (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_PIN_HASH_ENC) == 0 || (cp->parsed_params & PARAM_NEW_PIN_ENC) == 0 ||
       (cp->parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  if (cp->sub_command == CP_CMD_GET_PIN_TOKEN &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 || (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_PIN_HASH_ENC) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cp->sub_command == CP_CMD_GET_PIN_TOKEN &&
      ((cp->parsed_params & PARAM_PERMISSIONS) != 0 || (cp->parsed_params & PARAM_RP) != 0))
    return CTAP1_ERR_INVALID_PARAMETER;

  if (cp->sub_command == CP_CMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS &&
      ((cp->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0 || (cp->parsed_params & PARAM_KEY_AGREEMENT) == 0 ||
       (cp->parsed_params & PARAM_PIN_HASH_ENC) == 0 || (cp->parsed_params & PARAM_PERMISSIONS) == 0))
    return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t parse_client_pin(CborParser *parser, CTAP_client_pin *cp, const uint8_t *buf, size_t len) {
  return parse_client_pin_impl(parser, cp, buf, len, NULL);
}

uint8_t parse_client_pin_src(CborParser *parser, CTAP_client_pin *cp, const ctap_req_src_t *src, size_t len) {
  return parse_client_pin_impl(parser, cp, NULL, len, src);
}

static uint8_t parse_credential_management_impl(CborParser *parser, CTAP_credential_management *cm, const uint8_t *buf,
                                                size_t len, const ctap_req_src_t *src) {
  CborValue it, map;
  ctap_cbor_reader_t reader;
  size_t map_length;
  int key, tmp;
  memset(cm, 0, sizeof(CTAP_credential_management));

  uint8_t init_ret = src ? ctap_parser_init_src(parser, &it, &reader, src) : ctap_parser_init(parser, &it, buf, len);
  if (init_ret != 0) return init_ret;
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    const size_t value_offset = src ? reader.offset : (size_t)(map.source.ptr - buf);

    switch (key) {
    case CM_REQ_SUB_COMMAND:
      DBG_MSG("sub_command found\n");
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &tmp);
      CHECK_CBOR_RET(ret);
      cm->sub_command = tmp;
      DBG_MSG("sub_command: %d\n", cm->sub_command);
      cm->parsed_params |= PARAM_SUB_COMMAND;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case CM_REQ_SUB_COMMAND_PARAMS:
      DBG_MSG("subCommandParams found\n");
      cm->sub_command_params_offset = (uint32_t)value_offset;
      {
        const size_t start_offset = src ? reader.offset : value_offset;
        ret = parse_cm_params(cm, &map, src ? NULL : &cm->param_len);
        if (src) cm->param_len = reader.offset - start_offset;
      }
      CHECK_CBOR_RET(ret);
      break;

    case CM_REQ_PIN_UV_AUTH_PROTOCOL:
      DBG_MSG("pin_uv_auth_protocol found\n");
      ret = ctap_parse_pin_uv_auth_protocol(&map, &cm->pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      DBG_MSG("pin_uv_auth_protocol: %d\n", cm->pin_uv_auth_protocol);
      cm->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
      break;

    case CM_REQ_PIN_UV_AUTH_PARAM:
      DBG_MSG("pin_uv_auth_param found\n");
      ret = ctap_parse_pin_uv_auth_param(&map, cm->pin_uv_auth_param, &len, false);
      CHECK_PARSER_RET(ret);
      PRINT_HEX(cm->pin_uv_auth_param, len);
      cm->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  ret = cbor_value_leave_container(&it, &map);
  CHECK_CBOR_RET(ret);
  if ((cm->parsed_params & CM_REQUIRED_MASK) != CM_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;

  if ((cm->sub_command == CM_CMD_GET_CREDS_METADATA || cm->sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
       cm->sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN || cm->sub_command == CM_CMD_DELETE_CREDENTIAL ||
       cm->sub_command == CM_CMD_UPDATE_USER_INFORMATION) &&
      (cm->parsed_params & PARAM_PIN_UV_AUTH_PARAM) == 0)
    return CTAP2_ERR_PUAT_REQUIRED; // See Section 6.8.2, 6.8.3, 6.8.4, 6.8.5, 6.8.6
  if ((cm->sub_command == CM_CMD_GET_CREDS_METADATA || cm->sub_command == CM_CMD_ENUMERATE_RPS_BEGIN ||
       cm->sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN || cm->sub_command == CM_CMD_DELETE_CREDENTIAL ||
       cm->sub_command == CM_CMD_UPDATE_USER_INFORMATION) &&
      (cm->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL) == 0)
    return CTAP2_ERR_MISSING_PARAMETER; // See Section 6.8.2, 6.8.3, 6.8.4, 6.8.5, 6.8.6
  if (cm->sub_command == CM_CMD_ENUMERATE_CREDENTIALS_BEGIN && (cm->parsed_params & PARAM_RP) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cm->sub_command == CM_CMD_DELETE_CREDENTIAL && (cm->parsed_params & PARAM_CREDENTIAL_ID) == 0)
    return CTAP2_ERR_MISSING_PARAMETER;
  if (cm->sub_command == CM_CMD_UPDATE_USER_INFORMATION &&
      (cm->parsed_params & (PARAM_USER | PARAM_CREDENTIAL_ID)) != (PARAM_USER | PARAM_CREDENTIAL_ID))
    return CTAP2_ERR_MISSING_PARAMETER;

  return 0;
}

uint8_t parse_credential_management(CborParser *parser, CTAP_credential_management *cm, const uint8_t *buf,
                                    size_t len) {
  return parse_credential_management_impl(parser, cm, buf, len, NULL);
}

uint8_t parse_credential_management_src(CborParser *parser, CTAP_credential_management *cm, const ctap_req_src_t *src,
                                        size_t len) {
  return parse_credential_management_impl(parser, cm, NULL, len, src);
}

static uint8_t parse_config_params(CTAP_config *cfg, CborValue *val, size_t *total_length) {
  if (total_length) *total_length = 0;
  if (cbor_value_get_type(val) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  size_t map_length, len;
  CborValue map, arr;
  int key, tmp;
  int ret = cbor_value_get_map_length(val, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(val, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);

    switch (key) {
    case CONFIG_PARAM_NEW_MIN_PIN_LENGTH:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &tmp);
      CHECK_CBOR_RET(ret);
      if (tmp < 0 || tmp > CTAP_MAX_PIN_LENGTH) return CTAP1_ERR_INVALID_PARAMETER;
      cfg->new_min_pin_length = (uint8_t)tmp;
      cfg->parsed_params |= PARAM_NEW_MIN_PIN_LENGTH;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case CONFIG_PARAM_MIN_PIN_LENGTH_RPIDS:
      if (cbor_value_get_type(&map) != CborArrayType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_array_length(&map, &len);
      CHECK_CBOR_RET(ret);
      if (len > CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH) return CTAP2_ERR_KEY_STORE_FULL;
      cfg->min_pin_rpid_count = (uint8_t)len;
      ret = cbor_value_enter_container(&map, &arr);
      CHECK_CBOR_RET(ret);
      for (size_t j = 0; j < len; ++j) {
        CHECK_CANCELLED_VALUE(&arr);
        if (cbor_value_get_type(&arr) != CborTextStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        size_t rpid_len = DOMAIN_NAME_MAX_SIZE;
        ret = ctap_cbor_copy_text(&arr, cfg->min_pin_rpids[j].id, &rpid_len);
        CHECK_CBOR_RET(ret);
        cfg->min_pin_rpids[j].len = (uint8_t)rpid_len;
      }
      ret = cbor_value_leave_container(&map, &arr);
      CHECK_CBOR_RET(ret);
      cfg->parsed_params |= PARAM_MIN_PIN_LENGTH_RPIDS;
      break;

    case CONFIG_PARAM_FORCE_CHANGE_PIN:
      if (cbor_value_get_type(&map) != CborBooleanType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_boolean(&map, &cfg->force_change_pin);
      CHECK_CBOR_RET(ret);
      cfg->parsed_params |= PARAM_FORCE_CHANGE_PIN;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    default:
      DBG_MSG("Unknown config param: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  if ((val->parser->flags & CborParserFlag_ExternalSource) == 0 && total_length != NULL)
    *total_length = map.source.ptr - val->source.ptr;
  ret = cbor_value_leave_container(val, &map);
  CHECK_CBOR_RET(ret);
  return 0;
}

static uint8_t parse_config_impl(CborParser *parser, CTAP_config *cfg, const uint8_t *buf, size_t len,
                                 const ctap_req_src_t *src) {
  CborValue it, map;
  ctap_cbor_reader_t reader;
  size_t map_length;
  int key, tmp;
  memset(cfg, 0, sizeof(CTAP_config));

  uint8_t init_ret = src ? ctap_parser_init_src(parser, &it, &reader, src) : ctap_parser_init(parser, &it, buf, len);
  if (init_ret != 0) return init_ret;
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    const size_t value_offset = src ? reader.offset : (size_t)(map.source.ptr - buf);

    switch (key) {
    case CONFIG_REQ_SUB_COMMAND:
      if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_int_checked(&map, &tmp);
      CHECK_CBOR_RET(ret);
      if (tmp < 0 || tmp > UINT8_MAX) return CTAP1_ERR_INVALID_PARAMETER;
      cfg->sub_command = (uint8_t)tmp;
      cfg->parsed_params |= PARAM_SUB_COMMAND;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case CONFIG_REQ_SUB_COMMAND_PARAMS:
      cfg->sub_command_params_offset = (uint32_t)value_offset;
      {
        const size_t start_offset = src ? reader.offset : value_offset;
        ret = parse_config_params(cfg, &map, src ? NULL : &cfg->param_len);
        CHECK_PARSER_RET(ret);
        if (src) cfg->param_len = reader.offset - start_offset;
      }
      cfg->parsed_params |= PARAM_SUB_COMMAND_PARAMS;
      break;

    case CONFIG_REQ_PIN_UV_AUTH_PROTOCOL:
      ret = ctap_parse_pin_uv_auth_protocol(&map, &cfg->pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      cfg->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
      break;

    case CONFIG_REQ_PIN_UV_AUTH_PARAM:
      ret = ctap_parse_pin_uv_auth_param(&map, cfg->pin_uv_auth_param, &len, false);
      CHECK_PARSER_RET(ret);
      cfg->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
      break;

    default:
      DBG_MSG("Unknown config key: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  ret = cbor_value_leave_container(&it, &map);
  CHECK_CBOR_RET(ret);
  if ((cfg->parsed_params & CONFIG_REQUIRED_MASK) != CONFIG_REQUIRED_MASK) return CTAP2_ERR_MISSING_PARAMETER;
  return 0;
}

uint8_t parse_config(CborParser *parser, CTAP_config *cfg, const uint8_t *buf, size_t len) {
  return parse_config_impl(parser, cfg, buf, len, NULL);
}

uint8_t parse_config_src(CborParser *parser, CTAP_config *cfg, const ctap_req_src_t *src, size_t len) {
  return parse_config_impl(parser, cfg, NULL, len, src);
}

static uint8_t parse_large_blobs_impl(CborParser *parser, CTAP_large_blobs *lb, const uint8_t *buf, size_t len,
                                      const ctap_req_src_t *src) {
  CborValue it, map;
  ctap_cbor_reader_t reader;
  size_t map_length;
  int key, tmp;
  memset(lb, 0, sizeof(CTAP_large_blobs));

  uint8_t init_ret = src ? ctap_parser_init_src(parser, &it, &reader, src) : ctap_parser_init(parser, &it, buf, len);
  if (init_ret != 0) return init_ret;
  if (cbor_value_get_type(&it) != CborMapType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  int ret = cbor_value_get_map_length(&it, &map_length);
  CHECK_CBOR_RET(ret);
  ret = cbor_value_enter_container(&it, &map);
  CHECK_CBOR_RET(ret);

  for (size_t i = 0; i < map_length; ++i) {
    CHECK_CANCELLED_VALUE(&map);
    if (cbor_value_get_type(&map) != CborIntegerType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    ret = cbor_value_get_int_checked(&map, &key);
    CHECK_CBOR_RET(ret);
    ret = cbor_value_advance(&map);
    CHECK_CBOR_RET(ret);
    const size_t value_offset = src ? reader.offset : (size_t)(map.source.ptr - buf);

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
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case LB_REQ_SET:
      DBG_MSG("set found\n");
      if (cbor_value_get_type(&map) != CborByteStringType) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      ret = cbor_value_get_string_length(&map, &lb->set_len);
      CHECK_CBOR_RET(ret);
      if (lb->set_len > MAX_FRAGMENT_LENGTH) return CTAP1_ERR_INVALID_LENGTH;
      lb->set_offset = (uint32_t)(value_offset + 1);
      if (lb->set_len >= 24) ++lb->set_offset;
      if (lb->set_len >= 256) ++lb->set_offset;
      lb->parsed_params |= PARAM_SET;
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
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
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
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
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;

    case LB_REQ_PIN_UV_AUTH_PROTOCOL:
      DBG_MSG("pin_uv_auth_protocol found\n");
      ret = ctap_parse_pin_uv_auth_protocol(&map, &lb->pin_uv_auth_protocol);
      CHECK_PARSER_RET(ret);
      DBG_MSG("pin_uv_auth_protocol: %d\n", lb->pin_uv_auth_protocol);
      lb->parsed_params |= PARAM_PIN_UV_AUTH_PROTOCOL;
      break;

    case LB_REQ_PIN_UV_AUTH_PARAM:
      DBG_MSG("pin_uv_auth_param found\n");
      ret = ctap_parse_pin_uv_auth_param(&map, lb->pin_uv_auth_param, &len, false);
      CHECK_PARSER_RET(ret);
      lb->parsed_params |= PARAM_PIN_UV_AUTH_PARAM;
      break;

    default:
      DBG_MSG("Unknown key: %d\n", key);
      ret = cbor_value_advance(&map);
      CHECK_CBOR_RET(ret);
      break;
    }
  }

  ret = cbor_value_leave_container(&it, &map);
  CHECK_CBOR_RET(ret);
  if (!(lb->parsed_params & PARAM_OFFSET)) return CTAP1_ERR_INVALID_PARAMETER;
  if (!((lb->parsed_params & PARAM_GET) ^ (lb->parsed_params & PARAM_SET))) return CTAP1_ERR_INVALID_PARAMETER;
  if (lb->parsed_params & PARAM_GET) {
    if (lb->parsed_params & PARAM_LENGTH) return CTAP1_ERR_INVALID_PARAMETER;
    if ((lb->parsed_params & PARAM_PIN_UV_AUTH_PARAM) || (lb->parsed_params & PARAM_PIN_UV_AUTH_PROTOCOL))
      return CTAP1_ERR_INVALID_PARAMETER;
    if (lb->get > MAX_FRAGMENT_LENGTH) return CTAP1_ERR_INVALID_LENGTH;
  }
  if (lb->parsed_params & PARAM_SET) {
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

uint8_t parse_large_blobs(CborParser *parser, CTAP_large_blobs *lb, const uint8_t *buf, size_t len) {
  return parse_large_blobs_impl(parser, lb, buf, len, NULL);
}

uint8_t parse_large_blobs_src(CborParser *parser, CTAP_large_blobs *lb, const ctap_req_src_t *src, size_t len) {
  return parse_large_blobs_impl(parser, lb, NULL, len, src);
}
