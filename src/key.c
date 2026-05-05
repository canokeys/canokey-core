// SPDX-License-Identifier: Apache-2.0
#include "ecc.h"
#include "memzero.h"
#include <common.h>
#include <key.h>

#define KEY_META_ATTR 0xFF
#define CEIL_DIV_SQRT2 0xB504F334
#define MAX_KEY_TEMPLATE_LENGTH 0x16

// TODO: include_length is always TRUE
int ck_encoded_public_key_length(key_type_t type, bool include_length) {
  if (type >= KEY_TYPE_PKC_END) return -1;
  const size_t key_len = PUBLIC_KEY_LENGTH[type];

  switch (type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1:
  case SM2:
    return (include_length ? 1 : 0) + 3 + key_len;

  case SECP521R1:
    return (include_length ? 2 : 0) + 4 + key_len;

  case ED25519:
  case X25519:
    return (include_length ? 1 : 0) + 2 + key_len;

  case RSA2048:
  case RSA3072:
  case RSA4096:
    return (include_length ? 3 : 0) + 6 + key_len + E_LENGTH;

  default:
    return -1;
  }
}

int ck_encode_public_key(ck_key_t *key, uint8_t *buf, bool include_length) {
  int off = 0;
  const size_t key_len = PUBLIC_KEY_LENGTH[key->meta.type];

  switch (key->meta.type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1:
  case SM2:
    if (include_length) {
      buf[off++] = key_len + 3; // tag, length, and 0x04
    }
    buf[off++] = 0x86;
    buf[off++] = key_len + 1; // 0x04
    buf[off++] = 0x04;
    memcpy(&buf[off], key->ecc.pub, key_len);
    off += key_len;
    break;

  case SECP521R1:
    if (include_length) {
      buf[off++] = 0x81;        // Two-byte length
      buf[off++] = key_len + 4; // tag, length (two bytes), and 0x04
    }
    buf[off++] = 0x86;
    buf[off++] = 0x81;        // Two-byte length
    buf[off++] = key_len + 1; // 0x04
    buf[off++] = 0x04;
    memcpy(&buf[off], key->ecc.pub, key_len);
    off += key_len;
    break;

  case ED25519:
  case X25519:
    if (include_length) {
      buf[off++] = key_len + 2; // tag, length
    }
    buf[off++] = 0x86;
    buf[off++] = key_len;
    memcpy(&buf[off], key->ecc.pub, key_len);
    if (key->meta.type == X25519) {
      swap_big_number_endian(&buf[off]); // Public key of x25519 is encoded in little endian
    }
    off += key_len;
    break;

  case RSA2048:
  case RSA3072:
  case RSA4096:
    if (include_length) { // 3-byte length
      buf[off++] = 0x82;
      // 6 = modulus: tag (1), length (3); exponent: tag (1), length (1)
      buf[off++] = HI(6 + key_len + E_LENGTH);
      buf[off++] = LO(6 + key_len + E_LENGTH);
    }
    buf[off++] = 0x81; // modulus
    buf[off++] = 0x82;
    buf[off++] = HI(key_len);
    buf[off++] = LO(key_len);
    if (rsa_get_public_key(&key->rsa, &buf[off]) < 0) {
      DBG_MSG("RSA public key derive failed: type=%u nbits=%u\n", key->meta.type, key->rsa.nbits);
      return -1;
    }
    off += key_len;
    buf[off++] = 0x82; // exponent
    buf[off++] = E_LENGTH;
    memcpy(&buf[off], key->rsa.e, E_LENGTH);
    off += E_LENGTH;
    break;

  default:
    return -1;
  }

  return off;
}

int ck_parse_piv_policies(ck_key_t *key, const uint8_t *buf, size_t buf_len) {
  const uint8_t *end = buf + buf_len;

  while (buf < end) {
    switch (*buf++) {
    case 0xAA:
      DBG_MSG("May have pin policy\n");
      if (buf < end && *buf++ != 0x01) {
        DBG_MSG("Wrong length for pin policy\n");
        return KEY_ERR_LENGTH;
      }
      if (buf < end && (*buf > PIN_POLICY_ALWAYS || *buf < PIN_POLICY_NEVER)) {
        DBG_MSG("Wrong data for pin policy\n");
        return KEY_ERR_DATA;
      }
      key->meta.pin_policy = *buf++;
      break;

    case 0xAB:
      DBG_MSG("May have touch policy\n");
      if (buf < end && *buf++ != 0x01) {
        DBG_MSG("Wrong length for touch policy\n");
        return KEY_ERR_LENGTH;
      }
      if (buf < end && (*buf > TOUCH_POLICY_CACHED || *buf < TOUCH_POLICY_NEVER)) {
        DBG_MSG("Wrong data for touch policy\n");
        return KEY_ERR_DATA;
      }
      key->meta.touch_policy = *buf++;
      break;

    default:
      buf = end;
      break;
    }
  }

  return 0;
}

/*
 * OpenPGP key import wire layout consumed by the streaming parser
 * (ck_parse_openpgp_stream_*) below.
 *
 * RSA:
 * 7F48 xx Cardholder private key template
 *         91 xx e
 *         92 xx p
 *         93 xx q
 *         94 xx qinv
 *         95 xx dp
 *         96 xx dq
 * 5F48 xx Concatenation of key data as defined in DO 7F48
 *
 * ECC:
 * 7F48 xx Cardholder private key template
 *         92 xx private key
 *         99 xx public key (optional)
 * 5F48 xx Concatenation of key data as defined in DO 7F48
 */
enum {
  CK_PGP_STREAM_TAG_7F,
  CK_PGP_STREAM_TAG_48,
  CK_PGP_STREAM_TEMPLATE_LEN,
  CK_PGP_STREAM_TEMPLATE_TAG,
  CK_PGP_STREAM_TEMPLATE_VALUE_LEN,
  CK_PGP_STREAM_TAG_5F,
  CK_PGP_STREAM_TAG_48_2,
  CK_PGP_STREAM_DATA_LEN,
  CK_PGP_STREAM_DATA,
  CK_PGP_STREAM_DONE,
};

static int ck_stream_tlv_len_feed(ck_tlv_len_stream_t *st, uint8_t b, uint16_t *out) {
  if (st->state == 0) {
    if ((b & 0x80) == 0) {
      *out = b;
      return 1;
    }
    st->count = b & 0x7F;
    if (st->count == 0 || st->count > sizeof(st->buf)) return KEY_ERR_LENGTH;
    st->seen = 0;
    st->state = 1;
    return 0;
  }

  st->buf[st->seen++] = b;
  if (st->seen < st->count) return 0;

  uint16_t len = 0;
  for (uint8_t i = 0; i < st->count; ++i)
    len = (len << 8u) | st->buf[i];
  st->state = 0;
  st->count = 0;
  st->seen = 0;
  *out = len;
  return 1;
}

static int ck_openpgp_stream_template_len(ck_openpgp_stream_t *st, ck_key_t *key, uint16_t len) {
  if ((uint32_t)st->processed + len > st->total_len) return KEY_ERR_LENGTH;

  if (st->phase == CK_PGP_STREAM_TEMPLATE_LEN) {
    if (len > MAX_KEY_TEMPLATE_LENGTH) return KEY_ERR_DATA;
    st->template_end = st->processed + len;
    st->comp_idx = 0;
    st->data_len = 0;
    st->phase = CK_PGP_STREAM_TEMPLATE_TAG;
    return 0;
  }

  if (st->phase != CK_PGP_STREAM_TEMPLATE_VALUE_LEN) return KEY_ERR_DATA;

  if (st->rsa) {
    const size_t pri_len = PRIVATE_KEY_LENGTH[key->meta.type];
    const size_t expected_exact[] = {E_LENGTH, pri_len, pri_len, 0, 0, 0};
    if (st->comp_idx >= 6) return KEY_ERR_DATA;
    if (expected_exact[st->comp_idx] > 0 ? len != expected_exact[st->comp_idx] : len > pri_len) return KEY_ERR_DATA;
  } else {
    if (st->comp_idx == 0) {
      if (len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
    } else if (st->comp_idx == 1) {
      if (len > PUBLIC_KEY_LENGTH[key->meta.type] + 1) return KEY_ERR_DATA;
    } else {
      return KEY_ERR_DATA;
    }
  }

  st->comp_len[st->comp_idx++] = len;
  st->data_len += len;
  if (st->processed == st->template_end) {
    if (st->rsa ? st->comp_idx != 6 : st->comp_idx == 0) return KEY_ERR_DATA;
    st->comp_idx = 0;
    st->phase = CK_PGP_STREAM_TAG_5F;
  } else if (st->processed < st->template_end) {
    st->phase = CK_PGP_STREAM_TEMPLATE_TAG;
  } else {
    return KEY_ERR_DATA;
  }
  return 0;
}

static void ck_openpgp_stream_skip_empty_components(ck_openpgp_stream_t *st) {
  while (st->phase == CK_PGP_STREAM_DATA) {
    const uint8_t limit = st->rsa ? 6 : (st->comp_len[1] == 0 ? 1 : 2);
    if (st->comp_idx >= limit) {
      st->phase = CK_PGP_STREAM_DONE;
      return;
    }
    if (st->comp_len[st->comp_idx] != 0) return;
    DBG_MSG("OpenPGP stream skip empty component idx=%u\n", st->comp_idx);
    st->comp_idx++;
  }
}

static int ck_openpgp_stream_copy_data(ck_openpgp_stream_t *st, ck_key_t *key, uint8_t b) {
  ck_openpgp_stream_skip_empty_components(st);
  if (st->phase != CK_PGP_STREAM_DATA) return KEY_ERR_DATA;

  if (st->rsa) {
    const size_t pri_len = PRIVATE_KEY_LENGTH[key->meta.type];
    uint8_t *dests[] = {key->rsa.e, key->rsa.p, key->rsa.q, key->rsa.qinv, key->rsa.dp, key->rsa.dq};
    if (st->comp_idx >= 6) return KEY_ERR_DATA;
    const uint16_t off = st->comp_idx >= 3 ? pri_len - st->comp_len[st->comp_idx] + st->comp_off : st->comp_off;
    const uint16_t limit = st->comp_idx == 0 ? E_LENGTH : pri_len;
    if (off >= limit) {
      DBG_MSG("OpenPGP stream OOB: type=%u idx=%u off=%u limit=%u comp_len=%u comp_off=%u processed=%u\n",
              key->meta.type, st->comp_idx, off, limit, st->comp_len[st->comp_idx], st->comp_off, st->processed);
      return KEY_ERR_DATA;
    }
    if ((st->comp_off & 0x3F) == 0) {
      DBG_MSG("OpenPGP stream copy: type=%u idx=%u off=%u/%u processed=%u\n", key->meta.type, st->comp_idx,
              st->comp_off, st->comp_len[st->comp_idx], st->processed);
    }
    dests[st->comp_idx][off] = b;
  } else {
    if (st->comp_idx == 0) {
      const size_t pri_len = PRIVATE_KEY_LENGTH[key->meta.type];
      const uint16_t off = pri_len - st->comp_len[0] + st->comp_off;
      if (off >= pri_len) {
        DBG_MSG("OpenPGP stream OOB: type=%u idx=%u off=%u limit=%u comp_len=%u comp_off=%u processed=%u\n",
                key->meta.type, st->comp_idx, off, (unsigned)pri_len, st->comp_len[st->comp_idx], st->comp_off,
                st->processed);
        return KEY_ERR_DATA;
      }
      key->ecc.pri[off] = b;
    } else if (st->comp_idx != 1 || st->comp_len[1] == 0) {
      return KEY_ERR_DATA;
    }
  }

  if (++st->comp_off == st->comp_len[st->comp_idx]) {
    st->comp_off = 0;
    st->comp_idx++;
    DBG_MSG("OpenPGP stream component done: type=%u next_idx=%u processed=%u\n", key->meta.type, st->comp_idx,
            st->processed);
    if (st->rsa ? st->comp_idx == 6 : st->comp_idx == (st->comp_len[1] == 0 ? 1 : 2)) {
      st->phase = CK_PGP_STREAM_DONE;
    } else {
      ck_openpgp_stream_skip_empty_components(st);
    }
  }
  return 0;
}

void ck_parse_openpgp_stream_init(ck_openpgp_stream_t *st, ck_key_t *key, size_t total_len) {
  memzero(st, sizeof(*st));
  memzero(key->data, sizeof(rsa_key_t));
  key->meta.origin = KEY_ORIGIN_IMPORTED;
  st->total_len = total_len > UINT16_MAX ? UINT16_MAX : (uint16_t)total_len;
  st->rsa = IS_RSA(key->meta.type);
  if (st->rsa) key->rsa.nbits = PRIVATE_KEY_LENGTH[key->meta.type] * 16;
}

int ck_parse_openpgp_stream_update(ck_openpgp_stream_t *st, ck_key_t *key, const uint8_t *buf, size_t buf_len,
                                   bool final) {
  if (st->total_len > CK_KEY_IMPORT_MAX_LENGTH) return KEY_ERR_LENGTH;
  if (!IS_RSA(key->meta.type) && !IS_ECC(key->meta.type)) return -1;

  for (size_t i = 0; i < buf_len; ++i) {
    if (st->processed >= st->total_len || st->phase == CK_PGP_STREAM_DONE) return KEY_ERR_DATA;
    const uint8_t b = buf[i];
    st->processed++;

    switch (st->phase) {
    case CK_PGP_STREAM_TAG_7F:
      if (b != 0x7F) return KEY_ERR_DATA;
      st->phase = CK_PGP_STREAM_TAG_48;
      break;
    case CK_PGP_STREAM_TAG_48:
      if (b != 0x48) return KEY_ERR_DATA;
      st->phase = CK_PGP_STREAM_TEMPLATE_LEN;
      break;
    case CK_PGP_STREAM_TEMPLATE_LEN:
    case CK_PGP_STREAM_TEMPLATE_VALUE_LEN: {
      uint16_t len;
      int ret = ck_stream_tlv_len_feed(&st->tlv_len, b, &len);
      if (ret < 0) return ret;
      if (ret > 0) {
        ret = ck_openpgp_stream_template_len(st, key, len);
        if (ret < 0) return ret;
        if (ret == 0 && st->phase == CK_PGP_STREAM_TAG_5F) {
          DBG_MSG("OpenPGP stream template done: type=%u lens=%u,%u,%u,%u,%u,%u data_len=%u processed=%u\n",
                  key->meta.type, st->comp_len[0], st->comp_len[1], st->comp_len[2], st->comp_len[3], st->comp_len[4],
                  st->comp_len[5], st->data_len, st->processed);
        }
      }
      break;
    }
    case CK_PGP_STREAM_TEMPLATE_TAG:
      if (st->rsa) {
        static const uint8_t rsa_tags[] = {0x91, 0x92, 0x93, 0x94, 0x95, 0x96};
        if (st->comp_idx >= sizeof(rsa_tags) || b != rsa_tags[st->comp_idx]) return KEY_ERR_DATA;
      } else if ((st->comp_idx == 0 && b != 0x92) || (st->comp_idx == 1 && b != 0x99)) {
        return KEY_ERR_DATA;
      }
      st->phase = CK_PGP_STREAM_TEMPLATE_VALUE_LEN;
      break;
    case CK_PGP_STREAM_TAG_5F:
      if (b != 0x5F) return KEY_ERR_DATA;
      st->phase = CK_PGP_STREAM_TAG_48_2;
      break;
    case CK_PGP_STREAM_TAG_48_2:
      if (b != 0x48) return KEY_ERR_DATA;
      st->phase = CK_PGP_STREAM_DATA_LEN;
      break;
    case CK_PGP_STREAM_DATA_LEN: {
      uint16_t len;
      int ret = ck_stream_tlv_len_feed(&st->tlv_len, b, &len);
      if (ret < 0) return ret;
      if (ret > 0) {
        if (len != st->data_len) return KEY_ERR_DATA;
        st->comp_idx = 0;
        st->comp_off = 0;
        st->phase = CK_PGP_STREAM_DATA;
        DBG_MSG("OpenPGP stream data start: type=%u len=%u processed=%u\n", key->meta.type, len, st->processed);
        ck_openpgp_stream_skip_empty_components(st);
      }
      break;
    }
    case CK_PGP_STREAM_DATA: {
      int ret = ck_openpgp_stream_copy_data(st, key, b);
      if (ret < 0) return ret;
      break;
    }
    default:
      return KEY_ERR_DATA;
    }
  }

  if (!final) return 0;
  if (st->processed != st->total_len || st->phase != CK_PGP_STREAM_DONE) return KEY_ERR_LENGTH;

  if (st->rsa) {
    if (be32toh(*(uint32_t *)key->rsa.p) < CEIL_DIV_SQRT2 || be32toh(*(uint32_t *)key->rsa.q) < CEIL_DIV_SQRT2) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
  } else {
    if (!ecc_verify_private_key(key->meta.type, &key->ecc)) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
    if (ecc_complete_key(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_PROC;
    }
  }
  return 1;
}

enum {
  CK_PIV_STREAM_TAG,
  CK_PIV_STREAM_LEN,
  CK_PIV_STREAM_DATA,
  CK_PIV_STREAM_POLICY_TAG,
  CK_PIV_STREAM_POLICY_LEN,
  CK_PIV_STREAM_POLICY_VALUE,
  CK_PIV_STREAM_IGNORE_REST,
};

void ck_parse_piv_stream_init(ck_piv_stream_t *st, ck_key_t *key) {
  memzero(st, sizeof(*st));
  memzero(key->data, sizeof(rsa_key_t));
  key->meta.origin = KEY_ORIGIN_IMPORTED;
  st->rsa = IS_RSA(key->meta.type);
  if (st->rsa) {
    key->rsa.nbits = PRIVATE_KEY_LENGTH[key->meta.type] * 16;
    *(uint32_t *)key->rsa.e = htobe32(65537);
  }
}

static int ck_piv_stream_finish(ck_piv_stream_t *st, ck_key_t *key) {
  if (st->phase != CK_PIV_STREAM_POLICY_TAG && st->phase != CK_PIV_STREAM_IGNORE_REST) return KEY_ERR_LENGTH;

  if (st->rsa) {
    if (st->comp_idx != 5) return KEY_ERR_LENGTH;
    if (be32toh(*(uint32_t *)key->rsa.p) < CEIL_DIV_SQRT2 || be32toh(*(uint32_t *)key->rsa.q) < CEIL_DIV_SQRT2) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
  } else {
    if (key->meta.type == X25519) swap_big_number_endian(key->ecc.pri);
    if (!ecc_verify_private_key(key->meta.type, &key->ecc)) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
    if (ecc_complete_key(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_PROC;
    }
  }
  return 1;
}

int ck_parse_piv_stream_update(ck_piv_stream_t *st, ck_key_t *key, const uint8_t *buf, size_t buf_len, bool final) {
  if (!IS_RSA(key->meta.type) && !IS_ECC(key->meta.type)) return -1;

  for (size_t i = 0; i < buf_len; ++i) {
    if (++st->processed > CK_KEY_IMPORT_MAX_LENGTH) return KEY_ERR_LENGTH;
    const uint8_t b = buf[i];

    switch (st->phase) {
    case CK_PIV_STREAM_TAG:
      if (st->rsa) {
        if (st->comp_idx >= 5 || b != st->comp_idx + 1) return KEY_ERR_DATA;
      } else if (b != 0x06 && !(key->meta.type == ED25519 && b == 0x07) && !(key->meta.type == X25519 && b == 0x08)) {
        return KEY_ERR_DATA;
      }
      st->phase = CK_PIV_STREAM_LEN;
      break;

    case CK_PIV_STREAM_LEN: {
      uint16_t len;
      int ret = ck_stream_tlv_len_feed(&st->tlv_len, b, &len);
      if (ret < 0) return ret;
      if (ret > 0) {
        if (st->rsa) {
          if (len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
        } else if (len != PRIVATE_KEY_LENGTH[key->meta.type]) {
          return KEY_ERR_LENGTH;
        }
        st->comp_len = len;
        st->comp_off = 0;
        st->phase = CK_PIV_STREAM_DATA;
      }
      break;
    }

    case CK_PIV_STREAM_DATA:
      if (st->rsa) {
        const size_t pri_len = PRIVATE_KEY_LENGTH[key->meta.type];
        uint8_t *dests[] = {key->rsa.p, key->rsa.q, key->rsa.dp, key->rsa.dq, key->rsa.qinv};
        dests[st->comp_idx][pri_len - st->comp_len + st->comp_off] = b;
      } else {
        key->ecc.pri[st->comp_off] = b;
      }
      if (++st->comp_off == st->comp_len) {
        st->comp_off = 0;
        if (st->rsa && ++st->comp_idx < 5)
          st->phase = CK_PIV_STREAM_TAG;
        else
          st->phase = CK_PIV_STREAM_POLICY_TAG;
      }
      break;

    case CK_PIV_STREAM_POLICY_TAG:
      if (b == 0xAA || b == 0xAB) {
        st->policy_tag = b;
        st->phase = CK_PIV_STREAM_POLICY_LEN;
      } else {
        st->phase = CK_PIV_STREAM_IGNORE_REST;
      }
      break;

    case CK_PIV_STREAM_POLICY_LEN:
      if (b != 1) return KEY_ERR_LENGTH;
      st->phase = CK_PIV_STREAM_POLICY_VALUE;
      break;

    case CK_PIV_STREAM_POLICY_VALUE:
      if (st->policy_tag == 0xAA) {
        if (b > PIN_POLICY_ALWAYS || b < PIN_POLICY_NEVER) return KEY_ERR_DATA;
        key->meta.pin_policy = b;
      } else {
        if (b > TOUCH_POLICY_CACHED || b < TOUCH_POLICY_NEVER) return KEY_ERR_DATA;
        key->meta.touch_policy = b;
      }
      st->phase = CK_PIV_STREAM_POLICY_TAG;
      break;

    case CK_PIV_STREAM_IGNORE_REST:
      break;

    default:
      return KEY_ERR_DATA;
    }
  }

  return final ? ck_piv_stream_finish(st, key) : 0;
}

int ck_read_key_metadata(const char *path, key_meta_t *meta) {
  return read_attr(path, KEY_META_ATTR, meta, sizeof(key_meta_t));
}

int ck_write_key_metadata(const char *path, const key_meta_t *meta) {
  return write_attr(path, KEY_META_ATTR, meta, sizeof(key_meta_t));
}

int ck_read_key(const char *path, ck_key_t *key) {
  const int err = ck_read_key_metadata(path, &key->meta);
  if (err < 0) return err;
  return read_file(path, key->data, 0, sizeof(rsa_key_t));
}

int ck_write_key(const char *path, const ck_key_t *key) {
  const int err = write_file(path, key->data, 0, sizeof(rsa_key_t), 1);
  if (err < 0) return err;
  return ck_write_key_metadata(path, &key->meta);
}

int ck_generate_key(ck_key_t *key) {
  key->meta.origin = KEY_ORIGIN_GENERATED;

  if (IS_ECC(key->meta.type)) {
    if (ecc_generate(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return -1;
    }
    return 0;
  } else if (IS_RSA(key->meta.type)) {
    if (rsa_generate_key(&key->rsa, PUBLIC_KEY_LENGTH[key->meta.type] * 8) < 0) {
      memzero(key, sizeof(ck_key_t));
      return -1;
    }
    return 0;
  } else {
    return -1;
  }
}

int ck_sign(const ck_key_t *key, const uint8_t *input, size_t input_len, uint8_t *sig) {
  DBG_MSG("Data: ");
  PRINT_HEX(input, input_len);
  if (IS_ECC(key->meta.type)) {
    DBG_MSG("Private Key: ");
    PRINT_HEX(key->ecc.pri, PRIVATE_KEY_LENGTH[key->meta.type]);
    DBG_MSG("Public Key: ");
    PRINT_HEX(key->ecc.pub, PUBLIC_KEY_LENGTH[key->meta.type]);
    if (ecc_sign(key->meta.type, &key->ecc, input, input_len, sig) < 0) {
      ERR_MSG("ECC signing failed\n");
      DBG_KEY_META(&key->meta);
      return -1;
    }
  } else if (IS_RSA(key->meta.type)) {
    DBG_MSG("Key: ");
    PRINT_HEX(key->rsa.p, PRIVATE_KEY_LENGTH[key->meta.type]);
    PRINT_HEX(key->rsa.q, PRIVATE_KEY_LENGTH[key->meta.type]);
    if (rsa_sign_pkcs_v15(&key->rsa, input, input_len, sig) < 0) {
      ERR_MSG("RSA signing failed\n");
      DBG_KEY_META(&key->meta);
      return -1;
    }
  } else {
    return -1;
  }
  DBG_MSG("Sig: ");
  PRINT_HEX(sig, SIGNATURE_LENGTH[key->meta.type]);
  return SIGNATURE_LENGTH[key->meta.type];
}
