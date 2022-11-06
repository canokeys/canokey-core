// SPDX-License-Identifier: Apache-2.0
#include "ecc.h"
#include "memzero.h"
#include <common.h>
#include <key.h>
#include <memory.h>

#define KEY_META_ATTR 0
#define CEIL_DIV_SQRT2 0xB504F334
#define MAX_KEY_TEMPLATE_LENGTH 0x16

int ck_encode_public_key(const ck_key_t *key, uint8_t *buf, bool include_length) {
  int off = 0;

  switch (key->meta.type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1:
  case SM2:
    if (include_length) {
      buf[off++] = PUBLIC_KEY_LENGTH[key->meta.type] / 2 + 3; // tag, length, and 0x04
    }
    buf[off++] = 0x86;
    buf[off++] = PUBLIC_KEY_LENGTH[key->meta.type] / 2 + 1; // 0x04
    buf[off++] = 0x04;
    memcpy(&buf[off], key->ecc.pub, PUBLIC_KEY_LENGTH[key->meta.type] / 2);
    off += PUBLIC_KEY_LENGTH[key->meta.type] / 2;
    break;

  case ED25519:
  case X25519:
    if (include_length) {
      buf[off++] = PUBLIC_KEY_LENGTH[key->meta.type] + 2; // tag, length
    }
    buf[off++] = 0x86;
    buf[off++] = PUBLIC_KEY_LENGTH[key->meta.type];
    memcpy(&buf[off], key->ecc.pub, PUBLIC_KEY_LENGTH[key->meta.type]);
    if (key->meta.type == X25519) {
      swap_big_number_endian(&buf[off]); // Public key of x25519 is encoded in little endian
    }
    off += PUBLIC_KEY_LENGTH[key->meta.type];
    break;

  case RSA2048:
  case RSA3072:
  case RSA4096:
    if (include_length) { // 3-byte length
      buf[off++] = 0x82;
      // 6 = modulus: tag (1), length (3); exponent: tag (1), length (1)
      buf[off++] = HI(6 + PUBLIC_KEY_LENGTH[key->meta.type] + E_LENGTH);
      buf[off++] = LO(6 + PUBLIC_KEY_LENGTH[key->meta.type] + E_LENGTH);
    }
    buf[off++] = 0x81; // modulus
    buf[off++] = 0x82;
    buf[off++] = HI(PUBLIC_KEY_LENGTH[key->meta.type]);
    buf[off++] = LO(PUBLIC_KEY_LENGTH[key->meta.type]);
    rsa_get_public_key(&key->rsa, &buf[off]);
    off += PUBLIC_KEY_LENGTH[key->meta.type];
    buf[off++] = 0x82; // exponent
    buf[off++] = E_LENGTH;
    memcpy(&buf[off], key->rsa.e, E_LENGTH);
    off += E_LENGTH;
    break;

  case KEY_TYPE_END:
    return -1;
  }

  return off;
}

int ck_parse_piv(key_type_t type, const uint8_t *buf, size_t buf_len, ck_key_t *key) {
  memzero(key, sizeof(ck_key_t));
  key->meta.type = type;
  key->meta.origin = KEY_ORIGIN_IMPORTED;

  switch (type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1:
  case SM2:
  case ED25519:
  case X25519: {
    if (buf_len < PRIVATE_KEY_LENGTH[type] + 2) return KEY_ERR_LENGTH;
    if (buf[0] != 0x06 && buf[1] != PRIVATE_KEY_LENGTH[type]) return KEY_ERR_DATA;
    memcpy(key->ecc.pri, &buf[2], PRIVATE_KEY_LENGTH[type]);
    if (!ecc_verify_private_key(type, &key->ecc)) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
    if (ecc_complete_key(type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_PROC;
    }
    return 0;
  }

  case RSA2048:
  case RSA3072:
  case RSA4096: {
    int fail, len;
    size_t length_size;
    const uint8_t *p = buf;

    key->rsa.nbits = PRIVATE_KEY_LENGTH[type] * 16;
    *(uint32_t *)key->rsa.e = 65537;

    if (*p++ != 0x01) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len > PRIVATE_KEY_LENGTH[type]) return KEY_ERR_DATA;
    p += length_size;
    memcpy(key->rsa.p + (PRIVATE_KEY_LENGTH[type] - len), p, len);
    p += len;

    if ((p - buf) >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x02) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len > PRIVATE_KEY_LENGTH[type]) return KEY_ERR_DATA;
    p += length_size;
    memcpy(key->rsa.q + (PRIVATE_KEY_LENGTH[type] - len), p, len);
    p += len;

    if ((p - buf) >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x03) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len > PRIVATE_KEY_LENGTH[type]) return KEY_ERR_DATA;
    p += length_size;
    memcpy(key->rsa.dp + (PRIVATE_KEY_LENGTH[type] - len), p, len);
    p += len;

    if ((p - buf) >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x04) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len > PRIVATE_KEY_LENGTH[type]) return KEY_ERR_DATA;
    p += length_size;
    memcpy(key->rsa.dq + (PRIVATE_KEY_LENGTH[type] - len), p, len);
    p += len;

    if ((p - buf) >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x05) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len > PRIVATE_KEY_LENGTH[type]) return KEY_ERR_DATA;
    p += length_size;
    memcpy(key->rsa.qinv + (PRIVATE_KEY_LENGTH[type] - len), p, len);

    if (*(uint32_t *)key->rsa.p < CEIL_DIV_SQRT2 || *(uint32_t *)key->rsa.q < CEIL_DIV_SQRT2) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }

    return 0;
  }

  default:
    return -1;
  }
}

/*
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
int ck_parse_openpgp(ck_key_t *key, const uint8_t *buf, size_t buf_len) {
  memzero(key, sizeof(ck_key_t));
  key->meta.origin = KEY_ORIGIN_IMPORTED;

  const uint8_t *p = buf;
  int fail, len;
  size_t length_size;

  // Cardholder private key template
  if (p + 2 - buf >= buf_len) return KEY_ERR_LENGTH;
  if (*p++ != 0x7F || *p++ != 0x48) return KEY_ERR_DATA;
  len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
  if (fail) return KEY_ERR_LENGTH;
  if (len > MAX_KEY_TEMPLATE_LENGTH) return KEY_ERR_DATA;
  p += length_size;
  const uint8_t *data_tag = p + len; // saved for tag 5F48

  switch (key->meta.type) {
  case SECP256R1:
  case SECP256K1:
  case SECP384R1:
  case SM2:
  case ED25519:
  case X25519: {
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x92) return KEY_ERR_DATA;
    int data_pri_key_len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (data_pri_key_len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
    p += length_size;

    int data_pub_key_len = 0; // this is optional
    if (p < data_tag) {
      if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
      if (*p++ == 0x99) {
        data_pub_key_len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
        if (fail) return KEY_ERR_LENGTH;
        if (data_pub_key_len > PUBLIC_KEY_LENGTH[key->meta.type] + 1) return KEY_ERR_DATA;
      }
    }

    // Concatenation of key data
    p = data_tag;
    if (p + 2 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x5F || *p++ != 0x48) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail || len != data_pri_key_len + data_pub_key_len) return KEY_ERR_DATA;
    p += length_size;
    int n_leading_zeros = PRIVATE_KEY_LENGTH[key->meta.type] - data_pri_key_len;
    if (p + data_pri_key_len - buf > buf_len) return KEY_ERR_LENGTH;
    memcpy(key->ecc.pri + n_leading_zeros, p, data_pri_key_len);

    if (!ecc_verify_private_key(key->meta.type, &key->ecc)) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }
    if (ecc_complete_key(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_PROC;
    }

    return 0;
  }

  case RSA2048:
  case RSA3072:
  case RSA4096: {
    int qinv_len, dp_len, dq_len;

    // 0x91: e
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x91) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len != E_LENGTH) return KEY_ERR_DATA;
    p += length_size;

    // 0x92: p
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x92) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len != PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
    p += length_size;

    // 0x93: q
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x93) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len != PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
    p += length_size;

    // 0x94: qinv, may be less than p/q's length
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x94) return KEY_ERR_DATA;
    qinv_len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (qinv_len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
    p += length_size;

    // 0x94: dp, may be less than p/q's length
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x95) return KEY_ERR_DATA;
    dp_len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (dp_len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;
    p += length_size;

    // 0x94: dq, may be less than p/q's length
    if (p + 1 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x96) return KEY_ERR_DATA;
    dq_len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (dq_len > PRIVATE_KEY_LENGTH[key->meta.type]) return KEY_ERR_DATA;

    // Concatenation of key data
    p = data_tag;
    if (p + 2 - buf >= buf_len) return KEY_ERR_LENGTH;
    if (*p++ != 0x5F || *p++ != 0x48) return KEY_ERR_DATA;
    len = tlv_get_length_safe(p, buf_len - (p - buf), &fail, &length_size);
    if (fail) return KEY_ERR_LENGTH;
    if (len != PRIVATE_KEY_LENGTH[key->meta.type] * 2 + qinv_len + dp_len + dq_len + E_LENGTH) return KEY_ERR_DATA;
    p += length_size;

    if (p + len - buf > buf_len) return KEY_ERR_LENGTH;
    key->rsa.nbits = PRIVATE_KEY_LENGTH[key->meta.type] * 16;
    memcpy(key->rsa.e, p, E_LENGTH);
    p += E_LENGTH;
    memcpy(key->rsa.p, p, PRIVATE_KEY_LENGTH[key->meta.type]);
    p += PRIVATE_KEY_LENGTH[key->meta.type];
    memcpy(key->rsa.q, p, PRIVATE_KEY_LENGTH[key->meta.type]);
    p += PRIVATE_KEY_LENGTH[key->meta.type];
    memcpy(key->rsa.qinv + PRIVATE_KEY_LENGTH[key->meta.type] - qinv_len, p, qinv_len);
    p += qinv_len;
    memcpy(key->rsa.dp + PRIVATE_KEY_LENGTH[key->meta.type] - dp_len, p, dp_len);
    p += dp_len;
    memcpy(key->rsa.dq + PRIVATE_KEY_LENGTH[key->meta.type] - dq_len, p, dq_len);
    if (*(uint32_t *)key->rsa.p < CEIL_DIV_SQRT2 || *(uint32_t *)key->rsa.q < CEIL_DIV_SQRT2) {
      memzero(key, sizeof(ck_key_t));
      return KEY_ERR_DATA;
    }

    return 0;
  }

  default:
    return -1;
  }
}

int ck_read_key_metadata(const char *path, key_meta_t *key) {
  return read_attr(path, KEY_META_ATTR, key, sizeof(key_meta_t));
}

int ck_write_key_metadata(const char *path, const key_meta_t *key) {
  return write_attr(path, KEY_META_ATTR, key, sizeof(key_meta_t));
}

int ck_read_key(const char *path, ck_key_t *key) {
  int err = ck_read_key_metadata(path, &key->meta);
  if (err < 0) return err;
  return read_file(path, key->data, 0, sizeof(ck_key_t));
}

int ck_write_key(const char *path, const ck_key_t *key) {
  int err = ck_write_key_metadata(path, &key->meta);
  if (err < 0) return err;
  return write_file(path, key->data, 0, sizeof(ck_key_t), 1);
}

int ck_generate_key(ck_key_t *key) {
  key->meta.origin = KEY_ORIGIN_IMPORTED;

  if (IS_ECC(key->meta.type)) {
    if (ecc_generate(key->meta.type, &key->ecc) < 0) {
      memzero(key, sizeof(ck_key_t));
      return -1;
    }
    return 0;
  } else {
    if (rsa_generate_key(&key->rsa, PUBLIC_KEY_LENGTH[key->meta.type] * 8) < 0) {
      memzero(key, sizeof(ck_key_t));
      return -1;
    }
    return 0;
  }
}

int ck_sign(const ck_key_t *key, const uint8_t *input, size_t input_len, uint8_t *sig) {
  if (IS_ECC(key->meta.type)) {
    if (ecc_sign(key->meta.type, &key->ecc, input, sig) < 0) return -1;
  } else {
    if (rsa_sign_pkcs_v15(&key->rsa, input, input_len, sig) < 0) return -1;
  }
  return SIGNATURE_LENGTH[key->meta.type];
}
