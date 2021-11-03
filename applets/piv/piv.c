// SPDX-License-Identifier: Apache-2.0
#include <common.h>
#include <des.h>
#include <ecc.h>
#include <memzero.h>
#include <pin.h>
#include <piv.h>
#include <rand.h>
#include <rsa.h>

// data object path
#define PIV_AUTH_CERT_PATH "piv-pauc"
#define SIG_CERT_PATH "piv-sigc"
#define KEY_MANAGEMENT_CERT_PATH "piv-mntc"
#define CARD_AUTH_CERT_PATH "piv-cauc"
#define CHUID_PATH "piv-chu"
#define CCC_PATH "piv-ccc"

// key path
#define TAG_KEY_ALG 0x00
#define PIV_AUTH_KEY_PATH "piv-pauk"
#define SIG_KEY_PATH "piv-sigk"
#define KEY_MANAGEMENT_KEY_PATH "piv-mntk"
#define CARD_AUTH_KEY_PATH "piv-cauk"
#define CARD_ADMIN_KEY_PATH "piv-admk"

// alg
#define ALG_DEFAULT 0x00
#define ALG_TDEA_3KEY 0x03
#define ALG_RSA_2048 0x07
#define ALG_ECC_256 0x11
#define ALG_ECC_384 0x14
#define TDEA_BLOCK_SIZE 8
#define RSA2048_N_LENGTH 256
#define RSA2048_PQ_LENGTH 128
#define ECC_256_PRI_KEY_SIZE 32
#define ECC_256_PUB_KEY_SIZE 64
#define ECC_384_PRI_KEY_SIZE 48
#define ECC_384_PUB_KEY_SIZE 96

// tags for general auth
#define TAG_WITNESS 0x80
#define TAG_CHALLENGE 0x81
#define TAG_RESPONSE 0x82
#define TAG_EXP 0x85
#define IDX_WITNESS (TAG_WITNESS - 0x80)
#define IDX_CHALLENGE (TAG_CHALLENGE - 0x80)
#define IDX_RESPONSE (TAG_RESPONSE - 0x80)
#define IDX_EXP (TAG_EXP - 0x80)

// offsets for auth
#define OFFSET_AUTH_STATE 0
#define OFFSET_AUTH_KEY_ID 1
#define OFFSET_AUTH_ALGO 2
#define OFFSET_AUTH_CHALLENGE 3
#define LENGTH_CHALLENGE 16
#define LENGTH_AUTH_STATE (5 + LENGTH_CHALLENGE)

// states for auth
#define AUTH_STATE_NONE 0
#define AUTH_STATE_EXTERNAL 1
#define AUTH_STATE_MUTUAL 2

static const uint8_t rid[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t pix[] = {0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
static const uint8_t pin_policy[] = {0x40, 0x10};
static uint8_t auth_ctx[LENGTH_AUTH_STATE];
static uint8_t in_admin_status;

static pin_t pin = {.min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-pin"};
static pin_t puk = {.min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-puk"};

static void authenticate_reset(void) {
  auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;
  auth_ctx[OFFSET_AUTH_KEY_ID] = 0;
  auth_ctx[OFFSET_AUTH_ALGO] = 0;
  memset(auth_ctx + OFFSET_AUTH_CHALLENGE, 0, LENGTH_CHALLENGE);
}

static int create_key(const char *path) {
  if (write_file(path, NULL, 0, 0, 1) < 0) return -1;
  uint8_t alg = 0xFF;
  if (write_attr(path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0) return -1;
  return 0;
}

static int get_input_size(uint8_t alg) {
  switch (alg) {
  case ALG_DEFAULT:
  case ALG_TDEA_3KEY:
    return TDEA_BLOCK_SIZE;
  case ALG_RSA_2048:
    return RSA2048_N_LENGTH;
  case ALG_ECC_256:
    return ECC_256_PRI_KEY_SIZE;
  case ALG_ECC_384:
    return ECC_384_PRI_KEY_SIZE;
  default:
    return 0;
  }
}

void piv_poweroff(void) { in_admin_status = 0; }

int piv_install(uint8_t reset) {
  piv_poweroff();
  if (!reset && get_file_size(PIV_AUTH_CERT_PATH) >= 0) return 0;

  // PIN data
  if (pin_create(&pin, "123456\xFF\xFF", 8, 3) < 0) return -1;
  if (pin_create(&puk, "12345678", 8, 3) < 0) return -1;

  // objects
  if (write_file(PIV_AUTH_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(SIG_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(KEY_MANAGEMENT_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(CARD_AUTH_CERT_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(CCC_PATH, NULL, 0, 0, 1) < 0) return -1;
  if (write_file(CHUID_PATH, NULL, 0, 0, 1) < 0) return -1;

  // keys
  if (create_key(PIV_AUTH_KEY_PATH) < 0) return -1;
  if (create_key(SIG_KEY_PATH) < 0) return -1;
  if (create_key(KEY_MANAGEMENT_KEY_PATH) < 0) return -1;
  if (create_key(CARD_AUTH_KEY_PATH) < 0) return -1;
  if (create_key(CARD_ADMIN_KEY_PATH) < 0) return -1;
  if (write_file(CARD_ADMIN_KEY_PATH,
                 (uint8_t[]){1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}, 0, 24, 1) < 0)
    return -1;
  uint8_t alg = ALG_TDEA_3KEY;
  if (write_attr(CARD_ADMIN_KEY_PATH, TAG_KEY_ALG, &alg, sizeof(alg)) < 0) return -1;

  return 0;
}

static const char *get_object_path_by_tag(uint8_t tag) {
  // Part 1 Table 3 0x5FC1XX
  switch (tag) {
  case 0x01: // X.509 Certificate for Card Authentication
    return CARD_AUTH_CERT_PATH;
  case 0x02: // Card Holder Unique Identifier
    return CHUID_PATH;
  case 0x05: // X.509 Certificate for PIV Authentication
    return PIV_AUTH_CERT_PATH;
  case 0x07: // Card Capability Container
    return CCC_PATH;
  case 0x0A: // X.509 Certificate for Digital Signature
    return SIG_CERT_PATH;
  case 0x0B: // X.509 Certificate for Key Management
    return KEY_MANAGEMENT_CERT_PATH;
  default:
    return NULL;
  }
}

static uint16_t get_capacity_by_tag(uint8_t tag) {
  // Part 1 Table 7 Container Minimum Capacity
  // 5FC1XX
  switch (tag) {
  case 0x01: // X.509 Certificate for Card Authentication
    return 1905;
  case 0x02: // Card Holder Unique Identifier
    return 2916;
  case 0x05: // X.509 Certificate for PIV Authentication
    return 1905;
  case 0x07: // Card Capability Container
    return 287;
  case 0x0A: // X.509 Certificate for Digital Signature
    return 1905;
  case 0x0B: // X.509 Certificate for Key Management
    return 1905;
  default:
    return 0;
  }
}

static int piv_select(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x04 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);

  RDATA[0] = 0x61;
  RDATA[1] = 6 + sizeof(pix) + sizeof(rid);
  RDATA[2] = 0x4F;
  RDATA[3] = sizeof(pix);
  memcpy(RDATA + 4, pix, sizeof(pix));
  RDATA[4 + sizeof(pix)] = 0x79;
  RDATA[5 + sizeof(pix)] = 2 + sizeof(rid);
  RDATA[6 + sizeof(pix)] = 0x4F;
  RDATA[7 + sizeof(pix)] = sizeof(rid);
  memcpy(RDATA + 8 + sizeof(pix), rid, sizeof(rid));
  LL = 8 + sizeof(pix) + sizeof(rid);

  return 0;
}

/*
 * Command Data:
 * ---------------------------------------------
 *   Name     Tag    Value
 * ---------------------------------------------
 * Tag List   5C     Tag to read
 *                   0x7E for Discovery Object
 *                   0x7F61 for BIT, ignore
 *                   0x5FC1xx for others
 * ---------------------------------------------
 */
static int piv_get_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (LC < 2) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x5C) EXCEPT(SW_WRONG_DATA);
  if (DATA[1] + 2 != LC) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[1] == 1) {
    if (DATA[2] != 0x7E) EXCEPT(SW_FILE_NOT_FOUND);
    // For the Discovery Object, the 0x7E template nests two data elements:
    // 1) tag 0x4F contains the AID of the PIV Card Application and
    // 2) tag 0x5F2F lists the PIN Usage Policy.
    RDATA[0] = 0x7E;
    RDATA[1] = 5 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
    RDATA[2] = 0x4F;
    RDATA[3] = sizeof(rid) + sizeof(pix);
    memcpy(RDATA + 4, rid, sizeof(rid));
    memcpy(RDATA + 4 + sizeof(rid), pix, sizeof(pix));
    RDATA[4 + sizeof(rid) + sizeof(pix)] = 0x5F;
    RDATA[5 + sizeof(rid) + sizeof(pix)] = 0x2F;
    RDATA[6 + sizeof(rid) + sizeof(pix)] = sizeof(pin_policy);
    memcpy(RDATA + 7 + sizeof(rid) + sizeof(pix), pin_policy, sizeof(pin_policy));
    LL = 7 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
  } else if (DATA[1] == 3) {
    if (LC != 5 || DATA[2] != 0x5F || DATA[3] != 0xC1) EXCEPT(SW_FILE_NOT_FOUND);
    const char *path = get_object_path_by_tag(DATA[4]);
    if (path == NULL) EXCEPT(SW_FILE_NOT_FOUND);
    int len = read_file(path, RDATA, 0, APDU_BUFFER_SIZE);
    if (len < 0) return -1;
    if (len == 0) EXCEPT(SW_FILE_NOT_FOUND);
    LL = len;
  } else
    EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

static int piv_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 && P1 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (P1 == 0xFF) {
    if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
    pin.is_validated = 0;
    return 0;
  }
  if (LC == 0) {
    if (pin.is_validated) return 0;
    int retries = pin_get_retries(&pin);
    if (retries < 0) return -1;
    EXCEPT(SW_PIN_RETRIES + retries);
  }
  if (LC != 8) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(&pin, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_PIN_RETRIES + ctr);
  return 0;
}

static int piv_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  pin_t *p;
  if (P2 == 0x80)
    p = &pin;
  else if (P2 == 0x81)
    p = &puk;
  else
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(p, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(SW_PIN_RETRIES + ctr);
  err = pin_update(p, DATA + 8, 8);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static int piv_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80) EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16) EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(&puk, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL) return -1;
  if (ctr == 0) EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL) EXCEPT(0x63C0 + ctr);
  err = pin_update(&pin, DATA + 8, 8);
  if (err == PIN_IO_FAIL) return -1;
  if (err == PIN_LENGTH_INVALID) EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static const char *get_key_path(uint8_t id) {
  switch (id) {
  case 0x9A:
    return PIV_AUTH_KEY_PATH;
  case 0x9B:
    return CARD_ADMIN_KEY_PATH;
  case 0x9C:
    return SIG_KEY_PATH;
  case 0x9D:
    return KEY_MANAGEMENT_KEY_PATH;
  case 0x9E:
    return CARD_AUTH_KEY_PATH;
  default:
    return NULL;
  }
}

static int piv_general_authenticate(const CAPDU *capdu, RAPDU *rapdu) {
  if (LC == 0) EXCEPT(SW_WRONG_LENGTH);
  if (*DATA != 0x7C) EXCEPT(SW_WRONG_DATA);

  const char *key_path = get_key_path(P2);
  if (key_path == NULL) EXCEPT(SW_WRONG_P1P2);

  uint8_t alg = ALG_DEFAULT;
  if (read_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0) return -1;
  if (!(P1 == ALG_DEFAULT && alg == ALG_TDEA_3KEY) && alg != P1) EXCEPT(SW_WRONG_P1P2);

  uint16_t length = get_input_size(alg);
  uint16_t pos[6] = {0};
  int16_t len[6] = {0};
  int fail = 0;
  size_t length_size = 0;
  tlv_get_length_safe(DATA + 1, LC - 1, &fail, &length_size);
  if (fail) EXCEPT(SW_WRONG_LENGTH);
  uint16_t dat_pos = 1 + length_size;
  while (dat_pos < LC) {
    uint8_t tag = DATA[dat_pos++];
    if (tag != 0x80 && tag != 0x81 && tag != 0x82 && tag != 0x85) EXCEPT(SW_WRONG_DATA);
    len[tag - 0x80] = tlv_get_length_safe(DATA + dat_pos, LC - dat_pos, &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    dat_pos += length_size;
    pos[tag - 0x80] = dat_pos;
    dat_pos += len[tag - 0x80];
    DBG_MSG("Tag %02X, pos: %d, len: %d\n", tag, pos[tag - 0x80], len[tag - 0x80]);
  }

  //
  // CASE 1 - INTERNAL AUTHENTICATE (Key ID = 9A / 9E)
  // Authenticates the CARD to the CLIENT and is also used for KEY ESTABLISHMENT
  // and DIGITAL SIGNATURES. Documented in SP800-73-4 Part 2 Appendix A.3
  //
  // OR - Signature Generation (Key ID = 9C)
  // Documented in SP800-73-4 Part 2 Appendix A.4
  //
  // OR - KEY ESTABLISHMENT (Key ID = 9D, RSA only)
  // Documented in SP800-73-4 Part 2 Appendix A.5
  //

  // > Client application sends a challenge to the PIV Card Application
  if (pos[IDX_WITNESS] == 0 && pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] > 0 && pos[IDX_RESPONSE] > 0 &&
      len[IDX_RESPONSE] == 0) {
    authenticate_reset();
#ifndef FUZZ
    if (P2 != 0x9E && pin.is_validated == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
    if (P2 == 0x9D) pin.is_validated = 0;

    if (alg == ALG_RSA_2048) {
      if (length != len[IDX_CHALLENGE]) EXCEPT(SW_WRONG_DATA);

      rsa_key_t key;
      if (read_file(key_path, &key, 0, sizeof(rsa_key_t)) < 0) return -1;
      if (rsa_private(&key, DATA + pos[IDX_CHALLENGE], RDATA + 8) < 0) {
        memzero(&key, sizeof(key));
        return -1;
      }
      memzero(&key, sizeof(key));

      RDATA[0] = 0x7C;
      RDATA[1] = 0x82;
      RDATA[2] = HI(length + 4);
      RDATA[3] = LO(length + 4);
      RDATA[4] = TAG_RESPONSE;
      RDATA[5] = 0x82;
      RDATA[6] = HI(length);
      RDATA[7] = LO(length);
      LL = length + 8;
    } else if (alg == ALG_ECC_256 || alg == ALG_ECC_384) {
      if (len[IDX_CHALLENGE] > length) EXCEPT(SW_WRONG_DATA);

      size_t key_len = alg == ALG_ECC_256 ? ECC_256_PRI_KEY_SIZE : ECC_384_PRI_KEY_SIZE;
      ECC_Curve curve = alg == ALG_ECC_256 ? ECC_SECP256R1 : ECC_SECP384R1;
      uint8_t key[key_len], digest[key_len];

      if (read_file(key_path, key, 0, sizeof(key)) < 0) return -1;

      memset(digest, 0, sizeof(digest));
      memcpy(digest + (length - len[IDX_CHALLENGE]), DATA + pos[IDX_CHALLENGE], len[IDX_CHALLENGE]);
      if (ecdsa_sign(curve, key, digest, RDATA + 4) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));

      int sig_len = ecdsa_sig2ansi(key_len, RDATA + 4, RDATA + 4);
      RDATA[0] = 0x7C;
      RDATA[1] = sig_len + 2;
      RDATA[2] = TAG_RESPONSE;
      RDATA[3] = sig_len;
      LL = sig_len + 4;
    } else
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  }

  //
  // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
  // Authenticates the HOST to the CARD
  //

  // > Client application requests a challenge from the PIV Card Application.
  else if (pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] == 0) {
    authenticate_reset();
    in_admin_status = 0;

    if (P2 != 0x9B) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    RDATA[0] = 0x7C;
    RDATA[1] = length + 2;
    RDATA[2] = TAG_CHALLENGE;
    RDATA[3] = length;
    random_buffer(RDATA + 4, length);
    LL = length + 4;

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;
    auth_ctx[OFFSET_AUTH_KEY_ID] = P2;
    auth_ctx[OFFSET_AUTH_ALGO] = alg;

    if (alg == ALG_TDEA_3KEY) {
      uint8_t key[24];
      if (read_file(key_path, key, 0, 24) < 0) return -1;
      if (tdes_enc(RDATA + 4, auth_ctx + OFFSET_AUTH_CHALLENGE, key) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));
    } else {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  //
  // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
  //

  // > Client application requests a challenge from the PIV Card Application.
  else if (pos[IDX_RESPONSE] > 0 && len[IDX_RESPONSE] > 0) {
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL || auth_ctx[OFFSET_AUTH_KEY_ID] != P2 ||
        auth_ctx[OFFSET_AUTH_ALGO] != alg || length != len[IDX_RESPONSE] ||
        memcmp(auth_ctx + OFFSET_AUTH_CHALLENGE, DATA + pos[IDX_RESPONSE], length) != 0) {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    authenticate_reset();
    in_admin_status = 1;
  }

  //
  // CASE 4 - MUTUAL AUTHENTICATE REQUEST
  //

  // > Client application requests a WITNESS from the PIV Card Application.
  else if (pos[IDX_WITNESS] > 0 && len[IDX_WITNESS] == 0) {
    authenticate_reset();
    in_admin_status = 0;

    if (P2 != 0x9B) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
    auth_ctx[OFFSET_AUTH_KEY_ID] = P2;
    auth_ctx[OFFSET_AUTH_ALGO] = alg;
    if (OFFSET_AUTH_CHALLENGE + length > sizeof(auth_ctx)) EXCEPT(SW_WRONG_DATA);
    random_buffer(auth_ctx + OFFSET_AUTH_CHALLENGE, length);

    RDATA[0] = 0x7C;
    RDATA[1] = length + 2;
    RDATA[2] = TAG_WITNESS;
    RDATA[3] = length;
    LL = length + 4;

    if (alg == ALG_TDEA_3KEY) {
      uint8_t key[24];
      if (read_file(key_path, key, 0, 24) < 0) return -1;
      if (tdes_enc(auth_ctx + OFFSET_AUTH_CHALLENGE, RDATA + 4, key) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));
    } else {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }
  }

  //
  // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
  //

  // > Client application returns the decrypted witness referencing the original
  // algorithm key reference
  else if (pos[IDX_WITNESS] > 0 && len[IDX_WITNESS] > 0 && pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] > 0) {
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL || auth_ctx[OFFSET_AUTH_KEY_ID] != P2 ||
        auth_ctx[OFFSET_AUTH_ALGO] != alg || length != len[IDX_WITNESS] ||
        memcmp(auth_ctx + OFFSET_AUTH_CHALLENGE, DATA + pos[IDX_WITNESS], length) != 0) {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (length != len[IDX_CHALLENGE]) {
      authenticate_reset();
      EXCEPT(SW_WRONG_LENGTH);
    }

    RDATA[0] = 0x7C;
    RDATA[1] = length + 2;
    RDATA[2] = TAG_RESPONSE;
    RDATA[3] = length;
    LL = length + 4;

    if (alg == ALG_TDEA_3KEY) {
      uint8_t key[24];
      if (read_file(key_path, key, 0, 24) < 0) return -1;
      if (tdes_enc(DATA + pos[IDX_CHALLENGE], RDATA + 4, key) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));
    } else {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    authenticate_reset();
    in_admin_status = 1;
  }

  //
  // CASE 6 - ECDH with the PIV KMK
  // Documented in SP800-73-4 Part 2 Appendix A.5
  //

  else if (pos[IDX_RESPONSE] > 0 && len[IDX_RESPONSE] == 0 && pos[IDX_EXP] > 0 && len[IDX_EXP] > 0) {
    authenticate_reset();
#ifndef FUZZ
    if (P2 != 0x9D || pin.is_validated == 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
    if (len[IDX_EXP] != 2 * length + 1) EXCEPT(SW_WRONG_DATA);
    if (P2 == 0x9D) pin.is_validated = 0;
    uint8_t key[length];
    if (read_file(key_path, key, 0, length) < 0) return -1;
    ECC_Curve curve = alg == ALG_ECC_256 ? ECC_SECP256R1 : ECC_SECP384R1;
    if (ecdh_decrypt(curve, key, DATA + pos[IDX_EXP] + 1, RDATA + 4) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    RDATA[0] = 0x7C;
    RDATA[1] = length + 2;
    RDATA[2] = TAG_RESPONSE;
    RDATA[3] = length;
    LL = length + 4;
  }

  //
  // INVALID CASE
  //
  else {
    authenticate_reset();
    EXCEPT(SW_WRONG_DATA);
  }

  return 0;
}

static int piv_put_data(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (P1 != 0x3F || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (LC < 5) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x5C) EXCEPT(SW_WRONG_DATA);
  // Part 1 Table 3 0x5FC1XX
  if (DATA[1] != 3 || DATA[2] != 0x5F || DATA[3] != 0xC1) EXCEPT(SW_FILE_NOT_FOUND);
  const char *path = get_object_path_by_tag(DATA[4]);
  DBG_MSG("%s length %d\n", path, LC - 5);
  if (path == NULL) EXCEPT(SW_FILE_NOT_FOUND);
  uint16_t cap = get_capacity_by_tag(DATA[4]);
  if (LC - 5 > cap) EXCEPT(SW_NOT_ENOUGH_SPACE);
  if (write_file(path, DATA + 5, 0, LC - 5, 1) < 0) return -1;
#ifdef DEBUG_OUTPUT
  int len =
#endif
      read_file(path, DATA + 5, 0, LC - 5);
  DBG_MSG("length %d\n", len);
  return 0;
}

static int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (LC < 5) EXCEPT(SW_WRONG_LENGTH);
  if (P1 != 0x00 || (P2 != 0x9A && P2 != 0x9C && P2 != 0x9D && P2 != 0x9E) || DATA[0] != 0xAC || DATA[2] != 0x80 ||
      DATA[3] != 0x01)
    EXCEPT(SW_WRONG_DATA);
  const char *key_path = get_key_path(P2);
  uint8_t alg = DATA[4];
  if (alg == ALG_RSA_2048) {
    rsa_key_t key;
#ifndef FUZZ // to speed up fuzzing
    if (rsa_generate_key(&key, 2048) < 0) return -1;
#else
    memcpy(
        &key,
        "\x00\x08\x00\x00\x00\x01\x00\x01\xD7\x5A\x04\xFF\x4A\x3A\xD8\xCA\x21\x65\xDD\x61\x0C\x3C\x31\x4B\xFB\xC7\x07\x89\x1E\x1D\x05\xD3\xE5\x61\x39\xD5\x00\x2A\xB7\x7C\x5F\x15\x78\xA6\x32\xE3\x52\x9F\xE9\x68\x0C\x8A\x34\x1D\x9E\x6F\x03\x27\x2D\xC1\x86\x20\x90\xD8\x2D\xFE\xCB\xD5\xA8\xC9\x75\x31\xE7\x20\x2B\x5F\x1A\xA9\x4A\x77\xB1\xE5\x23\x8E\x5C\x23\x0F\x30\x0B\x67\x46\x29\xEE\x90\x23\x72\x75\x23\x3A\x5B\x50\x5E\
        \xF0\x7E\x6F\x9D\x07\xAA\x02\x2C\x63\x47\x79\xFB\x32\xAC\x84\xEE\x08\xDA\x13\xA8\xCF\x28\x56\x0E\xCD\x75\xBD\xF1\xF4\x51\xF8\x87\xA5\x99\x87\x96\x4D\xD4\x44\x7F\x00\x00\xF0\xC6\x5F\xD4\x44\x7F\x00\x00\xA0\xB4\x64\xD4\x44\x7F\x00\x01\xD8\xC6\x5F\xD4\x44\x7F\x00\x00\x80\x96\x4D\xD4\x44\x7F\x00\x00\xB8\x7C\x84\xD2\x44\x7F\x01\x00\xC0\xC6\x5F\xD4\x44\x7F\x00\x00\x18\xBC\x64\xD4\x44\x7F\x00\x00\xA8\xC6\x5F\x00\
        \x00\x00\x00\x00\xA0\x5C\x84\xD2\x44\x7F\x00\x00\x49\xE5\x6F\xDD\x44\x7F\x00\x00\xF8\xBB\x64\xD4\x44\x7F\x00\x00\x49\xE5\x6F\xDD\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xF6\x96\xD7\xD3\x44\x7F\x00\x00\xC8\xBB\x64\xD4\x01\x00\x00\x00\xB7\x2E\x83\x4D\xAA\x3C\x94\x00\x01\xC4\xBB\x40\x6C\x4D\x29\x7A\xDB\xE9\xEC\x74\x7E\x15\x07\x68\xC5\x3E\xA9\x70\x60\xA1\x46\x85\x3F\x65\xB1\xE7\x92\x31\xEF\x91\xC9\xA3\
        \x96\xCA\x94\x5A\xF8\x89\xE3\x84\x96\x0A\xE6\x24\x31\xB9\x0D\x77\x17\xD3\x08\x2D\x54\xEE\xC7\x6C\x6E\x46\x7A\xC3\xD0\x6E\x91\x7C\xD5\x21\xBC\x0C\x11\x2E\xEB\x80\xBB\x9C\x4E\x21\x45\x7E\x55\xB8\xD4\x71\xB0\x2D\xFB\xC5\x4F\x65\x94\xD4\x62\x92\x0C\x0D\x59\x6E\xF7\x33\xE4\x03\xA8\x3C\xF3\xFD\xC7\xA3\xB6\xAA\x80\x09\x9D\x22\xC2\xA7\x58\x43\x6A\x7D\x24\x51\x84\xD2\x44\x7F\x00\x01\xC0\xBA\x61\xD4\x44\x7F\x00\x00\
        \x80\x96\x4D\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x68\xBB\x64\xD4\x44\x7F\x00\x00\x52\x00\x00\x00\x06\x00\x00\x01\x40\xBA\x61\xD4\x44\x7F\x00\x00\xE8\xC5\x5F\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x50\xBB\x64\xD4\x44\x7F\x00\x00\xB8\xE2\x63\xD4\x44\x7F\x01\x01\x40\xBA\x61\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\xBA\x61\xD4\x44\x7F\x00\x00\x40\xBB\x64\xD4\x44\x7F\
        \x00\x00\xA0\xE2\x63\xD4\x44\x7F\x00\x01\x00\x05\x00\x00\x44\x7F\x04\x00\xB8\xC5\x5F\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xA0\xC5\x5F\xD4\x44\x7F\x00\x00\x98\xE2\x63\xD4\x44\x7F\x00\x06\x80\x96\x4D\xD4\x44\x7F\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x90\xC5\x5F\xD4\x44\x7F\x00\x00\x24\x51\x84\x00\x06\x00\x00\x00\x70\xC5\x5F\xD4\x44\x7F\x00\x00\x46\x00\x00\x00\x00\x00\x00\x01\xF8\xBA\x64\xD4\
        \x44\x7F\x00\x00\x41\xE5\x6F\xDD\x44\x7F\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xD8\xBA\x64\xD4\x44\x7F\x00\x00\x42\xE5\x6F\xDD\x44\x7F\x00\x01\x50\x51\x5E\xD4\x44\x7F\x00\x00\x58\xC5\x5F\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xC0\xBA\x64\xD4\x44\x7F\x00\x00\x41\xE5\x6F\xDD\x44\x7F\x00\x01\x20\x51\x5E\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\xBA\x61\xD4\x44\x01\x01\x01\xA8\xBA\
        \x64\xD4\x44\x7F\x00\x00\xCC\x02\x00\x00\x00\x00\x00\x01\xC0\xBA\x61\xD4\x44\x7F\x00\x00\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x90\xBA\x64\xD4\x44\x7F\x00\x00\x24\x51\x84\xD2\x44\x7F\x00\x01\x40\xBA\x61\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x01\x00\x01\x04\x30\x01\x00\x00\x44\x7F\x00\x00\x24\x51\x84\xD2\x44\x7F\x00\x01\xF8\xC4\x5F\xD4\x44\x7F\x00\x00\
        \x98\x0F\x64\xD4\x44\x01\x01\x01\x40\xE5\x6F\xDD\x44\x7F\x00\x00\x40\xBA\x61\xD4\x44\x7F\x00\xFF\x40\xE5\x6F\xDD\x44\x7F\x00\x00\xF0\xE4\x6F\xDD\x44\x7F\x00\x00\x37\x00\x00\x00\x00\x00\x00\x00\x87\x96\x4D\xD4\x44\x7F\x00\x00\xE0\xC4\x5F\xD4\x44\x7F\x00\x00\x20\x51\x84\xD2\x44\x7F\x00\x01\xC8\xC4\x5F\xD4\x44\x7F\x00\x00\x80\x96\x4D\xD4\x44\x7F\x00\x00\x01\x00\x00\x00\x7C\x00\x00\x01\xB0\xC4\x5F\xD4\x44\x7F\
        \x00\x00\x4A\x00\x00\x00\x06\x00\x00\x00\x50\x00\x00\x00\x44\x7F\xFF\x00\x98\xC4\x5F\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x80\xC4\x5F\xD4\x44\x7F\x00\x00\xD0\xB2\x64\xD4\x44\x7F\x00\x01\x39\xE5\x6F\xDD\x44\x7F\x00\x00\x28\xE1\x63\xD4\x44\x7F\x00\xFF\x39\xE5\x6F\xDD\x44\x7F\x00\x00\xF0\xE4\x6F\xDD\x44\x7F\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x87\x96\x4D\xD4\x44\x7F\x00\x00\x68\xC4\x5F\xD4\
        \x44\x7F\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x50\xC4\x5F\xD4\x44\x7F\x00\x00\x18\x7C\x84\xD2\x44\x7F\x00\x06\x80\x96\x4D\xD4\x44\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x40\xC4\x5F\xD4\x44\x7F\x00\x00\x40\xBA\x61\x00\x06\x00\x00\x00\x20\xC4\x5F\xD4\x44\x7F\x00\x00\x44\xBA\x61\xD4\x44\x7F\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x39\xE5\x6F\xDD\x44\x7F\x00\x00\xA4\x02\x00\x00\x00\x00\x00\x00\xA5\x02\
        \x00\x00\x00\x00\x00\x00\x3A\xE5\x6F\xDD\x44\x7F\x00\x00\x3A\xE5\x6F\xDD\x44\x7F\x00\x00\x08\xC4\x5F\xD4\x44\x7F\x00\x00\xD8\x0E\x64\xD4\x44\x01\x01\x00\x49\x00\x00\x00\x00\x00\x00\x00\x39\xE5\x6F\xDD\x44\x7F\x00\x00\x88\xB9\x64\xD4\x44\x7F\x00\x00\x39\xE5\x6F\xDD\x44\x7F\x01\x04\xCC\xFC\x0F\x50\x00\x00\x04\x04\xD2\xDC\xD6\x60\x00\x00\x04\x00\x60\xB9\x64\xD4\x44\x7F\x00\x00\xF0\xE4\x6F\xDD\x44\x7F\x00\x01\
        \x36\x87\x84\xD2\x44\x7F\x00\x00\x87\x96\x4D\xD4\x44\x7F\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x48\xB9\x64\xD4\x44\x7F\x00\x00\xD8\xC3\x5F\xD4\x44\x7F\x00\x01\x20\x87\x84\xD2\x44\x7F\x00\x00\xC0\x51\x84\xD2\x44\x7F\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00",
        sizeof(rsa_key_t));
#endif // FUZZ
    if (write_file(key_path, &key, 0, sizeof(key), 1) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    RDATA[0] = 0x7F;
    RDATA[1] = 0x49;
    RDATA[2] = 0x82;
    RDATA[3] = HI(6 + RSA2048_N_LENGTH + E_LENGTH);
    RDATA[4] = LO(6 + RSA2048_N_LENGTH + E_LENGTH);
    RDATA[5] = 0x81; // modulus
    RDATA[6] = 0x82;
    RDATA[7] = HI(RSA2048_N_LENGTH);
    RDATA[8] = LO(RSA2048_N_LENGTH);
    rsa_get_public_key(&key, RDATA + 9);
    RDATA[9 + RSA2048_N_LENGTH] = 0x82; // exponent
    RDATA[10 + RSA2048_N_LENGTH] = E_LENGTH;
    memcpy(RDATA + 11 + RSA2048_N_LENGTH, key.e, E_LENGTH);
    LL = 11 + RSA2048_N_LENGTH + E_LENGTH;
    memzero(&key, sizeof(key));
  } else if (alg == ALG_ECC_256 || alg == ALG_ECC_384) {
    size_t pri_key_len = alg == ALG_ECC_256 ? ECC_256_PRI_KEY_SIZE : ECC_384_PRI_KEY_SIZE;
    size_t pub_key_len = alg == ALG_ECC_256 ? ECC_256_PUB_KEY_SIZE : ECC_384_PUB_KEY_SIZE;
    ECC_Curve curve = alg == ALG_ECC_256 ? ECC_SECP256R1 : ECC_SECP384R1;
    uint8_t key[pri_key_len + pub_key_len];

    if (ecc_generate(curve, key, key + pri_key_len) < 0) return -1;
    if (write_file(key_path, key, 0, sizeof(key), 1) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    RDATA[0] = 0x7F;
    RDATA[1] = 0x49;
    RDATA[2] = pub_key_len + 3;
    RDATA[3] = 0x86;
    RDATA[4] = pub_key_len + 1;
    RDATA[5] = 0x04;
    memcpy(RDATA + 6, key + pri_key_len, pub_key_len);
    LL = pub_key_len + 6;
    memzero(key, sizeof(key));
  } else
    EXCEPT(SW_WRONG_DATA);
  if (write_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0) return -1;
  return 0;
}

static int piv_set_management_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0xFF || P2 != 0xFF) EXCEPT(SW_WRONG_P1P2);
  if (LC != 27) EXCEPT(SW_WRONG_LENGTH);
  if (DATA[0] != 0x03 || DATA[1] != 0x9B || DATA[2] != 24) EXCEPT(SW_WRONG_DATA);
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (write_file(CARD_ADMIN_KEY_PATH, DATA + 3, 0, 24, 1) < 0) return -1;
  return 0;
}

static int piv_reset(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  if (pin_get_retries(&pin) > 0 || pin_get_retries(&puk) > 0) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  piv_install(1);
  return 0;
}

static int piv_import_asymmetric_key(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  const char *key_path = get_key_path(P2);
  if (key_path == NULL) EXCEPT(SW_WRONG_P1P2);
  uint8_t alg = P1;

  switch (alg) {
  case ALG_RSA_2048: {
    if (LC == 0) EXCEPT(SW_WRONG_LENGTH);

    rsa_key_t key;
    memset(&key, 0, sizeof(key));
    key.nbits = 2048;
    key.e[1] = 1;
    key.e[3] = 1;

    int fail;
    size_t length_size;
    uint8_t *p = DATA;

    if ((p - DATA) >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x01) EXCEPT(SW_WRONG_DATA);
    int len = tlv_get_length_safe(p, LC - 1, &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len > RSA2048_PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;
    memcpy(key.p + (RSA2048_PQ_LENGTH - len), p, len);
    p += len;

    if ((p - DATA) >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x02) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len > RSA2048_PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;
    memcpy(key.q + (RSA2048_PQ_LENGTH - len), p, len);
    p += len;

    if ((p - DATA) >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x03) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len > RSA2048_PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;
    memcpy(key.dp + (RSA2048_PQ_LENGTH - len), p, len);
    p += len;

    if ((p - DATA) >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x04) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len > RSA2048_PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;
    memcpy(key.dq + (RSA2048_PQ_LENGTH - len), p, len);
    p += len;

    if ((p - DATA) >= LC) EXCEPT(SW_WRONG_LENGTH);
    if (*p++ != 0x05) EXCEPT(SW_WRONG_DATA);
    len = tlv_get_length_safe(p, LC - (p - DATA), &fail, &length_size);
    if (fail) EXCEPT(SW_WRONG_LENGTH);
    if (len > RSA2048_PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += length_size;
    memcpy(key.qinv + (RSA2048_PQ_LENGTH - len), p, len);

    if (write_file(key_path, &key, 0, sizeof(key), 1) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
    break;
  }

  case ALG_ECC_256:
  case ALG_ECC_384: {
    size_t pri_key_len = alg == ALG_ECC_256 ? ECC_256_PRI_KEY_SIZE : ECC_384_PRI_KEY_SIZE;
    size_t pub_key_len = alg == ALG_ECC_256 ? ECC_256_PUB_KEY_SIZE : ECC_384_PUB_KEY_SIZE;
    ECC_Curve curve = alg == ALG_ECC_256 ? ECC_SECP256R1 : ECC_SECP384R1;
    if (LC < 2 + pri_key_len) EXCEPT(SW_WRONG_LENGTH);

    uint8_t key[pri_key_len + pub_key_len];

    if (DATA[0] != 0x06 || DATA[1] != pri_key_len) EXCEPT(SW_WRONG_DATA);

    memcpy(key, DATA + 2, pri_key_len);

    if (!ecc_verify_private_key(curve, key)) {
      memzero(key, sizeof(key));
      EXCEPT(SW_WRONG_DATA);
    }

    if (ecc_get_public_key(curve, key, key + pri_key_len) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }

    if (write_file(key_path, key, 0, sizeof(key), 1) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }

    memzero(key, sizeof(key));
    break;
  }

  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  if (write_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0) return -1;
  return 0;
}

static int piv_get_version(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  RDATA[0] = 0x05;
  RDATA[1] = 0x00;
  RDATA[2] = 0x00;
  LL = 3;
  return 0;
}

static int piv_get_serial(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00) EXCEPT(SW_WRONG_P1P2);
  if (LC != 0) EXCEPT(SW_WRONG_LENGTH);
  fill_sn(RDATA);
  LL = 4;
  return 0;
}

int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  if (CLA != 0x00) EXCEPT(SW_CLA_NOT_SUPPORTED);

  int ret = 0;
  switch (INS) {
  case PIV_INS_SELECT:
    ret = piv_select(capdu, rapdu);
    break;
  case PIV_INS_GET_DATA:
    ret = piv_get_data(capdu, rapdu);
    break;
  case PIV_INS_VERIFY:
    ret = piv_verify(capdu, rapdu);
    break;
  case PIV_INS_CHANGE_REFERENCE_DATA:
    ret = piv_change_reference_data(capdu, rapdu);
    break;
  case PIV_INS_RESET_RETRY_COUNTER:
    ret = piv_reset_retry_counter(capdu, rapdu);
    break;
  case PIV_INS_GENERAL_AUTHENTICATE:
    ret = piv_general_authenticate(capdu, rapdu);
    break;
  case PIV_INS_PUT_DATA:
    ret = piv_put_data(capdu, rapdu);
    break;
  case PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR:
    ret = piv_generate_asymmetric_key_pair(capdu, rapdu);
    break;
  case PIV_INS_SET_MANAGEMENT_KEY:
    ret = piv_set_management_key(capdu, rapdu);
    break;
  case PIV_INS_RESET:
    ret = piv_reset(capdu, rapdu);
    break;
  case PIV_INS_IMPORT_ASYMMETRIC_KEY:
    ret = piv_import_asymmetric_key(capdu, rapdu);
    break;
  case PIV_INS_GET_VERSION:
    ret = piv_get_version(capdu, rapdu);
    break;
  case PIV_INS_GET_SERIAL:
    ret = piv_get_serial(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }

  if (ret < 0) EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}

// for testing without authentication
#ifdef TEST
void set_admin_status(int status) { in_admin_status = status; }
#endif