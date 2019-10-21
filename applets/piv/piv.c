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
#define TDEA_BLOCK_SIZE 8

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
    return N_LENGTH;
  case ALG_ECC_256:
    return ECC_KEY_SIZE;
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
  if (*DATA != 0x7C) EXCEPT(SW_WRONG_DATA);

  const char *key_path = get_key_path(P2);
  if (key_path == NULL) EXCEPT(SW_WRONG_P1P2);

  uint8_t alg;
  if (read_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0) return -1;
  if (!(P1 == ALG_DEFAULT && alg == ALG_TDEA_3KEY) && alg != P1) EXCEPT(SW_WRONG_P1P2);

  uint16_t length = get_input_size(alg);
  uint16_t pos[6] = {0};
  int16_t len[6] = {0};
  uint16_t dat_len = tlv_get_length(DATA + 1);
  uint16_t dat_pos = 1 + tlv_length_size(dat_len);
  while (dat_pos < LC) {
    uint8_t tag = DATA[dat_pos++];
    if (tag != 0x80 && tag != 0x81 && tag != 0x82 && tag != 0x85) EXCEPT(SW_WRONG_DATA);
    len[tag - 0x80] = tlv_get_length(DATA + dat_pos);
    dat_pos += tlv_length_size(len[tag - 0x80]);
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
    if (length != len[IDX_CHALLENGE]) EXCEPT(SW_WRONG_DATA);
    if (P2 == 0x9D) pin.is_validated = 0;

    if (alg == ALG_RSA_2048) {
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
    } else if (alg == ALG_ECC_256) {
      uint8_t key[ECC_KEY_SIZE];
      if (read_file(key_path, key, 0, sizeof(key)) < 0) return -1;
      if (ecdsa_sign(ECC_SECP256R1, key, DATA + pos[IDX_CHALLENGE], RDATA + 4) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));

      int sig_len = ecdsa_sig2ansi(RDATA + 4, RDATA + 4);
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
    if (len[IDX_EXP] != 2 * ECC_KEY_SIZE + 1) EXCEPT(SW_WRONG_DATA);
    if (P2 == 0x9D) pin.is_validated = 0;
    uint8_t key[ECC_KEY_SIZE];
    if (read_file(key_path, key, 0, ECC_KEY_SIZE) < 0) return -1;
    if (ecdh_decrypt(ECC_SECP256R1, key, DATA + pos[IDX_EXP] + 1, RDATA + 4) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    RDATA[0] = 0x7C;
    RDATA[1] = ECC_KEY_SIZE + 2;
    RDATA[2] = TAG_RESPONSE;
    RDATA[3] = ECC_KEY_SIZE;
    LL = ECC_KEY_SIZE + 4;
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
  if (DATA[0] != 0x5C) EXCEPT(SW_WRONG_DATA);
  if (DATA[1] != 3 || DATA[2] != 0x5F || DATA[3] != 0xC1) EXCEPT(SW_FILE_NOT_FOUND);
  const char *path = get_object_path_by_tag(DATA[4]);
  DBG_MSG("%s length %d\n", path, LC - 5);
  if (path == NULL) EXCEPT(SW_FILE_NOT_FOUND);
  if (write_file(path, DATA + 5, 0, LC - 5, 1) < 0) return -1;
  int len = read_file(path, DATA + 5, 0, LC - 5);
  DBG_MSG("length %d\n", len);
  return 0;
}

static int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
#ifndef FUZZ
  if (!in_admin_status) EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
#endif
  if (P1 != 0x00 || (P2 != 0x9A && P2 != 0x9C && P2 != 0x9D && P2 != 0x9E) || DATA[0] != 0xAC || DATA[2] != 0x80 ||
      DATA[3] != 0x01)
    EXCEPT(SW_WRONG_DATA);
  const char *key_path = get_key_path(P2);
  uint8_t alg = DATA[4];
  if (alg == ALG_RSA_2048) {
    rsa_key_t key;
    if (rsa_generate_key(&key) < 0) return -1;
    if (write_file(key_path, &key, 0, sizeof(key), 1) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    RDATA[0] = 0x7F;
    RDATA[1] = 0x49;
    RDATA[2] = 0x82;
    RDATA[3] = HI(6 + N_LENGTH + E_LENGTH);
    RDATA[4] = LO(6 + N_LENGTH + E_LENGTH);
    RDATA[5] = 0x81; // modulus
    RDATA[6] = 0x82;
    RDATA[7] = HI(N_LENGTH);
    RDATA[8] = LO(N_LENGTH);
    memcpy(RDATA + 9, key.n, N_LENGTH);
    RDATA[9 + N_LENGTH] = 0x82; // exponent
    RDATA[10 + N_LENGTH] = E_LENGTH;
    memcpy(RDATA + 11 + N_LENGTH, key.e, E_LENGTH);
    LL = 11 + N_LENGTH + E_LENGTH;
    memzero(&key, sizeof(key));
  } else if (alg == ALG_ECC_256) {
    uint8_t key[ECC_KEY_SIZE + ECC_PUB_KEY_SIZE];
    if (ecc_generate(ECC_SECP256R1, key, key + ECC_KEY_SIZE) < 0) return -1;
    if (write_file(key_path, key, 0, sizeof(key), 1) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    RDATA[0] = 0x7F;
    RDATA[1] = 0x49;
    RDATA[2] = ECC_PUB_KEY_SIZE + 3;
    RDATA[3] = 0x86;
    RDATA[4] = ECC_PUB_KEY_SIZE + 1;
    RDATA[5] = 0x04;
    memcpy(RDATA + 6, key + ECC_KEY_SIZE, ECC_PUB_KEY_SIZE);
    LL = ECC_PUB_KEY_SIZE + 6;
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
    rsa_key_t key;
    memset(&key, 0, sizeof(key));
    key.e[1] = 1;
    key.e[3] = 1;
    uint8_t *p = DATA;
    if (*p++ != 0x01) EXCEPT(SW_WRONG_DATA);
    int p_len = tlv_get_length(p);
    if (p_len > PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(p_len);
    memcpy(key.p + (PQ_LENGTH - p_len), p, p_len);
    p += p_len;
    if (*p++ != 0x02) EXCEPT(SW_WRONG_DATA);
    int q_len = tlv_get_length(p);
    if (q_len > PQ_LENGTH) EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(q_len);
    memcpy(key.q + (PQ_LENGTH - q_len), p, q_len);
    if (rsa_complete_key(&key) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    if (write_file(key_path, &key, 0, sizeof(key), 1) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
    break;
  }
  case ALG_ECC_256: {
    uint8_t key[ECC_KEY_SIZE + ECC_PUB_KEY_SIZE];
    if (DATA[0] != 0x06 || DATA[1] != ECC_KEY_SIZE) EXCEPT(SW_WRONG_DATA);
    memcpy(key, DATA + 2, ECC_KEY_SIZE);
    if (!ecc_verify_private_key(ECC_SECP256R1, key)) {
      memzero(key, sizeof(key));
      EXCEPT(SW_WRONG_DATA);
    }
    if (ecc_get_public_key(ECC_SECP256R1, key, key + ECC_KEY_SIZE) < 0) {
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
