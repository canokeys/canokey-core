#include <common.h>
#include <des.h>
#include <ecc.h>
#include <memzero.h>
#include <pin.h>
#include <piv.h>
#include <rand.h>
#include <rsa.h>

#define MAX_BUFFER_SIZE 2000

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

// states for chaining
#define CHAINING_STATE_NORMAL 0
#define CHAINING_STATE_LONG_RESPONSE 1
#define CHAINING_STATE_CHAINING 2

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
static uint8_t *buffer;
static uint16_t buffer_pos, buffer_len, buffer_cap;
static uint8_t state, state_ins, state_p1, state_p2;
static uint8_t auth_ctx[LENGTH_AUTH_STATE];
static uint8_t in_admin_status;

static pin_t pin = {
    .min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-pin"};
static pin_t puk = {
    .min_length = 8, .max_length = 8, .is_validated = 0, .path = "piv-puk"};

static void authenticate_reset(void) {
  auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_NONE;
  auth_ctx[OFFSET_AUTH_KEY_ID] = 0;
  auth_ctx[OFFSET_AUTH_ALGO] = 0;
  memset(auth_ctx + OFFSET_AUTH_CHALLENGE, 0, LENGTH_CHALLENGE);
}

static int create_key(const char *path) {
  if (write_file(path, NULL, 0) < 0)
    return -1;
  uint8_t alg = 0xFF;
  if (write_attr(path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0)
    return -1;
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

int piv_install(uint8_t reset) {
  state = CHAINING_STATE_NORMAL;

  if (!reset && get_file_size(PIV_AUTH_CERT_PATH) >= 0)
    return 0;

  // PIN data
  if (pin_create(&pin, "123456\xFF\xFF", 8, 3) < 0)
    return -1;
  if (pin_create(&puk, "12345678", 8, 3) < 0)
    return -1;

  // objects
  if (write_file(PIV_AUTH_CERT_PATH, NULL, 0) < 0)
    return -1;
  if (write_file(SIG_CERT_PATH, NULL, 0) < 0)
    return -1;
  if (write_file(KEY_MANAGEMENT_CERT_PATH, NULL, 0) < 0)
    return -1;
  if (write_file(CARD_AUTH_CERT_PATH, NULL, 0) < 0)
    return -1;
  if (write_file(CCC_PATH, NULL, 0) < 0)
    return -1;
  if (write_file(CHUID_PATH, NULL, 0) < 0)
    return -1;

  // keys
  if (create_key(PIV_AUTH_KEY_PATH) < 0)
    return -1;
  if (create_key(SIG_KEY_PATH) < 0)
    return -1;
  if (create_key(KEY_MANAGEMENT_KEY_PATH) < 0)
    return -1;
  if (create_key(CARD_AUTH_KEY_PATH) < 0)
    return -1;
  if (create_key(CARD_ADMIN_KEY_PATH) < 0)
    return -1;
  if (write_file(CARD_ADMIN_KEY_PATH,
                 (uint8_t[]){1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                             5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8},
                 24) < 0)
    return -1;
  uint8_t alg = ALG_TDEA_3KEY;
  if (write_attr(CARD_ADMIN_KEY_PATH, TAG_KEY_ALG, &alg, sizeof(alg)) < 0)
    return -1;

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

static void send_response(RAPDU *rapdu, uint16_t le) {
  uint32_t to_send = buffer_len - buffer_pos;
  if (to_send > le)
    to_send = le;
  memcpy(RDATA, buffer + buffer_pos, to_send);
  buffer_pos += to_send;
  LL = to_send;
  if (buffer_pos < buffer_len) {
    state = CHAINING_STATE_LONG_RESPONSE;
    if (buffer_len - buffer_pos > 0xFF)
      SW = 0x61FF;
    else
      SW = 0x6100 + (buffer_len - buffer_pos);
  }
}

static int piv_select(const CAPDU *capdu, RAPDU *rapdu) {
  state = CHAINING_STATE_NORMAL;
  in_admin_status = 0;

  buffer[0] = 0x61;
  buffer[1] = 6 + sizeof(pix) + sizeof(rid);
  buffer[2] = 0x4F;
  buffer[3] = sizeof(pix);
  memcpy(buffer + 4, pix, sizeof(pix));
  buffer[4 + sizeof(pix)] = 0x79;
  buffer[5 + sizeof(pix)] = 2 + sizeof(rid);
  buffer[6 + sizeof(pix)] = 0x4F;
  buffer[7 + sizeof(pix)] = sizeof(rid);
  memcpy(buffer + 8 + sizeof(pix), rid, sizeof(rid));
  buffer_len = 8 + sizeof(pix) + sizeof(rid);
  send_response(rapdu, LE);

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
  if (P1 != 0x3F || P2 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (DATA[0] != 0x5C)
    EXCEPT(SW_WRONG_DATA);
  if (DATA[1] + 2 != LC)
    EXCEPT(SW_WRONG_LENGTH);
  if (DATA[1] == 1) {
    if (DATA[2] != 0x7E)
      EXCEPT(SW_FILE_NOT_FOUND);
    // For the Discovery Object, the 0x7E template nests two data elements:
    // 1) tag 0x4F contains the AID of the PIV Card Application and
    // 2) tag 0x5F2F lists the PIN Usage Policy.
    buffer[0] = 0x7E;
    buffer[1] = 5 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
    buffer[2] = 0x4F;
    buffer[3] = sizeof(rid) + sizeof(pix);
    memcpy(buffer + 4, rid, sizeof(rid));
    memcpy(buffer + 4 + sizeof(rid), pix, sizeof(pix));
    buffer[4 + sizeof(rid) + sizeof(pix)] = 0x5F;
    buffer[5 + sizeof(rid) + sizeof(pix)] = 0x2F;
    buffer[6 + sizeof(rid) + sizeof(pix)] = sizeof(pin_policy);
    memcpy(buffer + 7 + sizeof(rid) + sizeof(pix), pin_policy,
           sizeof(pin_policy));
    buffer_len = 7 + sizeof(rid) + sizeof(pix) + sizeof(pin_policy);
    send_response(rapdu, LE);
  } else if (DATA[1] == 3) {
    if (LC != 5 || DATA[2] != 0x5F || DATA[3] != 0xC1)
      EXCEPT(SW_FILE_NOT_FOUND);
    const char *path = get_object_path_by_tag(DATA[4]);
    if (path == NULL)
      EXCEPT(SW_FILE_NOT_FOUND);
    int len = read_file(path, buffer, MAX_BUFFER_SIZE - 4);
    if (len < 0)
      return -1;
    if (len == 0)
      EXCEPT(SW_FILE_NOT_FOUND);
    buffer_len = len;
    send_response(rapdu, LE);
  } else
    EXCEPT(SW_FILE_NOT_FOUND);
  return 0;
}

static int piv_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 && P1 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (P1 == 0xFF) {
    if (LC != 0)
      EXCEPT(SW_WRONG_LENGTH);
    pin.is_validated = 0;
    return 0;
  }
  if (LC == 0) {
    if (pin.is_validated)
      return 0;
    int retries = pin_get_retries(&pin);
    if (retries < 0)
      return -1;
    EXCEPT(SW_PIN_RETRIES + retries);
  }
  if (LC != 8)
    EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(&pin, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL)
    return -1;
  if (ctr == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL)
    EXCEPT(SW_PIN_RETRIES + ctr);
  return 0;
}

static int piv_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  pin_t *p;
  if (P2 == 0x80)
    p = &pin;
  else if (P2 == 0x81)
    p = &puk;
  else
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16)
    EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(p, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL)
    return -1;
  if (ctr == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL)
    EXCEPT(SW_PIN_RETRIES + ctr);
  err = pin_update(p, DATA + 8, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

static int piv_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  if (P2 != 0x80)
    EXCEPT(SW_REFERENCE_DATA_NOT_FOUND);
  if (LC != 16)
    EXCEPT(SW_WRONG_LENGTH);
  uint8_t ctr;
  int err = pin_verify(&puk, DATA, 8, &ctr);
  if (err == PIN_IO_FAIL)
    return -1;
  if (ctr == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (err == PIN_AUTH_FAIL)
    EXCEPT(0x63C0 + ctr);
  err = pin_update(&pin, DATA + 8, 8);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
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
  if (*buffer != 0x7C)
    EXCEPT(SW_WRONG_DATA);

  const char *key_path = get_key_path(P2);
  if (key_path == NULL)
    EXCEPT(SW_WRONG_P1P2);

  uint8_t alg;
  if (read_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0)
    return -1;
  if (!(P1 == ALG_DEFAULT && alg == ALG_TDEA_3KEY) && alg != P1)
    EXCEPT(SW_WRONG_P1P2);

  uint16_t length = get_input_size(alg);
  uint16_t pos[6] = {0};
  int16_t len[6] = {0};
  uint16_t dat_len = tlv_get_length(buffer + 1);
  uint16_t dat_pos = 1 + tlv_length_size(dat_len);
  while (dat_pos < buffer_len) {
    uint8_t tag = buffer[dat_pos++];
    len[tag - 0x80] = tlv_get_length(buffer + dat_pos);
    dat_pos += tlv_length_size(len[tag - 0x80]);
    pos[tag - 0x80] = dat_pos;
    dat_pos += len[tag - 0x80];
    MSG_DBG("Tag %02X, pos: %d, len: %d", tag, pos[tag - 0x80],
            len[tag - 0x80]);
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
  if (pos[IDX_WITNESS] == 0 && pos[IDX_CHALLENGE] > 0 &&
      len[IDX_CHALLENGE] > 0 && pos[IDX_RESPONSE] > 0 &&
      len[IDX_RESPONSE] == 0) {
    authenticate_reset();
    if (P2 != 0x9E && pin.is_validated == 0)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (length != len[IDX_CHALLENGE])
      EXCEPT(SW_WRONG_DATA);
    if (P2 == 0x9D)
      pin.is_validated = 0;

    if (alg == ALG_RSA_2048) {
      rsa_key_t key;
      if (read_file(key_path, &key, sizeof(rsa_key_t)) < 0)
        return -1;
      if (rsa_private(&key, buffer + pos[IDX_CHALLENGE], buffer + 8) < 0) {
        memzero(&key, sizeof(key));
        return -1;
      }
      memzero(&key, sizeof(key));

      buffer[0] = 0x7C;
      buffer[1] = 0x82;
      buffer[2] = HI(length + 4u);
      buffer[3] = LO(length + 4u);
      buffer[4] = TAG_RESPONSE;
      buffer[5] = 0x82;
      buffer[6] = HI(length);
      buffer[7] = LO(length);
      buffer_len = length + 8;
    } else if (alg == ALG_ECC_256) {
      uint8_t key[ECC_KEY_SIZE];
      if (read_file(key_path, key, sizeof(key)) < 0)
        return -1;
      if (ecdsa_sign(ECC_SECP256R1, key, buffer + pos[IDX_CHALLENGE],
                     buffer + 4) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));

      int sig_len = ecdsa_sig2ansi(buffer + 4, buffer + 4);
      buffer[0] = 0x7C;
      buffer[1] = sig_len + 2;
      buffer[2] = TAG_RESPONSE;
      buffer[3] = sig_len;
      buffer_len = sig_len + 4;
    } else
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    send_response(rapdu, LE);
  }

  //
  // CASE 2 - EXTERNAL AUTHENTICATE REQUEST
  // Authenticates the HOST to the CARD
  //

  // > Client application requests a challenge from the PIV Card Application.
  else if (pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] == 0) {
    authenticate_reset();
    in_admin_status = 0;

    if (P2 != 0x9B)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    buffer[0] = 0x7C;
    buffer[1] = length + 2;
    buffer[2] = TAG_CHALLENGE;
    buffer[3] = length;
    random_buffer(buffer + 4, length);
    buffer_len = length + 4;

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_EXTERNAL;
    auth_ctx[OFFSET_AUTH_KEY_ID] = P2;
    auth_ctx[OFFSET_AUTH_ALGO] = alg;

    if (alg == ALG_TDEA_3KEY) {
      uint8_t key[24];
      if (read_file(key_path, key, 24) < 0)
        return -1;
      if (tdes_enc(buffer + 4, auth_ctx + OFFSET_AUTH_CHALLENGE, key) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));
    } else {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    send_response(rapdu, LE);
  }

  //
  // CASE 3 - EXTERNAL AUTHENTICATE RESPONSE
  //

  // > Client application requests a challenge from the PIV Card Application.
  else if (pos[IDX_RESPONSE] > 0 && len[IDX_RESPONSE] > 0) {
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_EXTERNAL ||
        auth_ctx[OFFSET_AUTH_KEY_ID] != P2 ||
        auth_ctx[OFFSET_AUTH_ALGO] != alg || length != len[IDX_RESPONSE] ||
        memcmp(auth_ctx + OFFSET_AUTH_CHALLENGE, buffer + pos[IDX_RESPONSE],
               length) != 0) {
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

    if (P2 != 0x9B)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);

    auth_ctx[OFFSET_AUTH_STATE] = AUTH_STATE_MUTUAL;
    auth_ctx[OFFSET_AUTH_KEY_ID] = P2;
    auth_ctx[OFFSET_AUTH_ALGO] = alg;
    random_buffer(auth_ctx + OFFSET_AUTH_CHALLENGE, length);

    buffer[0] = 0x7C;
    buffer[1] = length + 2;
    buffer[2] = TAG_WITNESS;
    buffer[3] = length;
    buffer_len = length + 4;

    if (alg == ALG_TDEA_3KEY) {
      uint8_t key[24];
      if (read_file(key_path, key, 24) < 0)
        return -1;
      if (tdes_enc(auth_ctx + OFFSET_AUTH_CHALLENGE, buffer + 4, key) < 0) {
        memzero(key, sizeof(key));
        return -1;
      }
      memzero(key, sizeof(key));
    } else {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    send_response(rapdu, LE);
  }

  //
  // CASE 5 - MUTUAL AUTHENTICATE RESPONSE
  //

  // > Client application returns the decrypted witness referencing the original
  // algorithm key reference
  else if (pos[IDX_WITNESS] > 0 && len[IDX_WITNESS] > 0 &&
           pos[IDX_CHALLENGE] > 0 && len[IDX_CHALLENGE] > 0) {
    if (auth_ctx[OFFSET_AUTH_STATE] != AUTH_STATE_MUTUAL ||
        auth_ctx[OFFSET_AUTH_KEY_ID] != P2 ||
        auth_ctx[OFFSET_AUTH_ALGO] != alg || length != len[IDX_WITNESS] ||
        memcmp(auth_ctx + OFFSET_AUTH_CHALLENGE, buffer + pos[IDX_WITNESS],
               length) != 0) {
      authenticate_reset();
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (length != len[IDX_CHALLENGE]) {
      authenticate_reset();
      EXCEPT(SW_WRONG_LENGTH);
    }

    buffer[0] = 0x7C;
    buffer[1] = length + 2;
    buffer[2] = TAG_RESPONSE;
    buffer[3] = length;
    buffer_len = length + 4;

    if (alg == ALG_TDEA_3KEY) {
      uint8_t key[24];
      if (read_file(key_path, key, 24) < 0)
        return -1;
      if (tdes_enc(buffer + pos[IDX_CHALLENGE], buffer + 4, key) < 0) {
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
    send_response(rapdu, LE);
  }

  //
  // CASE 6 - ECDH with the PIV KMK
  // Documented in SP800-73-4 Part 2 Appendix A.5
  //

  else if (pos[IDX_RESPONSE] > 0 && len[IDX_RESPONSE] == 0 &&
           pos[IDX_EXP] > 0 && len[IDX_EXP] > 0) {
    authenticate_reset();
    if (P2 != 0x9D || pin.is_validated == 0)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (len[IDX_EXP] != 2 * ECC_KEY_SIZE + 1)
      EXCEPT(SW_WRONG_DATA);
    if (P2 == 0x9D)
      pin.is_validated = 0;
    uint8_t key[ECC_KEY_SIZE];
    if (read_file(key_path, key, ECC_KEY_SIZE) < 0)
      return -1;
    if (ecdh_decrypt(ECC_SECP256R1, key, buffer + pos[IDX_EXP] + 1,
                     buffer + 4) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    buffer[0] = 0x7C;
    buffer[1] = ECC_KEY_SIZE + 2;
    buffer[2] = TAG_RESPONSE;
    buffer[3] = ECC_KEY_SIZE;
    buffer_len = ECC_KEY_SIZE + 4;
    send_response(rapdu, LE);
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
  if (!in_admin_status)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (P1 != 0x3F || P2 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (buffer[0] != 0x5C)
    EXCEPT(SW_WRONG_DATA);
  if (buffer[1] != 3 || buffer[2] != 0x5F || buffer[3] != 0xC1)
    EXCEPT(SW_FILE_NOT_FOUND);
  const char *path = get_object_path_by_tag(buffer[4]);
  if (path == NULL)
    EXCEPT(SW_FILE_NOT_FOUND);
  if (write_file(path, buffer + 5, buffer_len - 5) < 0)
    return -1;
  return 0;
}

static int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  if (!in_admin_status)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (P1 != 0x00 || (P2 != 0x9A && P2 != 0x9C && P2 != 0x9D && P2 != 0x9E) ||
      buffer[0] != 0xAC || buffer[2] != 0x80 || buffer[3] != 0x01)
    EXCEPT(SW_WRONG_DATA);
  const char *key_path = get_key_path(P2);
  uint8_t alg = buffer[4];
  if (alg == ALG_RSA_2048) {
    rsa_key_t key;
    if (rsa_generate_key(&key) < 0)
      return -1;
    if (write_file(key_path, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    buffer[0] = 0x7F;
    buffer[1] = 0x49;
    buffer[2] = 0x82;
    buffer[3] = HI(6 + N_LENGTH + E_LENGTH);
    buffer[4] = LO(6 + N_LENGTH + E_LENGTH);
    buffer[5] = 0x81; // modulus
    buffer[6] = 0x82;
    buffer[7] = HI(N_LENGTH);
    buffer[8] = LO(N_LENGTH);
    memcpy(buffer + 9, key.n, N_LENGTH);
    buffer[9 + N_LENGTH] = 0x82; // exponent
    buffer[10 + N_LENGTH] = E_LENGTH;
    memcpy(buffer + 11 + N_LENGTH, key.e, E_LENGTH);
    buffer_len = 11 + N_LENGTH + E_LENGTH;
    memzero(&key, sizeof(key));
    send_response(rapdu, LE);
  } else if (alg == ALG_ECC_256) {
    uint8_t key[ECC_KEY_SIZE + ECC_PUB_KEY_SIZE];
    if (ecc_generate(ECC_SECP256R1, key, key + ECC_KEY_SIZE) < 0)
      return -1;
    if (write_file(key_path, key, sizeof(key)) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    buffer[0] = 0x7F;
    buffer[1] = 0x49;
    buffer[2] = ECC_PUB_KEY_SIZE + 3;
    buffer[3] = 0x86;
    buffer[4] = ECC_PUB_KEY_SIZE + 1;
    buffer[5] = 0x04;
    memcpy(buffer + 6, key + ECC_KEY_SIZE, ECC_PUB_KEY_SIZE);
    buffer_len = ECC_PUB_KEY_SIZE + 6;
    memzero(key, sizeof(key));
    send_response(rapdu, LE);
  } else
    EXCEPT(SW_WRONG_DATA);
  if (write_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0)
    return -1;
  return 0;
}

static int piv_set_management_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0xFF || P2 != 0xFF)
    EXCEPT(SW_WRONG_P1P2);
  if (LC != 27)
    EXCEPT(SW_WRONG_LENGTH);
  if (buffer[0] != 0x03 || buffer[1] != 0x9B || buffer[2] != 24)
    EXCEPT(SW_WRONG_DATA);
  if (!in_admin_status)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (write_file(CARD_ADMIN_KEY_PATH, buffer + 3, 24) < 0)
    return -1;
  return 0;
}

static int piv_reset(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  if (LC != 0)
    EXCEPT(SW_WRONG_LENGTH);
  if (pin_get_retries(&pin) > 0 || pin_get_retries(&puk) > 0)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  piv_install(1);
  return 0;
}

static int piv_import_asymmetric_key(const CAPDU *capdu, RAPDU *rapdu) {
  if (!in_admin_status)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  const char *key_path = get_key_path(P2);
  if (key_path == NULL)
    EXCEPT(SW_WRONG_P1P2);
  uint8_t alg = P1;
  switch (alg) {
  case ALG_RSA_2048: {
    rsa_key_t key;
    memset(&key, 0, sizeof(key));
    key.e[1] = 1;
    key.e[3] = 1;
    uint8_t *p = buffer;
    if (*p++ != 0x01)
      EXCEPT(SW_WRONG_DATA);
    int p_len = tlv_get_length(p);
    if (p_len > PQ_LENGTH)
      EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(p_len);
    memcpy(key.p + (PQ_LENGTH - p_len), p, p_len);
    p += p_len;
    if (*p++ != 0x02)
      EXCEPT(SW_WRONG_DATA);
    int q_len = tlv_get_length(p);
    if (q_len > PQ_LENGTH)
      EXCEPT(SW_WRONG_DATA);
    p += tlv_length_size(q_len);
    memcpy(key.q + (PQ_LENGTH - q_len), p, q_len);
    if (rsa_complete_key(&key) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    if (write_file(key_path, &key, sizeof(key)) < 0) {
      memzero(&key, sizeof(key));
      return -1;
    }
    memzero(&key, sizeof(key));
    break;
  }
  case ALG_ECC_256: {
    uint8_t key[ECC_KEY_SIZE + ECC_PUB_KEY_SIZE];
    if (buffer[0] != 0x06 || buffer[1] != ECC_KEY_SIZE)
      EXCEPT(SW_WRONG_DATA);
    memcpy(key, buffer + 2, ECC_KEY_SIZE);
    if (ecc_get_public_key(ECC_SECP256R1, key, key + ECC_KEY_SIZE) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    if (write_file(key_path, key, sizeof(key)) < 0) {
      memzero(key, sizeof(key));
      return -1;
    }
    memzero(key, sizeof(key));
    break;
  }
  default:
    EXCEPT(SW_WRONG_P1P2);
  }
  if (write_attr(key_path, TAG_KEY_ALG, &alg, sizeof(alg)) < 0)
    return -1;
  return 0;
}

static int piv_get_version(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  if (LC != 0)
    EXCEPT(SW_WRONG_LENGTH);
  buffer[0] = 0x05;
  buffer[1] = 0x00;
  buffer[2] = 0x00;
  buffer_len = 3;
  send_response(rapdu, LE);
  return 0;
}

static int piv_get_serial(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00 || P2 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  if (LC != 0)
    EXCEPT(SW_WRONG_LENGTH);
  fill_sn(buffer);
  buffer_len = 4;
  send_response(rapdu, LE);
  return 0;
}

int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  uint8_t is_chaining = CLA & 0x10u;
restart:
  if (state == CHAINING_STATE_NORMAL) {
    buffer_len = 0;
    buffer_pos = 0;
    if (is_chaining) {
      state_ins = INS;
      state_p1 = P1;
      state_p2 = P2;
      state = CHAINING_STATE_CHAINING;
    } else {
      memcpy(buffer, DATA, LC);
      buffer_len = LC;
    }
  }
  if (state == CHAINING_STATE_CHAINING) {
    if (state_ins != INS || state_p1 != P1 || state_p2 != P2) {
      state = CHAINING_STATE_NORMAL;
      goto restart;
    }
    if (buffer_len + LC > buffer_cap)
      EXCEPT(SW_WRONG_DATA);
    memcpy(buffer + buffer_len, DATA, LC);
    buffer_len += LC;
    if (is_chaining)
      return 0;
    state = CHAINING_STATE_NORMAL;
  }
  if (state == CHAINING_STATE_LONG_RESPONSE && INS != PIV_INS_GET_RESPONSE) {
    state = CHAINING_STATE_NORMAL;
    goto restart;
  }
  int ret = 0;
  switch (INS) {
  case PIV_INS_GET_RESPONSE:
    if (state != CHAINING_STATE_LONG_RESPONSE)
      EXCEPT(SW_CONDITIONS_NOT_SATISFIED);
    send_response(rapdu, LE);
    break;
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
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}

int piv_config(uint8_t *buf, uint16_t buffer_size) {
  if (buffer_size < MAX_BUFFER_SIZE)
    return -1;
  buffer = buf;
  buffer_cap = buffer_size;
  return 0;
}
