#include "openpgp.h"
#include <fs.h>
#include <string.h>

static uint8_t pw1_mode, pw3_verified;

#define PW1_MIN_LENGTH 6
#define PW1_MAX_LENGTH 127
#define PW1_PATH "pgp-pw1"
#define PW1_DEFAULT "123456"
#define PW1_MODE81_ON() pw1_mode |= 1u
#define PW1_MODE81_OFF() pw1_mode &= 0XFEu
#define PW1_MODE82_ON() pw1_mode |= 2u
#define PW1_MODE82_OFF() pw1_mode &= 0XFDu
#define PW3_MIN_LENGTH 8
#define PW3_MAX_LENGTH 127
#define PW3_PATH "pgp-pw3"
#define PW3_DEFAULT "12345678"
#define PW_RETRY_ATTR 0
#define PW_RETRY_COUNTER_DEFAULT 3

int openpgp_initialize() {
  uint8_t retry_counter = PW_RETRY_COUNTER_DEFAULT;
  int err = write_file(PW1_PATH, PW1_DEFAULT, strlen(PW1_DEFAULT));
  if (err < 0)
    return err;
  err = write_attr(PW1_PATH, PW_RETRY_ATTR, &retry_counter,
                   sizeof(retry_counter));
  if (err < 0)
    return err;
  err = write_file(PW3_PATH, PW3_DEFAULT, strlen(PW3_DEFAULT));
  if (err < 0)
    return err;
  err = write_attr(PW3_PATH, PW_RETRY_ATTR, &retry_counter,
                   sizeof(retry_counter));
  if (err < 0)
    return err;
  return 0;
}

int openpgp_select(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;

  pw1_mode = 0;

  rapdu->sw = SW_NO_ERROR;
  rapdu->len = 0;
  return 0;
}

int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (capdu->p2 == 0x81 || capdu->p2 == 0x82) {
    if (capdu->lc < PW1_MIN_LENGTH || capdu->lc > PW1_MAX_LENGTH) {
      rapdu->sw = SW_WRONG_DATA;
      return 0;
    }
    uint8_t ctr;
    int err = read_attr(PW1_PATH, PW_RETRY_ATTR, &ctr, sizeof(ctr));
    if (err < 0)
      return err;
    if (ctr == 0) {
      rapdu->sw = SW_AUTHENTICATION_BLOCKED;
      return 0;
    }
    int len = read_file(PW1_PATH, rapdu->data, PW1_MAX_LENGTH);
    if (len != capdu->lc || memcmp(rapdu->data, capdu->data, len) != 0) {
      --ctr;
      err = write_attr(PW1_PATH, PW_RETRY_ATTR, &ctr, sizeof(ctr));
      if (err < 0)
        return err;
      rapdu->sw = SW_SECURITY_STATUS_NOT_SATISFIED;
      return 0;
    }
    if (capdu->p2 == 0x81)
      PW1_MODE81_ON();
    else
      PW1_MODE82_ON();
    ctr = PW_RETRY_COUNTER_DEFAULT;
    err = write_attr(PW1_PATH, PW_RETRY_ATTR, &ctr, sizeof(ctr));
    if (err < 0)
      return err;
    rapdu->sw = SW_NO_ERROR;
    return 0;
  }
  if (capdu->p2 == 0x83) {
    if (capdu->lc < PW3_MIN_LENGTH || capdu->lc > PW3_MAX_LENGTH) {
      rapdu->sw = SW_WRONG_DATA;
      return 0;
    }
    uint8_t ctr;
    int err = read_attr(PW3_PATH, PW_RETRY_ATTR, &ctr, sizeof(ctr));
    if (err < 0)
      return err;
    if (ctr == 0) {
      rapdu->sw = SW_AUTHENTICATION_BLOCKED;
      return 0;
    }
    int len = read_file(PW3_PATH, rapdu->data, PW3_MAX_LENGTH);
    if (len != capdu->lc || memcmp(rapdu->data, capdu->data, len) != 0) {
      --ctr;
      err = write_attr(PW3_PATH, PW_RETRY_ATTR, &ctr, sizeof(ctr));
      if (err < 0)
        return err;
      rapdu->sw = SW_SECURITY_STATUS_NOT_SATISFIED;
      return 0;
    }
    pw3_verified = 1;
    ctr = PW_RETRY_COUNTER_DEFAULT;
    err = write_attr(PW1_PATH, PW_RETRY_ATTR, &ctr, sizeof(ctr));
    if (err < 0)
      return err;
    rapdu->sw = SW_NO_ERROR;
    return 0;
  }
  rapdu->sw = SW_WRONG_P1P2;
  return 0;
}

int openpgp_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_compute_digital_signature(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_decipher(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_internal_authentication(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int openpgp_get_challenge(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_terminate_df(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_activate_file(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  rapdu->len = 0;
  switch (capdu->ins) {
  case 0xA4:
    return openpgp_select(capdu, rapdu);
  case 0xCA:
    return openpgp_get_data(capdu, rapdu);
  case OPENPGP_VERIFY:
    return openpgp_verify(capdu, rapdu);
  case 0x24:
    return openpgp_change_reference_data(capdu, rapdu);
  case 0x2C:
    return openpgp_reset_retry_counter(capdu, rapdu);
    // TODO: DADB
  case 0x47:
    return openpgp_generate_asymmetric_key_pair(capdu, rapdu);
  case 0x2A:
    if (capdu->p1 == 0x9E && capdu->p2 == 0x9A)
      return openpgp_compute_digital_signature(capdu, rapdu);
    if (capdu->p1 == 0x80 && capdu->p2 == 0x86)
      return openpgp_decipher(capdu, rapdu);
    rapdu->sw = SW_WRONG_P1P2;
    rapdu->len = 0;
    return 0;
  case 0x88:
    return openpgp_internal_authentication(capdu, rapdu);
  case 0xC0:
    return 0; // TODO
  case 0x84:
    return openpgp_get_challenge(capdu, rapdu);
  case 0xE6:
    return openpgp_terminate_df(capdu, rapdu);
  case 0x44:
    return openpgp_activate_file(capdu, rapdu);
  }
  rapdu->sw = SW_INS_NOT_SUPPORTED;
  rapdu->len = 0;
  return 0;
}
