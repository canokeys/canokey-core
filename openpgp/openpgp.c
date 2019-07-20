#include "openpgp.h"
#include <fs.h>
#include <pin.h>
#include <string.h>

static uint8_t pw1_mode;
pin_t pw1 = {
    .min_length = 6, .max_length = 64, .is_validated = 0, .path = "pgp-pw1"};
pin_t pw3 = {
    .min_length = 8, .max_length = 64, .is_validated = 0, .path = "pgp-pw3"};
pin_t rc = {
    .min_length = 0, .max_length = 64, .is_validated = 0, .path = "pgp-rc"};

#define EXCEPT(sw_code)                                                        \
  do {                                                                         \
    rapdu->sw = sw_code;                                                       \
    return 0;                                                                  \
  } while (0)
#define P1 capdu->p1
#define P2 capdu->p2
#define LC capdu->lc
#define DATA capdu->data

#define PW1_MODE81_ON() pw1_mode |= 1u
#define PW1_MODE81_OFF() pw1_mode &= 0XFEu
#define PW1_MODE82_ON() pw1_mode |= 2u
#define PW1_MODE82_OFF() pw1_mode &= 0XFDu
#define PW_RETRY_COUNTER_DEFAULT 3

#define ASSERT_ADMIN()                                                         \
  do {                                                                         \
    if (pw3.is_validated == 0) {                                               \
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);                                \
    }                                                                          \
  } while (0)

int openpgp_initialize() {
  if (pin_create(&pw1, "123456", 6, PW_RETRY_COUNTER_DEFAULT) < 0)
    return -1;
  if (pin_create(&pw3, "12345678", 8, PW_RETRY_COUNTER_DEFAULT) < 0)
    return -1;
  if (pin_create(&rc, NULL, 0, PW_RETRY_COUNTER_DEFAULT) < 0)
    return -1;
  return 0;
}

int openpgp_select(const CAPDU *capdu, RAPDU *rapdu) {
  (void)capdu;

  pw1_mode = 0;
  pw1.is_validated = 0;
  pw3.is_validated = 0;

  return 0;
}

int openpgp_get_data(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int openpgp_verify(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  pin_t *pw;
  if (P2 == 0x81) {
    pw = &pw1;
    PW1_MODE81_OFF();
  } else if (P2 == 0x82) {
    pw = &pw1;
    PW1_MODE82_OFF();
  } else if (P2 == 0x83)
    pw = &pw3;
  else
    EXCEPT(SW_WRONG_P1P2);
  int err = pin_verify(pw, DATA, LC);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  if (err == PIN_AUTH_FAIL)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  if (P2 == 0x81)
    PW1_MODE81_ON();
  else if (P2 == 0x82)
    PW1_MODE82_ON();
  return 0;
}

int openpgp_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) {
  if (P1 != 0x00)
    EXCEPT(SW_WRONG_P1P2);
  pin_t *pw;
  if (P2 == 0x81) {
    pw = &pw1;
    pw1_mode = 0;
  } else if (P2 == 0x83)
    pw = &pw3;
  else
    EXCEPT(SW_WRONG_P1P2);
  int pw_length = pin_get_size(pw);
  int err = pin_verify(pw, DATA, pw_length);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_AUTH_FAIL)
    EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
  if (err == 0)
    EXCEPT(SW_AUTHENTICATION_BLOCKED);
  err = pin_update(pw, DATA + pw_length, LC - pw_length);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

int openpgp_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) {
  if ((P1 != 0x00 && P1 != 0x02) || P2 != 0x81)
    EXCEPT(SW_WRONG_P1P2);
  int offset, err;
  if (P1 == 0x00) {
    offset = pin_get_size(&rc);
    if (offset == 0)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    err = pin_verify(&rc, DATA, offset);
    if (err == PIN_IO_FAIL)
      return -1;
    if (err == PIN_AUTH_FAIL)
      EXCEPT(SW_SECURITY_STATUS_NOT_SATISFIED);
    if (err == 0)
      EXCEPT(SW_AUTHENTICATION_BLOCKED);
  } else {
    ASSERT_ADMIN();
    offset = 0;
  }
  err = pin_update(&pw1, DATA + offset, LC - offset);
  if (err == PIN_IO_FAIL)
    return -1;
  if (err == PIN_LENGTH_INVALID)
    EXCEPT(SW_WRONG_LENGTH);
  return 0;
}

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
  rapdu->sw = SW_NO_ERROR;
  switch (capdu->ins) {
  case 0xA4:
    return openpgp_select(capdu, rapdu);
  case 0xCA:
    return openpgp_get_data(capdu, rapdu);
  case OPENPGP_VERIFY:
    return openpgp_verify(capdu, rapdu);
  case OPENPGP_CHANGE_REFERENCE_DATA:
    return openpgp_change_reference_data(capdu, rapdu);
  case OPENPGP_RESET_RETRY_COUNTER:
    return openpgp_reset_retry_counter(capdu, rapdu);
    // TODO: DADB
  case 0x47:
    return openpgp_generate_asymmetric_key_pair(capdu, rapdu);
  case 0x2A:
    if (P1 == 0x9E && P2 == 0x9A)
      return openpgp_compute_digital_signature(capdu, rapdu);
    if (P1 == 0x80 && P2 == 0x86)
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
  return 0;
}
