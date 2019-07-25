#include <common.h>
#include <piv.h>

int piv_select(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_get_data(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_verify(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_change_reference_data(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_reset_retry_counter(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_general_authenticate(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_put_data(const CAPDU *capdu, RAPDU *rapdu) { return 0; }

int piv_generate_asymmetric_key_pair(const CAPDU *capdu, RAPDU *rapdu) {
  return 0;
}

int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  LL = 0;
  SW = SW_NO_ERROR;
  int ret;
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
  case PIV_GENERAL_AUTHENTICATE:
    ret = piv_general_authenticate(capdu, rapdu);
    break;
  case PIV_INS_PUT_DATA:
    ret = piv_put_data(capdu, rapdu);
    break;
  case PIV_GENERATE_ASYMMETRIC_KEY_PAIR:
    ret = piv_generate_asymmetric_key_pair(capdu, rapdu);
    break;
  default:
    EXCEPT(SW_INS_NOT_SUPPORTED);
  }
  if (ret < 0)
    EXCEPT(SW_UNABLE_TO_PROCESS);
  return 0;
}
