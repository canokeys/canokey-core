// SPDX-License-Identifier: Apache-2.0
#include <stdbool.h>
#include <stdint.h>

#include "pin.h"

static uint8_t in_use;
static bool user_verified;
static bool user_present;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinuvauthprotocol-beginusingpinuvauthtoken
void begin_using_uv_auth_token(bool user_is_present) {
  user_present = user_is_present;
  user_verified = true;
  // TODO: time limit
}

void pin_uv_auth_token_usage_timer_observer(void) {

}

bool get_user_present_flag_value(void) {
  return user_present;
}

bool get_user_verified_flag_value(void) {
  return user_verified;
}

void clear_user_present_flag(void) {

}

void clear_user_verified_flag(void) {

}

void clear_pin_uv_auth_token_permissions_except_lbw(void) {

}

void stopUsingPinUvAuthToken(void) {

}
