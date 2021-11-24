// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <applets.h>
#include <ctap.h>
#include <ndef.h>
#include <oath.h>
#include <openpgp.h>
#include <piv.h>

static uint8_t is_ready;

void applets_install(void) {
  openpgp_install(0);
  piv_install(0);
  oath_install(0);
  ctap_install(0);
  admin_install(0);
  ndef_install(0);
}

void applets_poweroff(void) {
  piv_poweroff();
  oath_poweroff();
  admin_poweroff();
  openpgp_poweroff();
  ndef_poweroff();
}

uint8_t is_applets_ready(void) {
  return is_ready;
}

void set_applets_ready(uint8_t val) {
  is_ready = val;
}
