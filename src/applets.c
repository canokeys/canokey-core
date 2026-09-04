// SPDX-License-Identifier: Apache-2.0
#include <admin.h>
#include <applets.h>
#include <ctap.h>
#if ENABLE_APPLET_NDEF
#include <ndef.h>
#endif
#include <oath.h>
#include <openpgp.h>
#include <pass.h>
#include <piv.h>

int applets_install(void) {
  if (openpgp_install(0) < 0) return -1;
  if (piv_install(0) < 0) return -1;
  if (oath_install(0) < 0) return -1;
  if (ctap_install(0) != 0) return -1;
  if (admin_install(0) < 0) return -1;
#if ENABLE_APPLET_NDEF
  if (ndef_install(0) < 0) return -1;
#endif
  if (pass_install(0) < 0) return -1;
  return 0;
}

void applets_poweroff(void) {
  ctap_poweroff();
  piv_poweroff();
  oath_poweroff();
  admin_poweroff();
  openpgp_poweroff();
#if ENABLE_APPLET_NDEF
  ndef_poweroff();
#endif
}
