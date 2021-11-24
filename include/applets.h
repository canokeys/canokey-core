// SPDX-License-Identifier: Apache-2.0
#ifndef APPLETS_H_
#define APPLETS_H_

#include <stdint.h>

void applets_install(void);
void applets_poweroff(void);
uint8_t is_applets_ready(void);
void set_applets_ready(uint8_t val);

#endif // APPLETS_H_
