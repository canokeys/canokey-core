#ifndef CANOKEY_CORE_SRC_DEVICE_H_
#define CANOKEY_CORE_SRC_DEVICE_H_

#include "common.h"

void wait_for_user_presence(void);
void device_delay(int ms);
uint32_t device_get_tick(void);

#endif // CANOKEY_CORE_SRC_DEVICE_H_
