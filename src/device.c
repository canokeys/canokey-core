#include "common.h"

__weak void wait_for_user_presence(void) {}

__weak void device_delay(int ms) {}

__weak uint32_t device_get_tick(void) { return 0; }