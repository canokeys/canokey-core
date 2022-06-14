// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_CORE_PIN_H
#define CANOKEY_CORE_PIN_H

void begin_using_uv_auth_token(bool user_is_present);
void pin_uv_auth_token_usage_timer_observer(void);
bool get_user_present_flag_value(void);
bool get_user_verified_flag_value(void);
void clear_user_present_flag(void);
void clear_user_verified_flag(void);
void clear_pin_uv_auth_token_permissions_except_lbw(void);
void stopUsingPinUvAuthToken(void);

#endif //CANOKEY_CORE_PIN_H
