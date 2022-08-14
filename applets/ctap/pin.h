// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_CORE_PIN_H
#define CANOKEY_CORE_PIN_H

#define CP_PERMISSION_MC   0x01
#define CP_PERMISSION_GA   0x02
#define CP_PERMISSION_CM   0x04
#define CP_PERMISSION_BE   0x08
#define CP_PERMISSION_LBW  0x10
#define CP_PERMISSION_ACFG 0x20

// utility functions
void cp_begin_using_uv_auth_token(bool user_is_present);
void cp_pin_uv_auth_token_usage_timer_observer(void);
bool cp_get_user_present_flag_value(void);
bool cp_get_user_verified_flag_value(void);
void cp_clear_user_present_flag(void);
void cp_clear_user_verified_flag(void);
void cp_clear_pin_uv_auth_token_permissions_except_lbw(void);
void cp_stop_using_pin_uv_auth_token(void);
// pin auth protocol
void cp_initialize(void);
void cp_regenerate(void);
void cp_reset_pin_uv_auth_token(void);
void cp_get_public_key(uint8_t *buf);
int cp_decapsulate(uint8_t *buf);
int cp_encrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out);
int cp_encrypt_pin_token(const uint8_t *key, uint8_t *out);
int cp_decrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out);
bool cp_verify(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig);
bool cp_verify_pin_token(const uint8_t *msg, size_t msg_len, const uint8_t *sig);

void cp_set_permission(int new_permissions);
bool pin_has_permission(int permission);
bool pin_verify_rp_id(const uint8_t *rp_id_hash);
void pin_associate_rp_id(const uint8_t *rp_id_hash);

#endif //CANOKEY_CORE_PIN_H
