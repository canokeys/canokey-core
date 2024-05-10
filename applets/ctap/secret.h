/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_FIDO2_SECRET_H_
#define CANOKEY_CORE_FIDO2_SECRET_H_

#include "ctap-internal.h"
#include <ctap.h>

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
int cp_decapsulate(uint8_t *buf, int pin_protocol);
int cp_encrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out, int pin_protocol);
int cp_encrypt_pin_token(const uint8_t *key, uint8_t *out, int pin_protocol);
int cp_decrypt(const uint8_t *key, const uint8_t *in, size_t in_size, uint8_t *out, int pin_protocol);
bool cp_verify(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig, int pin_protocol);
bool cp_verify_pin_token(const uint8_t *msg, size_t msg_len, const uint8_t *sig, int pin_protocol);

void cp_set_permission(int new_permissions);
bool cp_has_permission(int permission);
bool cp_has_associated_rp_id(void);
bool cp_verify_rp_id(const uint8_t *rp_id_hash);
void cp_associate_rp_id(const uint8_t *rp_id_hash);
key_type_t cose_alg_to_key_type(int alg);

int increase_counter(uint32_t *counter);
int generate_key_handle(credential_id *kh, uint8_t *pubkey, int32_t alg_type, uint8_t dc, uint8_t cp);
size_t sign_with_device_key(const uint8_t *input, size_t input_len, uint8_t *sig);
int sign_with_private_key(int32_t alg_type, ecc_key_t *key, const uint8_t *input, size_t len, uint8_t *sig);
int verify_key_handle(const credential_id *kh, ecc_key_t *key);
bool check_credential_protect_requirements(credential_id *kh, bool with_cred_list, bool uv);
int get_cert(uint8_t *buf);
bool has_pin(void);
int set_pin(uint8_t *buf, uint8_t length);
int verify_pin_hash(uint8_t *buf);
int get_pin_retries(void);
int set_pin_retries(uint8_t ctr);
int make_hmac_secret_output(uint8_t *nonce, uint8_t *salt, uint8_t len, uint8_t *output, bool uv);
int make_large_blob_key(uint8_t *nonce, uint8_t *output);

#endif // CANOKEY_CORE_FIDO2_SECRET_H_
