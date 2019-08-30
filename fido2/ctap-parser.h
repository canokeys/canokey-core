#ifndef CANOKEY_CORE_FIDO2_CTAP_PARSER_H_
#define CANOKEY_CORE_FIDO2_CTAP_PARSER_H_

#include <cbor.h>
#include <fido2.h>

uint8_t parse_rp(uint8_t *rpIdHash, CborValue *val);
uint8_t parse_user(UserEntity *user, CborValue *val);
uint8_t parse_pub_key_cred_params(CborValue *val);
uint8_t parse_verify_exclude_list(CborValue *lst);
uint8_t parse_options(uint8_t *rk, uint8_t *uv, uint8_t *up, CborValue *val);
uint8_t parse_make_credential(CTAP_MakeCredential *mc, uint8_t *buf,
                              size_t len);

#endif // CANOKEY_CORE_FIDO2_CTAP_PARSER_H_
