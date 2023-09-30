/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_FIDO2_CTAP_PARSER_H_
#define CANOKEY_CORE_FIDO2_CTAP_PARSER_H_

#include "ctap-internal.h"
#include <cbor.h>
#include <ctap.h>

uint8_t parse_user(user_entity *user, CborValue *val);
uint8_t parse_verify_pub_key_cred_params(CborValue *val, int32_t *alg_type);
uint8_t parse_credential_descriptor(CborValue *arr, uint8_t *id);
uint8_t parse_public_key_credential_list(CborValue *lst);
uint8_t parse_options(CTAP_options *options, CborValue *val);
uint8_t parse_cose_key(CborValue *val, uint8_t *public_key);
uint8_t parse_make_credential(CborParser *parser, CTAP_make_credential *mc, const uint8_t *buf, size_t len);
uint8_t parse_get_assertion(CborParser *parser, CTAP_get_assertion *ga, const uint8_t *buf, size_t len);
uint8_t parse_client_pin(CborParser *parser, CTAP_client_pin *cp, const uint8_t *buf, size_t len);
uint8_t parse_credential_management(CborParser *parser, CTAP_credential_management *cm, const uint8_t *buf, size_t len);
uint8_t parse_large_blobs(CborParser *parser, CTAP_large_blobs *lb, const uint8_t *buf, size_t len);

#endif // CANOKEY_CORE_FIDO2_CTAP_PARSER_H_
