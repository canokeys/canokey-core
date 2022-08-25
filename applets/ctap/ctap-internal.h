/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FIDO_INTERNAL_H_
#define FIDO_INTERNAL_H_

#include <apdu.h>
#include <cbor.h>
#include <common.h>
#include <ecc.h>
#include <sha.h>

#define CTAP_CERT_FILE "ctap_cert"
#define KEY_ATTR 0x00
#define SIGN_CTR_ATTR 0x01
#define PIN_ATTR 0x02
#define PIN_CTR_ATTR 0x03
#define KH_KEY_ATTR 0x04
#define HE_KEY_ATTR 0x05
#define RK_FILE "ctap_rk"
#define RK_META_FILE "ctap_rkm"
#define RK_NUMBERS_ATTR 0x00

#define CTAP_INS_MSG 0x10

#define CTAP_MAKE_CREDENTIAL 0x01
#define CTAP_GET_ASSERTION 0x02
#define CTAP_GET_INFO 0x04
#define CTAP_CLIENT_PIN 0x06
#define CTAP_RESET 0x07
#define CTAP_GET_NEXT_ASSERTION 0x08
#define CTAP_CREDENTIAL_MANAGEMENT 0x0A
#define CTAP_SELECTION 0x0B
#define CTAP_LARGE_BLOBS 0x0C
#define CTAP_CONFIG 0x0D

#define PARAM_clientDataHash (1 << 0)
#define PARAM_rpId (1 << 1)
#define PARAM_user (1 << 2)
#define PARAM_pubKeyCredParams (1 << 3)
#define PARAM_extensions (1 << 4)
#define PARAM_options (1 << 5)
#define PARAM_pinUvAuthParam (1 << 6)
#define PARAM_pinUvAuthProtocol (1 << 7)
#define PARAM_subCommand (1 << 8)
#define PARAM_keyAgreement (1 << 9)
#define PARAM_newPinEnc (1 << 10)
#define PARAM_pinHashEnc (1 << 11)
#define PARAM_hmacSecret (1 << 12)
#define PARAM_enterpriseAttestation (1 << 13)
#define PARAM_permissions (1 << 14)
#define PARAM_credential_id (1 << 15)

#define MC_requiredMask (PARAM_clientDataHash | PARAM_rpId | PARAM_user | PARAM_pubKeyCredParams)
#define GA_requiredMask (PARAM_clientDataHash | PARAM_rpId)
#define CP_requiredMask (PARAM_subCommand)

#define OPTION_FALSE 0x0
#define OPTION_TRUE 0x1
#define OPTION_ABSENT 0x2

#define MC_clientDataHash 0x01
#define MC_rp 0x02
#define MC_user 0x03
#define MC_pubKeyCredParams 0x04
#define MC_excludeList 0x05
#define MC_extensions 0x06
#define MC_options 0x07
#define MC_pinUvAuthParam 0x08
#define MC_pinProtocol 0x09
#define MC_enterpriseAttestation 0x0A

#define GA_rpId 0x01
#define GA_clientDataHash 0x02
#define GA_allowList 0x03
#define GA_extensions 0x04
#define GA_options 0x05
#define GA_pinUvAuthParam 0x06
#define GA_pinUvAuthProtocol 0x07

#define HMAC_SECRET_keyAgreement 0x01
#define HMAC_SECRET_saltEnc 0x02
#define HMAC_SECRET_saltAuth 0x03

#define CP_pinUvAuthProtocol 0x01
#define CP_subCommand 0x02
#define CP_keyAgreement 0x03
#define CP_pinUvAuthParam 0x04
#define CP_newPinEnc 0x05
#define CP_pinHashEnc 0x06
#define CP_permissions 0x09
#define CP_rpId 0x0A
#define CP_cmdGetPINRetries 0x01
#define CP_cmdGetKeyAgreement 0x02
#define CP_cmdSetPin 0x03
#define CP_cmdChangePin 0x04
#define CP_cmdGetPinToken 0x05
#define CP_cmdGetPinUvAuthTokenUsingPinWithPermissions 0x09

#define CM_subCommand 0x01
#define CM_subCommandParams 0x02
#define CM_pinUvAuthProtocol 0x03
#define CM_pinUvAuthParam 0x04
#define CM_cmdGetCredsMetadata 0x01
#define CM_cmdEnumerateRPsBegin 0x02
#define CM_cmdEnumerateRPsGetNextRP 0x03
#define CM_cmdEnumerateCredentialsBegin 0x04
#define CM_cmdEnumerateCredentialsGetNextCredential 0x05
#define CM_cmdDeleteCredential 0x06
#define CM_cmdUpdateUserInformation 0x07
#define CM_paramRpIdHash 0x01
#define CM_paramCredentialId 0x02
#define CM_paramUser 0x03
#define CM_respExistingResidentCredentialsCount 0x01
#define CM_respMaxPossibleRemainingResidentCredentialsCount 0x02
#define CM_respRp 0x03
#define CM_respRpIDHash 0x04
#define CM_respTotalRPs 0x05
#define CM_respUser 0x06
#define CM_respCredentialID 0x07
#define CM_respPublicKey 0x08
#define CM_respTotalCredentials 0x09
#define CM_respCredProtect 0x0A
#define CM_respLargeBlobKey 0x0B

// TODO rename these constants
#define RESP_versions 0x1
#define RESP_extensions 0x2
#define RESP_aaguid 0x3
#define RESP_options 0x4
#define RESP_maxMsgSize 0x5
#define RESP_pinUvAuthProtocols 0x6

#define RESP_fmt 0x01
#define RESP_authData 0x02
#define RESP_attStmt 0x03

#define RESP_credential 0x01
#define RESP_signature 0x03
#define RESP_publicKeyCredentialUserEntity 0x04
#define RESP_numberOfCredentials 0x05

#define RESP_keyAgreement 0x01
#define RESP_pinUvAuthToken 0x02
#define RESP_pinRetries 0x03

#define FLAGS_UP (1)
#define FLAGS_UV (1 << 2)
#define FLAGS_AT (1 << 6)
#define FLAGS_ED (1 << 7)

#define KH_KEY_SIZE 32
#define HE_KEY_SIZE 32
#define PRI_KEY_SIZE 32
#define PUB_KEY_SIZE 64
#define SHARED_SECRET_SIZE 32
#define MAX_COSE_KEY_SIZE 78
#define PIN_ENC_SIZE_P1 64
#define PIN_ENC_SIZE_P2 80
#define PIN_HASH_SIZE_P1 16
#define PIN_HASH_SIZE_P2 32
#define MAX_CERT_SIZE 1152
#define AAGUID_SIZE 16
#define PIN_AUTH_SIZE_P1 16
#define PIN_TOKEN_SIZE 32
#define HMAC_SECRET_SALT_SIZE 64
#define HMAC_SECRET_SALT_AUTH_SIZE 16
#define CREDENTIAL_TAG_SIZE 16
#define CLIENT_DATA_HASH_SIZE 32
#define CREDENTIAL_NONCE_SIZE 16
#define DOMAIN_NAME_MAX_SIZE 254
#define USER_ID_MAX_SIZE 64
#define DISPLAY_NAME_LIMIT 65 // Must be minimum of 64 bytes but can be more.
#define MAX_RK_NUM 64
#define MAX_STORED_RPID_LENGTH 32

typedef struct {
  uint8_t id[USER_ID_MAX_SIZE];
  uint8_t id_size;
  uint8_t displayName[DISPLAY_NAME_LIMIT];
} __packed UserEntity;

typedef struct {
  uint8_t tag[CREDENTIAL_TAG_SIZE];
  uint8_t nonce[CREDENTIAL_NONCE_SIZE];
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  int32_t alg_type;
} __packed CredentialId;

typedef struct {
  CredentialId credential_id;
  UserEntity user;
  bool deleted;
} __packed CTAP_residentKey;

typedef struct {
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  uint8_t rp_id[MAX_STORED_RPID_LENGTH];
  size_t rp_id_len;
  uint64_t slots;
} __packed CTAP_rp_meta;

typedef struct {
  uint8_t aaguid[AAGUID_SIZE];
  uint16_t credentialIdLength;
  CredentialId credentialId;
  uint8_t publicKey[MAX_COSE_KEY_SIZE]; // public key in cose_key format
  // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
} __packed CTAP_attestedData;

typedef struct {
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  uint8_t flags;
  uint32_t signCount;
  CTAP_attestedData at;
  uint8_t extensions[14];
} __packed CTAP_authData;

typedef struct {
  uint8_t up : 2;
  uint8_t uv : 2;
  uint8_t rk : 2;
} CTAP_options;

typedef struct {
  uint16_t parsedParams;
  uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
  uint8_t rpId[MAX_STORED_RPID_LENGTH];
  size_t rpIdLen;
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  UserEntity user;
  int32_t alg_type;
  CborValue excludeList;
  size_t excludeListSize;
  CTAP_options options;
  uint8_t extension_hmac_secret;
  uint8_t pinUvAuthParam[SHA256_DIGEST_LENGTH];
  size_t pinUvAuthParamLength;
  uint8_t pinUvAuthProtocol;
} CTAP_makeCredential;

typedef struct {
  uint16_t parsedParams;
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
  CborValue allowList;
  size_t allowListSize;
  CTAP_options options;
  uint8_t pinUvAuthParam[SHA256_DIGEST_LENGTH];
  size_t pinUvAuthParamLength;
  uint8_t pinUvAuthProtocol;
  uint8_t hmacSecretKeyAgreement[PUB_KEY_SIZE];
  uint8_t hmacSecretSaltEnc[HMAC_SECRET_SALT_SIZE];
  uint8_t hmacSecretSaltAuth[HMAC_SECRET_SALT_AUTH_SIZE];
  uint8_t hmacSecretSaltLen;
} CTAP_getAssertion;

typedef struct {
  uint16_t parsedParams;
  uint8_t subCommand;
  uint8_t pinUvAuthProtocol;
  uint8_t keyAgreement[PUB_KEY_SIZE];
  uint8_t pinUvAuthParam[SHA256_DIGEST_LENGTH];
  uint8_t newPinEnc[PIN_ENC_SIZE_P2];
  uint8_t pinHashEnc[PIN_HASH_SIZE_P2];
  uint8_t permissions;
} CTAP_clientPin;

typedef struct {
  uint16_t parsedParams;
  uint8_t subCommand;
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  CredentialId credentialId;
  UserEntity user;
  uint8_t pinUvAuthProtocol;
  uint8_t pinUvAuthParam[SHA256_DIGEST_LENGTH];
} CTAP_credentialManagement;

int u2f_register(const CAPDU *capdu, RAPDU *rapdu);
int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu);
int u2f_version(const CAPDU *capdu, RAPDU *rapdu);
int u2f_select(const CAPDU *capdu, RAPDU *rapdu);
uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t flags, uint8_t extensionSize,
                            const uint8_t *extension, size_t *len, int32_t alg_type, bool dc);

#endif
