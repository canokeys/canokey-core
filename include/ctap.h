#ifndef CANOKEY_CORE_FIDO2_FIDO2_H_
#define CANOKEY_CORE_FIDO2_FIDO2_H_

#include <apdu.h>
#include <cbor.h>
#include <ecc.h>
#include <sha.h>
#include <stdint.h>

#define CTAP_CERT_FILE "ctap_cert"
#define KEY_ATTR 0x00
#define SIGN_CTR_ATTR 0x01
#define PIN_ATTR 0x02
#define PIN_CTR_ATTR 0x03
#define KH_KEY_ATTR 0x04
#define HE_KEY_ATTR 0x05
#define RK_FILE "ctap_rk"

#define CTAP_INS_MSG 0x10

#define CTAP_MAKE_CREDENTIAL 0x01
#define CTAP_GET_ASSERTION 0x02
#define CTAP_GET_INFO 0x04
#define CTAP_CLIENT_PIN 0x06
#define CTAP_RESET 0x07
#define CTAP_GET_NEXT_ASSERTION 0x08

#define PARAM_clientDataHash (1 << 0)
#define PARAM_rpId (1 << 1)
#define PARAM_user (1 << 2)
#define PARAM_pubKeyCredParams (1 << 3)
#define PARAM_extensions (1 << 4)
#define PARAM_options (1 << 5)
#define PARAM_pinAuth (1 << 6)
#define PARAM_pinProtocol (1 << 7)
#define PARAM_subCommand (1 << 8)
#define PARAM_keyAgreement (1 << 9)
#define PARAM_newPinEnc (1 << 10)
#define PARAM_pinHashEnc (1 << 11)
#define PARAM_hmacSecret (1 << 12)

#define MC_requiredMask (PARAM_clientDataHash | PARAM_rpId | PARAM_user | PARAM_pubKeyCredParams)
#define GA_requiredMask (PARAM_clientDataHash | PARAM_rpId)
#define CP_requiredMask (PARAM_pinProtocol | PARAM_subCommand)

#define MC_clientDataHash 0x01
#define MC_rp 0x02
#define MC_user 0x03
#define MC_pubKeyCredParams 0x04
#define MC_excludeList 0x05
#define MC_extensions 0x06
#define MC_options 0x07
#define MC_pinAuth 0x08
#define MC_pinProtocol 0x09

#define GA_rpId 0x01
#define GA_clientDataHash 0x02
#define GA_allowList 0x03
#define GA_extensions 0x04
#define GA_options 0x05
#define GA_pinAuth 0x06
#define GA_pinProtocol 0x07

#define HMAC_SECRET_keyAgreement 0x01
#define HMAC_SECRET_saltEnc 0x02
#define HMAC_SECRET_saltAuth 0x03

#define CP_pinProtocol 0x01
#define CP_subCommand 0x02
#define CP_cmdGetRetries 0x01
#define CP_cmdGetKeyAgreement 0x02
#define CP_cmdSetPin 0x03
#define CP_cmdChangePin 0x04
#define CP_cmdGetPinToken 0x05
#define CP_keyAgreement 0x03
#define CP_pinAuth 0x04
#define CP_newPinEnc 0x05
#define CP_pinHashEnc 0x06
#define CP_getKeyAgreement 0x07
#define CP_getRetries 0x08

#define RESP_versions 0x1
#define RESP_extensions 0x2
#define RESP_aaguid 0x3
#define RESP_options 0x4
#define RESP_maxMsgSize 0x5
#define RESP_pinProtocols 0x6

#define RESP_fmt 0x01
#define RESP_authData 0x02
#define RESP_attStmt 0x03

#define RESP_credential 0x01
#define RESP_signature 0x03
#define RESP_publicKeyCredentialUserEntity 0x04
#define RESP_numberOfCredentials 0x05

#define RESP_keyAgreement 0x01
#define RESP_pinToken 0x02
#define RESP_retries 0x03

#define FLAGS_UP    (1)
#define FLAGS_UV    (1<<2)
#define FLAGS_AT    (1<<6)
#define FLAGS_ED    (1<<7)

#define KH_KEY_SIZE 32
#define HE_KEY_SIZE 32
#define SHARED_SECRET_SIZE 32
#define MAX_COSE_KEY_SIZE 78
#define MAX_PIN_SIZE 63
#define PIN_HASH_SIZE 16
#define MAX_CERT_SIZE 1152
#define AAGUID_SIZE 16
#define PIN_AUTH_SIZE 16
#define PIN_TOKEN_SIZE 16
#define HMAC_SECRET_SALT_SIZE 64
#define HMAC_SECRET_SALT_AUTH_SIZE 16
#define CREDENTIAL_TAG_SIZE 16
#define CLIENT_DATA_HASH_SIZE 32
#define CREDENTIAL_NONCE_SIZE 16
#define DOMAIN_NAME_MAX_SIZE 254
#define USER_ID_MAX_SIZE 64
#define USER_NAME_LIMIT 65    // Must be minimum of 64 bytes but can be more.
#define DISPLAY_NAME_LIMIT 65 // Must be minimum of 64 bytes but can be more.
#define ICON_LIMIT 129        // Must be minimum of 64 bytes but can be more.
#define MAX_RK_NUM 64

typedef struct {
  uint8_t id[USER_ID_MAX_SIZE];
  uint8_t id_size;
  uint8_t name[USER_NAME_LIMIT];
  uint8_t displayName[DISPLAY_NAME_LIMIT];
  uint8_t icon[ICON_LIMIT];
} __attribute__((packed)) UserEntity;

typedef struct {
  uint8_t tag[CREDENTIAL_TAG_SIZE];
  uint8_t nonce[CREDENTIAL_NONCE_SIZE];
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
} __attribute__((packed)) CredentialId;

typedef struct {
  CredentialId credential_id;
  UserEntity user;
} __attribute__((packed)) CTAP_residentKey;

typedef struct {
  uint8_t aaguid[AAGUID_SIZE];
  uint16_t credentialIdLength;
  CredentialId credentialId;
  uint8_t publicKey[MAX_COSE_KEY_SIZE]; // public key in cose_key format
  // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
} __attribute__((packed)) CTAP_attestedData;

typedef struct {
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  uint8_t flags;
  uint32_t signCount;
  CTAP_attestedData at;
  uint8_t extensions[14];
} __attribute__((packed)) CTAP_authData;

typedef struct {
  uint16_t parsedParams;
  uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  UserEntity user;
  CborValue excludeList;
  size_t excludeListSize;
  uint8_t rk;
  uint8_t extension_hmac_secret;
  uint8_t uv;
  uint8_t pinAuth[PIN_AUTH_SIZE];
  size_t pinAuthLength;
} CTAP_makeCredential;

typedef struct {
  uint16_t parsedParams;
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
  CborValue allowList;
  size_t allowListSize;
  uint8_t up;
  uint8_t uv;
  uint8_t pinAuth[PIN_AUTH_SIZE];
  size_t pinAuthLength;
  uint8_t hmacSecretKeyAgreement[ECC_PUB_KEY_SIZE];
  uint8_t hmacSecretSaltEnc[HMAC_SECRET_SALT_SIZE];
  uint8_t hmacSecretSaltAuth[HMAC_SECRET_SALT_AUTH_SIZE];
  uint8_t hmacSecretSaltLen;
} CTAP_getAssertion;

typedef struct {
  uint16_t parsedParams;
  uint8_t subCommand;
  uint8_t keyAgreement[ECC_PUB_KEY_SIZE];
  uint8_t pinAuth[PIN_AUTH_SIZE];
  uint8_t newPinEnc[MAX_PIN_SIZE + 1];
  uint8_t pinHashEnc[PIN_HASH_SIZE];
} CTAP_clientPin;

uint8_t ctap_install(uint8_t reset);
int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu);
int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu);
int ctap_process(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len);
int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_FIDO2_FIDO2_H_
