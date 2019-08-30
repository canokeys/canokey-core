#ifndef CANOKEY_CORE_FIDO2_FIDO2_H_
#define CANOKEY_CORE_FIDO2_FIDO2_H_

#include <cbor.h>
#include <sha.h>
#include <stdint.h>

#define PARAM_clientDataHash (1 << 0)
#define PARAM_rpId (1 << 1)
#define PARAM_user (1 << 2)
#define PARAM_pubKeyCredParams (1 << 3)
#define PARAM_excludeList (1 << 4)
#define PARAM_extensions (1 << 5)
#define PARAM_options (1 << 6)
#define PARAM_pinAuth (1 << 7)
#define PARAM_pinProtocol (1 << 8)
#define PARAM_allowList (1 << 9)

#define MC_requiredMask 0xF

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

#define PUB_KEY_CRED_PUB_KEY 0x01
#define PUB_KEY_CRED_CTAP1 0x41
#define PUB_KEY_CRED_CUSTOM 0x42
#define PUB_KEY_CRED_UNKNOWN 0x3F

#define PIN_AUTH_SIZE 16
#define CREDENTIAL_TAG_SIZE 16
#define CLIENT_DATA_HASH_SIZE 32
#define CREDENTIAL_NONCE_SIZE 16
#define DOMAIN_NAME_MAX_SIZE 254
#define USER_ID_MAX_SIZE 64
#define USER_NAME_LIMIT 65    // Must be minimum of 64 bytes but can be more.
#define DISPLAY_NAME_LIMIT 65 // Must be minimum of 64 bytes but can be more.
#define ICON_LIMIT 129        // Must be minimum of 64 bytes but can be more.

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
  uint16_t parsedParams;
  uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
  uint8_t rpIdHash[SHA256_DIGEST_LENGTH];
  UserEntity user;
  CborValue excludeList;
  size_t excludeListSize;
  uint8_t rk;
  uint8_t uv;
  uint8_t pinAuth[PIN_AUTH_SIZE];
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
} CTAP_getAssertion;

#endif // CANOKEY_CORE_FIDO2_FIDO2_H_
