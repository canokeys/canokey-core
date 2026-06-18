/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FIDO_INTERNAL_H_
#define FIDO_INTERNAL_H_

#include <apdu.h>
#include <cbor.h>
#include <common.h>
#include <ctaphid.h>
#include <ecc.h>
#include <sha.h>

#define FIRMWARE_VERSION 201
#define CTAP_MAX_MSG_SIZE MAX_CTAP_BUFSIZE

// Filesystem Meta
// clang-format off
#define CTAP_CERT_FILE  "ctap_cert"
#define KEY_ATTR        0x00
#define SIGN_CTR_ATTR   0x01
#define PIN_ATTR        0x02
#define PIN_CTR_ATTR    0x03
#define KH_KEY_ATTR     0x04
#define HE_KEY_ATTR     0x05
#define DC_FILE         "ctap_dc"
#define DC_GENERAL_ATTR 0x00
#define DC_META_FILE    "ctap_dm"
#define LB_FILE         "ctap_lb"
#define LB_FILE_TMP     "ctap_lbt"
#define MIN_PIN_RPIDS_FILE "ctap_mpr"
// clang-format on

// Commands
// clang-format off
#define CTAP_MAKE_CREDENTIAL       0x01
#define CTAP_GET_ASSERTION         0x02
#define CTAP_GET_INFO              0x04
#define CTAP_CLIENT_PIN            0x06
#define CTAP_RESET                 0x07
#define CTAP_GET_NEXT_ASSERTION    0x08
#define CTAP_CREDENTIAL_MANAGEMENT 0x0A
#define CTAP_SELECTION             0x0B
#define CTAP_LARGE_BLOBS           0x0C
#define CTAP_CONFIG                0x0D
#define CTAP_CRED_MANAGE_LEGACY    0x41
#define CTAP_INVALID_CMD           0xFF
// clang-format on

// Parsed params
// clang-format off
#define PARAM_CLIENT_DATA_HASH       (1 << 0)
#define PARAM_RP                     (1 << 1)
#define PARAM_USER                   (1 << 2)
#define PARAM_PUB_KEY_CRED_PARAMS    (1 << 3)
#define PARAM_EXTENSIONS             (1 << 4)
#define PARAM_OPTIONS                (1 << 5)
#define PARAM_PIN_UV_AUTH_PARAM      (1 << 6)
#define PARAM_PIN_UV_AUTH_PROTOCOL   (1 << 7)
#define PARAM_SUB_COMMAND            (1 << 8)
#define PARAM_KEY_AGREEMENT          (1 << 9)
#define PARAM_NEW_PIN_ENC            (1 << 10)
#define PARAM_PIN_HASH_ENC           (1 << 11)
#define PARAM_HMAC_SECRET            (1 << 12)
#define PARAM_ENTERPRISE_ATTESTATION (1 << 13)
#define PARAM_PERMISSIONS            (1 << 14)
#define PARAM_CREDENTIAL_ID          (1 << 15)
#define PARAM_GET                    (1 << 16)
#define PARAM_SET                    (1 << 17)
#define PARAM_OFFSET                 (1 << 18)
#define PARAM_LENGTH                 (1 << 19)
#define PARAM_SUB_COMMAND_PARAMS     (1 << 20)
#define PARAM_NEW_MIN_PIN_LENGTH     (1 << 21)
#define PARAM_MIN_PIN_LENGTH_RPIDS   (1 << 22)
#define PARAM_FORCE_CHANGE_PIN       (1 << 23)
// clang-format on

#define MC_REQUIRED_MASK (PARAM_CLIENT_DATA_HASH | PARAM_RP | PARAM_USER | PARAM_PUB_KEY_CRED_PARAMS)
#define GA_REQUIRED_MASK (PARAM_CLIENT_DATA_HASH | PARAM_RP)
#define CP_REQUIRED_MASK (PARAM_SUB_COMMAND)
#define CM_REQUIRED_MASK (PARAM_SUB_COMMAND)
#define CONFIG_REQUIRED_MASK (PARAM_SUB_COMMAND)

// clang-format off
#define OPTION_FALSE  0x0
#define OPTION_TRUE   0x1
#define OPTION_ABSENT 0x2
// clang-format on

#define FLAGS_UP (1)
#define FLAGS_UV (1 << 2)
#define FLAGS_AT (1 << 6)
#define FLAGS_ED (1 << 7)

// clang-format off
#define CRED_PROTECT_ABSENT                                        0x00
#define CRED_PROTECT_VERIFICATION_OPTIONAL                         0x01
#define CRED_PROTECT_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST 0x02
#define CRED_PROTECT_VERIFICATION_REQUIRED                         0x03
// clang-format on

// Params for each command
// clang-format off
#define MC_REQ_CLIENT_DATA_HASH       0x01
#define MC_REQ_RP                     0x02
#define MC_REQ_USER                   0x03
#define MC_REQ_PUB_KEY_CRED_PARAMS    0x04
#define MC_REQ_EXCLUDE_LIST           0x05
#define MC_REQ_EXTENSIONS             0x06
#define MC_REQ_OPTIONS                0x07
#define MC_REQ_PIN_UV_AUTH_PARAM      0x08
#define MC_REQ_PIN_PROTOCOL           0x09
#define MC_REQ_ENTERPRISE_ATTESTATION 0x0A
#define MC_RESP_FMT                   0x01
#define MC_RESP_AUTH_DATA             0x02
#define MC_RESP_ATT_STMT              0x03
#define MC_RESP_EP_ATT                0x04
#define MC_RESP_LARGE_BLOB_KEY        0x05

#define GA_REQ_RP_ID                              0x01
#define GA_REQ_CLIENT_DATA_HASH                   0x02
#define GA_REQ_ALLOW_LIST                         0x03
#define GA_REQ_EXTENSIONS                         0x04
#define GA_REQ_OPTIONS                            0x05
#define GA_REQ_PIN_UV_AUTH_PARAM                  0x06
#define GA_REQ_PIN_UV_AUTH_PROTOCOL               0x07
#define GA_REQ_HMAC_SECRET_KEY_AGREEMENT          0x01
#define GA_REQ_HMAC_SECRET_SALT_ENC               0x02
#define GA_REQ_HMAC_SECRET_SALT_AUTH              0x03
#define GA_REQ_HMAC_SECRET_PIN_PROTOCOL           0x04
#define GA_RESP_CREDENTIAL                        0x01
#define GA_RESP_AUTH_DATA                         0x02
#define GA_RESP_SIGNATURE                         0x03
#define GA_RESP_PUBLIC_KEY_CREDENTIAL_USER_ENTITY 0x04
#define GA_RESP_NUMBER_OF_CREDENTIALS             0x05
#define GA_RESP_LARGE_BLOB_KEY                    0x07

#define GI_RESP_VERSIONS                        0x01
#define GI_RESP_EXTENSIONS                      0x02
#define GI_RESP_AAGUID                          0x03
#define GI_RESP_OPTIONS                         0x04
#define GI_RESP_MAX_MSG_SIZE                    0x05
#define GI_RESP_PIN_UV_AUTH_PROTOCOLS           0x06
#define GI_RESP_MAX_CREDENTIAL_COUNT_IN_LIST    0x07
#define GI_RESP_MAX_CREDENTIAL_ID_LENGTH        0x08
#define GI_RESP_TRANSPORTS                      0x09
#define GI_RESP_ALGORITHMS                      0x0A
#define GI_RESP_MAX_SERIALIZED_LARGE_BLOB_ARRAY 0x0B
#define GI_RESP_FORCE_PIN_CHANGE                0x0C
#define GI_RESP_MIN_PIN_LENGTH                  0x0D
#define GI_RESP_FIRMWARE_VERSION                0x0E
#define GI_RESP_MAX_CRED_BLOB_LENGTH            0x0F
#define GI_RESP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH 0x10
#define GI_RESP_REMAINING_DISCOVERABLE_CREDENTIALS 0x14
#define GI_RESP_ATTESTATION_FORMATS             0x16
#define GI_RESP_LONG_TOUCH_FOR_RESET            0x18
#define GI_RESP_TRANSPORTS_FOR_RESET            0x1A
#define GI_RESP_MAX_PIN_LENGTH                  0x1D
#define GI_RESP_AUTHENTICATOR_CONFIG_COMMANDS   0x1F

#define CP_REQ_PIN_UV_AUTH_PROTOCOL                             0x01
#define CP_REQ_SUB_COMMAND                                      0x02
#define CP_REQ_KEY_AGREEMENT                                    0x03
#define CP_REQ_PIN_UV_AUTH_PARAM                                0x04
#define CP_REQ_NEW_PIN_ENC                                      0x05
#define CP_REQ_PIN_HASH_ENC                                     0x06
#define CP_REQ_PERMISSIONS                                      0x09
#define CP_REQ_RP_ID                                            0x0A
#define CP_CMD_GET_PIN_RETRIES                                  0x01
#define CP_CMD_GET_KEY_AGREEMENT                                0x02
#define CP_CMD_SET_PIN                                          0x03
#define CP_CMD_CHANGE_PIN                                       0x04
#define CP_CMD_GET_PIN_TOKEN                                    0x05
#define CP_CMD_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS 0x09
#define CP_RESP_KEY_AGREEMENT                                   0x01
#define CP_RESP_PIN_UV_AUTH_TOKEN                               0x02
#define CP_RESP_PIN_RETRIES                                     0x03
#define CP_PERMISSION_MC                                        0x01
#define CP_PERMISSION_GA                                        0x02
#define CP_PERMISSION_CM                                        0x04
#define CP_PERMISSION_BE                                        0x08
#define CP_PERMISSION_LBW                                       0x10
#define CP_PERMISSION_ACFG                                      0x20

#define CM_REQ_SUB_COMMAND                                        0x01
#define CM_REQ_SUB_COMMAND_PARAMS                                 0x02
#define CM_REQ_PIN_UV_AUTH_PROTOCOL                               0x03
#define CM_REQ_PIN_UV_AUTH_PARAM                                  0x04
#define CM_CMD_GET_CREDS_METADATA                                 0x01
#define CM_CMD_ENUMERATE_RPS_BEGIN                                0x02
#define CM_CMD_ENUMERATE_RPS_GET_NEXT_RP                          0x03
#define CM_CMD_ENUMERATE_CREDENTIALS_BEGIN                        0x04
#define CM_CMD_ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL          0x05
#define CM_CMD_DELETE_CREDENTIAL                                  0x06
#define CM_CMD_UPDATE_USER_INFORMATION                            0x07
#define CM_PARAM_RP_ID_HASH                                       0x01
#define CM_PARAM_CREDENTIAL_ID                                    0x02
#define CM_PARAM_USER                                             0x03
#define CM_RESP_EXISTING_RESIDENT_CREDENTIALS_COUNT               0x01
#define CM_RESP_MAX_POSSIBLE_REMAINING_RESIDENT_CREDENTIALS_COUNT 0x02
#define CM_RESP_RP                                                0x03
#define CM_RESP_RP_ID_HASH                                        0x04
#define CM_RESP_TOTAL_RPS                                         0x05
#define CM_RESP_USER                                              0x06
#define CM_RESP_CREDENTIAL_ID                                     0x07
#define CM_RESP_PUBLIC_KEY                                        0x08
#define CM_RESP_TOTAL_CREDENTIALS                                 0x09
#define CM_RESP_CRED_PROTECT                                      0x0A
#define CM_RESP_LARGE_BLOB_KEY                                    0x0B
#define CM_RESP_THIRD_PARTY_PAYMENT                               0x0C
// clang-format on

#define LB_REQ_GET 0x01
#define LB_REQ_SET 0x02
#define LB_REQ_OFFSET 0x03
#define LB_REQ_LENGTH 0x04
#define LB_REQ_PIN_UV_AUTH_PARAM 0x05
#define LB_REQ_PIN_UV_AUTH_PROTOCOL 0x06
#define LB_RESP_CONFIG 0x01

#define CONFIG_REQ_SUB_COMMAND 0x01
#define CONFIG_REQ_SUB_COMMAND_PARAMS 0x02
#define CONFIG_REQ_PIN_UV_AUTH_PROTOCOL 0x03
#define CONFIG_REQ_PIN_UV_AUTH_PARAM 0x04
#define CONFIG_CMD_ENABLE_ENTERPRISE_ATTESTATION 0x01
#define CONFIG_CMD_TOGGLE_ALWAYS_UV 0x02
#define CONFIG_CMD_SET_MIN_PIN_LENGTH 0x03
#define CONFIG_CMD_ENABLE_LONG_TOUCH_FOR_RESET 0x04
#define CONFIG_CMD_VENDOR_PROTOTYPE 0xFF
#define CONFIG_PARAM_NEW_MIN_PIN_LENGTH 0x01
#define CONFIG_PARAM_MIN_PIN_LENGTH_RPIDS 0x02
#define CONFIG_PARAM_FORCE_CHANGE_PIN 0x03

// Size limits
// clang-format off
#define KH_KEY_SIZE                   32
#define HE_KEY_SIZE                   32
#define PRI_KEY_SIZE                  32
#define PUB_KEY_SIZE                  64
#define SHARED_SECRET_SIZE_P1         32
#define SHARED_SECRET_SIZE_P2         64
#define SHARED_SECRET_SIZE_HMAC       32
#define MAX_COSE_KEY_SIZE             78
#define PIN_ENC_SIZE_P1               64
#define PIN_ENC_SIZE_P2               80
#define PIN_HASH_SIZE_P1              16
#define PIN_HASH_SIZE_P2              32
#define MAX_CERT_SIZE                 1152
#define AAGUID_SIZE                   16
#define PIN_AUTH_SIZE_P1              16
#define PIN_TOKEN_SIZE                32
#define HMAC_SECRET_SALT_SIZE         64
#define HMAC_SECRET_SALT_IV_SIZE      16
#define HMAC_SECRET_SALT_AUTH_SIZE_P1 16
#define HMAC_SECRET_SALT_AUTH_SIZE_P2 32
#define CREDENTIAL_TAG_SIZE           16
#define CLIENT_DATA_HASH_SIZE         32
#define CREDENTIAL_NONCE_SIZE                    16
#define CREDENTIAL_NONCE_DC_POS                  16
#define CREDENTIAL_NONCE_CP_POS                  17
#define CREDENTIAL_NONCE_THIRD_PARTY_PAYMENT_POS CREDENTIAL_NONCE_CP_POS
#define DOMAIN_NAME_MAX_SIZE          254
#define USER_ID_MAX_SIZE              64
#define DISPLAY_NAME_LIMIT            65
#define USER_NAME_LIMIT               65
#define MAX_STORED_RPID_LENGTH        32
#define MAX_HMAC_SECRET_OUTPUT_IN_AUTH (HMAC_SECRET_SALT_IV_SIZE + HMAC_SECRET_SALT_SIZE)
// Map header plus all MakeCredential authData extension outputs supported here.
// `sizeof("key")` is the exact encoded size for these short CBOR text keys:
// one initial byte plus the key bytes, excluding the C string terminator.
#define MAX_EXTENSION_SIZE_IN_AUTH                                                                                     \
  (1 + sizeof("credBlob") + 1 + sizeof("credProtect") + 1 + sizeof("hmac-secret") + 1 +                            \
   sizeof("hmac-secret-mc") + 2 + MAX_HMAC_SECRET_OUTPUT_IN_AUTH + sizeof("minPinLength") + 2 +                     \
   sizeof("thirdPartyPayment") + 1)
#define MAX_CREDENTIAL_COUNT_IN_LIST  16
#define MAX_CRED_BLOB_LENGTH          32
#define LARGE_BLOB_KEY_SIZE           32
#define LARGE_BLOB_SIZE_LIMIT         4096
#define CTAP_DEFAULT_MIN_PIN_LENGTH        4
#define CTAP_MAX_PIN_LENGTH                63
#define CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH 4
#define MAX_FRAGMENT_LENGTH           (MAX_CTAP_BUFSIZE - 64)
#define MAX_CTAP_EXTERNAL_STRING_CHUNK MAX_FRAGMENT_LENGTH
// clang-format on

typedef struct {
  uint8_t len;
  char id[DOMAIN_NAME_MAX_SIZE];
} __packed CTAP_min_pin_rp_id;

typedef struct {
  uint8_t id[USER_ID_MAX_SIZE];
  uint8_t id_size;
  char name[USER_NAME_LIMIT];
  char display_name[DISPLAY_NAME_LIMIT];
} __packed user_entity;

typedef struct {
  uint8_t tag[CREDENTIAL_TAG_SIZE];
  uint8_t nonce[CREDENTIAL_NONCE_SIZE + 2]; // 16-byte random nonce + 1-byte dc + 1-byte flags
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  int32_t alg_type;
} __packed credential_id;

typedef struct {
  credential_id credential_id;
  user_entity user;
  // Deleted records are tombstones. They stay in place so enumeration cursors
  // and crash recovery can use stable file indexes, and future credentials can
  // reuse the slot without growing DC_FILE.
  bool deleted;
  bool has_large_blob_key;
  uint8_t cred_blob_len;
  uint8_t cred_blob[MAX_CRED_BLOB_LENGTH];
} __packed CTAP_discoverable_credential;

typedef struct {
  // Count of non-deleted discoverable credentials. pending_* records the file
  // index of an in-flight add/delete so ctap_consistency_check() can roll back
  // cleanly after a reset between the data-file and metadata-file writes.
  uint32_t numbers;
  uint32_t pending_index;
  uint8_t pending_op;
} __packed CTAP_dc_general_attr;

#define CTAP_DC_PENDING_NONE   0
#define CTAP_DC_PENDING_ADD    1
#define CTAP_DC_PENDING_DELETE 2

typedef struct {
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  uint8_t rp_id[MAX_STORED_RPID_LENGTH];
  uint8_t rp_id_len;
  // Number of live credentials for this RP. A zero-count entry becomes a
  // tombstone and may be reused by a later RP metadata record.
  uint32_t live_count;
  bool deleted;
} __packed CTAP_rp_meta;

typedef struct {
  uint8_t aaguid[AAGUID_SIZE];
  uint16_t credential_id_length;
  credential_id credential_id;
  uint8_t public_key[MAX_COSE_KEY_SIZE]; // public key in cose_key format
  // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
} __packed CTAP_attested_data;

typedef struct {
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  uint8_t flags;
  uint32_t sign_count;
  CTAP_attested_data at;
  uint8_t extensions[MAX_EXTENSION_SIZE_IN_AUTH];
} __packed CTAP_auth_data;

typedef struct {
  uint8_t up : 2;
  uint8_t uv : 2;
  uint8_t rk : 2;
} CTAP_options;

typedef struct {
  uint8_t key_agreement[PUB_KEY_SIZE];
  uint8_t salt_enc[HMAC_SECRET_SALT_IV_SIZE + HMAC_SECRET_SALT_SIZE];
  uint8_t salt_enc_len;
  uint8_t salt_auth[HMAC_SECRET_SALT_AUTH_SIZE_P2];
  uint8_t salt_auth_len;
  uint8_t pin_protocol;
} CTAP_hmac_secret_ext;

typedef struct {
  uint32_t parsed_params;
  uint8_t client_data_hash[CLIENT_DATA_HASH_SIZE];
  uint8_t rp_id[MAX_STORED_RPID_LENGTH];
  size_t rp_id_len;
  uint8_t rp_id_full[DOMAIN_NAME_MAX_SIZE];
  size_t rp_id_full_len;
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  user_entity user;
  int32_t alg_type;
  credential_id exclude_list[MAX_CREDENTIAL_COUNT_IN_LIST];
  size_t exclude_list_size;
  CTAP_options options;
  uint8_t pin_uv_auth_param[SHA256_DIGEST_LENGTH];
  size_t pin_uv_auth_param_len;
  uint8_t pin_uv_auth_protocol;
  bool ext_hmac_secret;
  bool ext_hmac_secret_mc;
  CTAP_hmac_secret_ext ext_hmac_secret_data;
  bool ext_large_blob_key;
  bool ext_third_party_payment;
  bool ext_min_pin_length;
  uint8_t ext_cred_protect;
  uint8_t ext_cred_blob[MAX_CRED_BLOB_LENGTH];
  uint8_t ext_has_cred_blob : 1;
  uint8_t ext_cred_blob_len : 7;
} CTAP_make_credential;

typedef struct {
  uint32_t parsed_params;
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  uint8_t client_data_hash[CLIENT_DATA_HASH_SIZE];
  credential_id allow_list[MAX_CREDENTIAL_COUNT_IN_LIST];
  size_t allow_list_size;
  CTAP_options options;
  uint8_t pin_uv_auth_param[SHA256_DIGEST_LENGTH];
  size_t pin_uv_auth_param_len;
  uint8_t pin_uv_auth_protocol;
  CTAP_hmac_secret_ext ext_hmac_secret_data;
  bool ext_large_blob_key;
  bool ext_cred_blob;
  bool ext_third_party_payment;
} CTAP_get_assertion;

typedef struct {
  uint32_t parsed_params;
  uint8_t sub_command;
  uint8_t pin_uv_auth_protocol;
  uint8_t key_agreement[PUB_KEY_SIZE];
  uint8_t pin_uv_auth_param[SHA256_DIGEST_LENGTH];
  uint8_t new_pin_enc[PIN_ENC_SIZE_P2];
  uint8_t pin_hash_enc[PIN_HASH_SIZE_P2];
  uint8_t permissions;
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
} CTAP_client_pin;

typedef struct {
  uint32_t parsed_params;
  uint8_t sub_command;
  uint32_t sub_command_params_offset;
  size_t param_len;
  uint8_t rp_id_hash[SHA256_DIGEST_LENGTH];
  credential_id credential_id;
  user_entity user;
  uint8_t pin_uv_auth_protocol;
  uint8_t pin_uv_auth_param[SHA256_DIGEST_LENGTH];
} CTAP_credential_management;

typedef struct {
  uint32_t parsed_params;
  uint8_t sub_command;
  uint32_t sub_command_params_offset;
  size_t param_len;
  uint8_t pin_uv_auth_protocol;
  uint8_t pin_uv_auth_param[SHA256_DIGEST_LENGTH];
  uint8_t new_min_pin_length;
  bool force_change_pin;
  uint8_t min_pin_rpid_count;
  CTAP_min_pin_rp_id min_pin_rpids[CTAP_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH];
} CTAP_config;

typedef struct {
  uint32_t parsed_params;
  uint16_t get;
  uint32_t set_offset;
  size_t set_len;
  uint16_t offset;
  uint16_t length;
  uint8_t pin_uv_auth_protocol;
  uint8_t pin_uv_auth_param[SHA256_DIGEST_LENGTH];
} CTAP_large_blobs;

typedef struct {
  int32_t curve_id;
  int32_t algo_id;
} __packed CTAP_sm2_attr;

int u2f_register(const CAPDU *capdu, RAPDU *rapdu);
int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu);
int u2f_version(const CAPDU *capdu, RAPDU *rapdu);
int u2f_select(const CAPDU *capdu, RAPDU *rapdu);
uint8_t ctap_make_auth_data(uint8_t *rp_id_hash, uint8_t *buf, uint8_t flags, const uint8_t *extension,
                            size_t extension_size, size_t *len, int32_t alg_type, bool dc, uint8_t cred_protect);

#endif
