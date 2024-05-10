/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_FIDO2_CTAP_ERRORS_H_
#define CANOKEY_CORE_FIDO2_CTAP_ERRORS_H_

#define CTAP1_ERR_SUCCESS                   0x00
#define CTAP1_ERR_INVALID_COMMAND           0x01
#define CTAP1_ERR_INVALID_PARAMETER         0x02
#define CTAP1_ERR_INVALID_LENGTH            0x03
#define CTAP1_ERR_INVALID_SEQ               0x04
#define CTAP1_ERR_TIMEOUT                   0x05
#define CTAP1_ERR_CHANNEL_BUSY              0x06
#define CTAP1_ERR_LOCK_REQUIRED             0x0A
#define CTAP1_ERR_INVALID_CHANNEL           0x0B
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE      0x11
#define CTAP2_ERR_INVALID_CBOR              0x12
#define CTAP2_ERR_MISSING_PARAMETER         0x14
#define CTAP2_ERR_LIMIT_EXCEEDED            0x15
#define CTAP2_ERR_FP_DATABASE_FULL          0x17
#define CTAP2_ERR_LARGE_BLOB_STORAGE_FULL   0x18
#define CTAP2_ERR_CREDENTIAL_EXCLUDED       0x19
#define CTAP2_ERR_PROCESSING                0x21
#define CTAP2_ERR_INVALID_CREDENTIAL        0x22
#define CTAP2_ERR_USER_ACTION_PENDING       0x23
#define CTAP2_ERR_OPERATION_PENDING         0x24
#define CTAP2_ERR_NO_OPERATIONS             0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM     0x26
#define CTAP2_ERR_OPERATION_DENIED          0x27
#define CTAP2_ERR_KEY_STORE_FULL            0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION        0x2B
#define CTAP2_ERR_INVALID_OPTION            0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL          0x2D
#define CTAP2_ERR_NO_CREDENTIALS            0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT       0x2F
#define CTAP2_ERR_NOT_ALLOWED               0x30
#define CTAP2_ERR_PIN_INVALID               0x31
#define CTAP2_ERR_PIN_BLOCKED               0x32
#define CTAP2_ERR_PIN_AUTH_INVALID          0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED          0x34
#define CTAP2_ERR_PIN_NOT_SET               0x35
#define CTAP2_ERR_PUAT_REQUIRED             0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION      0x37
#define CTAP2_ERR_REQUEST_TOO_LARGE         0x39
#define CTAP2_ERR_ACTION_TIMEOUT            0x3A
#define CTAP2_ERR_UP_REQUIRED               0x3B
#define CTAP2_ERR_UV_BLOCKED                0x3C
#define CTAP2_ERR_INTEGRITY_FAILURE         0x3D
#define CTAP2_ERR_INVALID_SUBCOMMAND        0x3E
#define CTAP2_ERR_UV_INVALID                0x3F
#define CTAP2_ERR_UNAUTHORIZED_PERMISSION   0x40
#define CTAP1_ERR_OTHER                     0x7F
#define CTAP2_ERR_SPEC_LAST                 0xDF
#define CTAP2_ERR_EXTENSION_FIRST           0xE0
#define CTAP2_ERR_EXTENSION_LAST            0xEF
#define CTAP2_ERR_VENDOR_FIRST              0xF0
#define CTAP2_ERR_UNHANDLED_REQUEST         0xF1
#define CTAP2_ERR_VENDOR_LAST               0xFF

#endif // CANOKEY_CORE_FIDO2_CTAP_ERRORS_H_
