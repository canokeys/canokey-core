/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_PIV_H_
#define CANOKEY_CORE_INCLUDE_PIV_H_

#include <apdu.h>

// clang-format off
#define PIV_INS_VERIFY                       0x20
#define PIV_INS_CHANGE_REFERENCE_DATA        0x24
#define PIV_INS_RESET_RETRY_COUNTER          0x2C
#define PIV_INS_GENERATE_ASYMMETRIC_KEY_PAIR 0x47
#define PIV_INS_GENERAL_AUTHENTICATE         0x87
#define PIV_INS_SELECT                       0xA4
#define PIV_INS_GET_DATA_RESPONSE            0xC0
#define PIV_INS_GET_DATA                     0xCB
#define PIV_INS_PUT_DATA                     0xDB
#define PIV_INS_GET_METADATA                 0xF7
#define PIV_INS_GET_SERIAL                   0xF8
// Yubico PIV attestation extension: 00 F9 <slot> 00, no data. The response is
// a DER X.509 certificate signed by the P-256 key in F9. Only keys generated on
// the device can be attested; no PIN or management-key authentication is
// required. F9 key/certificate storage survives PIV reset.
#define PIV_INS_ATTEST                       0xF9
// Yubico vendor extension: 00 F6 <toSlot> <fromSlot>, no data.
// toSlot=FF deletes the key. Moving and deleting require management-key
// authentication, accept only ordinary asymmetric slots (9A/9C/9D/9E and
// 82..95), and affect only the asymmetric key; certificate objects stay in
// their original slots. The F9 attestation key is not movable or deletable.
#define PIV_INS_MOVE_DELETE_KEY              0xF6
// Vendor extension: 00 FA <pinRetries> <pukRetries>, no data.
// Requires management-key and PIN authentication, then resets PIN/PUK to
// their defaults with the requested retry limits.
#define PIV_INS_SET_PIN_RETRIES              0xFA
#define PIV_INS_RESET                        0xFB
#define PIV_INS_GET_VERSION                  0xFD
#define PIV_INS_IMPORT_ASYMMETRIC_KEY        0xFE
#define PIV_INS_SET_MANAGEMENT_KEY           0xFF

#define PIV_INS_ALGORITHM_EXTENSION          0xEE
// clang-format on

#define PIV_CERT_OBJECT_MAX_SIZE 6144

/*
 * Post-quantum PIV extensions use the configurable algorithm IDs below
 * (defaults: ML-DSA-65 = E2, ML-KEM-768 = E3). ML-DSA GENERAL AUTHENTICATE
 * accepts 7C { 82 00, 81 <message> } through Short APDU command chaining and
 * hashes the message incrementally; Extended APDUs are rejected. ML-KEM key
 * generation uses the standard 00 47 command. Import accepts exactly one 0A 40 <64-byte d || z>
 * component followed by the common AA/AB policy tags. Only d || z is persisted;
 * the 1184-byte public key is derived for GENERATE/GET METADATA responses and
 * the 2400-byte expanded decapsulation key is never stored. GENERAL
 * AUTHENTICATE takes a 1088-byte ciphertext in tag 81 and returns the 32-byte
 * shared secret in tag 82.
 *
 * GENERAL AUTHENTICATE with P1=FF is a vendor randomized Ed25519 signing mode.
 * It uses the same chained 7C { 82 00, 81 <message> } request and returns a
 * standard 64-byte Ed25519 signature in tag 82. The device generates and mixes
 * the nonce randomness; the host does not provide r. Repeated signatures may
 * differ. Normal Ed25519 uses its configured algorithm ID, remains RFC 8032
 * deterministic, and accepts at most APPLET_SHARED_BUFFER_LENGTH (currently
 * 544) message bytes. P1=FF is available only while algorithm extensions are
 * enabled.
 */
typedef struct {
  uint8_t enabled;
  uint8_t ed25519;
  uint8_t rsa3072;
  uint8_t rsa4096;
  uint8_t x25519;
  uint8_t secp256k1;
  uint8_t secp521r1;
  uint8_t sm2;
  uint8_t mldsa65;
  uint8_t mlkem768;
} __packed piv_algorithm_extension_config_t;

/*
 * Ordinary asymmetric slots (9A/9C/9D/9E and 82..95) do not restrict key
 * usage. The key type and GENERAL AUTHENTICATE template determine which
 * operation is possible. F9 remains signing-only and 9B remains AES-only.
 */

int piv_install(uint8_t reset);
void piv_poweroff(void);
int piv_process_apdu(const CAPDU *capdu, RAPDU *rapdu);
int piv_process_apdu_message(RAPDU_CHAINING *rapdu_chaining, CAPDU *capdu, RAPDU *rapdu);

/*
 * Platform storage for configurable PIV algorithm IDs. Core uses a valid
 * platform record as the PIV install completion marker.
 */
int piv_platform_algorithm_extension_config_read(piv_algorithm_extension_config_t *cfg);
int piv_platform_algorithm_extension_config_write(const piv_algorithm_extension_config_t *cfg);

#endif // CANOKEY_CORE_INCLUDE_PIV_H_
