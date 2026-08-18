// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_CORE_PIV_ATTESTATION_H
#define CANOKEY_CORE_PIV_ATTESTATION_H

#include <stdint.h>

/*
 * Build and register a YubiKey-compatible PIV attestation certificate
 * response. Returns an ISO 7816 status word, or -1 for an internal I/O error.
 */
int piv_attestation_generate(uint8_t slot, const char *target_key_path, const char *attestation_key_path,
                             const char *attestation_cert_path);

#endif // CANOKEY_CORE_PIV_ATTESTATION_H
