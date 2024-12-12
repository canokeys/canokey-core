/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_FIDO2_FIDO2_H_
#define CANOKEY_CORE_FIDO2_FIDO2_H_

#include <apdu.h>
#include <stdint.h>

typedef enum {
    CTAP_SRC_NONE,
    CTAP_SRC_CCID,
    CTAP_SRC_HID,
} ctap_src_t;

uint8_t ctap_install(uint8_t reset);
int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu);
int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu);
int ctap_read_sm2_config(const CAPDU *capdu, RAPDU *rapdu);
int ctap_write_sm2_config(const CAPDU *capdu, RAPDU *rapdu);
int ctap_process_cbor_with_src(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len, ctap_src_t src);
int ctap_process_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src);
static int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
    return ctap_process_apdu_with_src(capdu, rapdu, CTAP_SRC_CCID);
}
int ctap_wink(void);

#endif // CANOKEY_CORE_FIDO2_FIDO2_H_
