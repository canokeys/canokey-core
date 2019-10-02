#ifndef CANOKEY_CORE_FIDO2_FIDO2_H_
#define CANOKEY_CORE_FIDO2_FIDO2_H_

#include <apdu.h>
#include <stdint.h>

uint8_t ctap_install(uint8_t reset);
int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu);
int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu);
int ctap_process_cbor(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len);
int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_FIDO2_FIDO2_H_
