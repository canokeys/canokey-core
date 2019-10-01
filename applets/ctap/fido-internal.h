#ifndef FIDO_INTERNAL_H_
#define FIDO_INTERNAL_H_

int u2f_register(const CAPDU *capdu, RAPDU *rapdu);
int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu);
int u2f_version(const CAPDU *capdu, RAPDU *rapdu);
int u2f_select(const CAPDU *capdu, RAPDU *rapdu);
uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t flags, uint8_t extensionSize,
                            const uint8_t *extension, size_t *len);

#endif
