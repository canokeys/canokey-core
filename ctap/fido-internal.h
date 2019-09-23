#ifndef FIDO_INTERNAL_H_
#define FIDO_INTERNAL_H_

int u2f_register(const CAPDU *capdu, RAPDU *rapdu);
int u2f_authenticate(const CAPDU *capdu, RAPDU *rapdu);
int u2f_version(const CAPDU *capdu, RAPDU *rapdu);
int u2f_select(const CAPDU *capdu, RAPDU *rapdu);
void u2f_config(void);

uint8_t ctap_make_auth_data(uint8_t *rpIdHash, uint8_t *buf, uint8_t at, uint8_t uv, uint8_t up, size_t *len);

#endif

