/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_FIDO2_FIDO2_H_
#define CANOKEY_CORE_FIDO2_FIDO2_H_

#include <apdu.h>
#include <ctaphid.h>
#include <stddef.h>
#include <stdint.h>

#define CTAP_INS_MSG 0x10

typedef enum {
  CTAP_SRC_NONE,
  CTAP_SRC_CCID,
  CTAP_SRC_HID,
} ctap_src_t;

typedef int (*ctap_req_read_t)(void *ctx, size_t offset, uint8_t *buf, size_t len);
typedef int (*ctap_req_cancelled_t)(void *ctx);

typedef struct {
  ctap_req_read_t read;
  ctap_req_cancelled_t cancelled;
  void *ctx;
  size_t base_offset;
  size_t len;
} ctap_req_src_t;

uint8_t ctap_install(uint8_t reset);
void ctap_poweroff(void);
void ctap_deselect(void);
void ctap_schedule_runtime_reset(void);
int ctap_install_private_key(const CAPDU *capdu, RAPDU *rapdu);
int ctap_install_cert(const CAPDU *capdu, RAPDU *rapdu);
int ctap_read_sm2_config(const CAPDU *capdu, RAPDU *rapdu);
int ctap_write_sm2_config(const CAPDU *capdu, RAPDU *rapdu);

// Platform storage for the vendor SM2 COSE identifiers.
int ctap_platform_sm2_config_read(void *cfg, size_t len);
int ctap_platform_sm2_config_write(const void *cfg, size_t len);
// Platform storage for CTAP 2.3 persistent options such as min PIN length and alwaysUV.
int ctap_platform_persistent_config_read(void *cfg, size_t len);
int ctap_platform_persistent_config_write(const void *cfg, size_t len);

int ctap_process_cbor_with_src(uint8_t *req, size_t req_len, uint8_t *resp, size_t *resp_len, ctap_src_t src);
// Returns 1 on success with `*source` populated, or -1 on failure.
int ctap_process_cbor_stream_source_with_src(const ctap_req_src_t *req_src, uint8_t *scratch, size_t scratch_len,
                                             CTAPHID_TxSource *source, ctap_src_t src);
// Returns 1 on success with `*source` populated, or -1 on failure.
int ctap_process_cbor_stream_with_src(uint8_t *req, size_t req_len, uint8_t *scratch, size_t scratch_len,
                                      CTAPHID_TxSource *source, ctap_src_t src);
int ctap_process_apdu_source_with_src(const CAPDU *capdu, const ctap_req_src_t *req_src, RAPDU *rapdu, ctap_src_t src);
int ctap_process_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src);
int ctap_process_pke_apdu_with_src(const CAPDU *capdu, RAPDU *rapdu, ctap_src_t src);
int ctap_nfc_pending_active(void);
#ifdef TEST
void ctap_test_seed_get_next_assertion_state(void);
void ctap_test_seed_credential_management_state(void);
int ctap_test_credential_management_state_active(void);
#endif
static inline int ctap_process_apdu(const CAPDU *capdu, RAPDU *rapdu) {
  return ctap_process_apdu_with_src(capdu, rapdu, CTAP_SRC_CCID);
}
int ctap_wink(void);

#endif // CANOKEY_CORE_FIDO2_FIDO2_H_
