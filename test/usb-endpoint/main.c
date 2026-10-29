// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdio.h>
#include <apdu.h>
#include <usbd_ioreq.h>

static unsigned control_stalls, target_sets, target_clears, status_sent, class_calls;
static uint8_t halted, wire[2];
int release_apdu_buffer(uint8_t owner) { (void)owner; return 0; }
USBD_StatusTypeDef USBD_LL_StallEP(USBD_HandleTypeDef *p, uint8_t ep) {
  (void)p;
  if ((ep & 0x7f) == 0) ++control_stalls;
  else { assert(ep == 0x82); ++target_sets; halted = 1; }
  return USBD_OK;
}
USBD_StatusTypeDef USBD_LL_ClearStallEP(USBD_HandleTypeDef *p, uint8_t ep) {
  (void)p; assert(ep == 0x82); ++target_clears; halted = 0; return USBD_OK;
}
uint8_t USBD_LL_IsStallEP(USBD_HandleTypeDef *p, uint8_t ep) {
  (void)p; assert(ep == 0x82); return halted;
}
USBD_StatusTypeDef USBD_CtlSendStatus(USBD_HandleTypeDef *p) {
  (void)p; ++status_sent; return USBD_OK;
}
USBD_StatusTypeDef USBD_CtlSendData(USBD_HandleTypeDef *p, const uint8_t *b, uint16_t n, uint8_t sender) {
  (void)p; (void)sender; assert(n == 2); wire[0] = b[0]; wire[1] = b[1]; return USBD_OK;
}
static uint8_t class_setup(USBD_HandleTypeDef *p, USBD_SetupReqTypedef *r) {
  (void)p; (void)r; ++class_calls; return USBD_FAIL;
}
static const USBD_ClassTypeDef cls = {.Setup = class_setup};
static void reset_counts(void) {
  control_stalls = target_sets = target_clears = status_sent = class_calls = 0;
}
static void reject(USBD_HandleTypeDef *p, USBD_SetupReqTypedef r) {
  for (unsigned state = 0; state < 2; ++state) {
    halted = state; reset_counts(); USBD_StdEPReq(p, &r);
    assert(control_stalls == 2 && target_sets == 0 && target_clears == 0);
    assert(status_sent == 0 && class_calls == 0 && halted == state);
  }
}
int main(void) {
  USBD_HandleTypeDef p = {.dev_state = USBD_STATE_CONFIGURED, .ep_in_mask = 1u << 2, .pClass = &cls};
  for (unsigned op = 1; op <= 3; op += 2) {
    USBD_SetupReqTypedef valid = {.bmRequest = 2, .bRequest = op, .wIndex = 0x82};
    for (unsigned initial = 0; initial < 2; ++initial) {
      halted = initial; reset_counts(); USBD_StdEPReq(&p, &valid);
      assert(control_stalls == 0 && class_calls == 0 && status_sent == 1);
      assert(target_sets == (op == 3) && target_clears == (op == 1));
      assert(halted == (op == 3));
      USBD_SetupReqTypedef status = {.bmRequest = 0x82, .bRequest = 0, .wIndex = 0x82, .wLength = 2};
      USBD_StdEPReq(&p, &status); assert(wire[0] == halted && wire[1] == 0);
    }
    const uint16_t invalid[] = {0, 0x80, 1, 0x81, 2, 3, 0x83, 0x84, 0x92, 0x0182, 0xff82};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
      USBD_SetupReqTypedef r = valid; r.wIndex = invalid[i]; reject(&p, r);
    }
    USBD_SetupReqTypedef r = valid; r.wValue = 1; reject(&p, r);
    r = valid; r.wLength = 1; reject(&p, r);
    r = valid; r.bmRequest = 0x82; reject(&p, r);
    p.ep_in_mask = 0; reject(&p, valid); p.ep_in_mask = 1u << 2;
    p.dev_state = USBD_STATE_ADDRESSED; reject(&p, valid);
    p.dev_state = USBD_STATE_DEFAULT; reject(&p, valid);
    p.dev_state = USBD_STATE_CONFIGURED;
  }
  puts("PASS endpoint halt: valid requests, DATA-toggle reset call, little-endian status, invalid indices/requests, membership/direction and device state");
}
