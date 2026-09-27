/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CK_CCID_IO_H
#define CK_CCID_IO_H
#include <stddef.h>
#include <stdint.h>
/* Main-loop packet lease API. IRQs may call disjoint Rust USB state, never the applet runtime. Generation is checked
 * inside each operation's critical section. A submitted buffer is immutable
 * until idle or a real bus reset has quiesced the controller. */
uint32_t ck_ccid_io_generation(void);
uint32_t ck_ccid_io_now(void);
uint8_t ck_ccid_io_pending(void);
int32_t ck_ccid_io_peek(void);
/* Copy up to 64 bytes and rearm only after ending the hardware RX borrow. */
int32_t ck_ccid_io_take(uint32_t generation, uint8_t output[64], uint32_t *tick);
uint8_t ck_ccid_io_idle(void);
/* 1 accepted, 0 busy, -1 disconnected/stale. zlp is Rust transfer policy. */
int32_t ck_ccid_io_submit(uint32_t generation, const uint8_t *bytes, uint16_t length, uint8_t zlp);
/* Copies <=16 opaque bytes. No protocol decoding or callbacks into Rust. */
void ck_ccid_io_arm(uint32_t generation, const uint8_t *bytes, uint8_t length, uint16_t interval);
void ck_ccid_io_disarm(void);
uint8_t ck_ccid_io_live(void);
#endif
