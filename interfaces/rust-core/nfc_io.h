// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_RUST_NFC_IO_H
#define CANOKEY_RUST_NFC_IO_H
#include <stdint.h>
/* Raw chip operations only. The Rust caller serializes bus and protocol state
 * with this mask; restoring it must preserve an already masked caller. */
uint32_t ck_nfc_io_lock(void);
void ck_nfc_io_unlock(uint32_t mask);
int32_t ck_nfc_io_read(uint16_t address, uint8_t *bytes, uint8_t length);
int32_t ck_nfc_io_write(uint16_t address, const uint8_t *bytes, uint8_t length);
uint32_t ck_nfc_io_now(void);
void ck_nfc_io_select(uint8_t active);
void ck_nfc_io_delay(uint16_t milliseconds);
/* One-shot hardware callback. Callbacks may enter disjoint Rust NFC IRQ state,
 * but never the main-loop Core, storage or crypto workspace. */
void ck_nfc_io_schedule(void (*callback)(void), uint16_t milliseconds);
#endif
