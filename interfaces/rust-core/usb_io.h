/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CK_USB_IO_H
#define CK_USB_IO_H
#include <stdint.h>
#include <stddef.h>
/* IRQ-local Rust USB state is disjoint from applet/core state. Raw hardware
 * operations never call Rust synchronously. Every USB access is serialized by
 * the IRQ mask; restore the incoming mask, do not unconditionally enable IRQs. */
uint32_t ck_usb_dcd_lock(void);
void ck_usb_dcd_unlock(uint32_t mask);
void ck_usb_dcd_start(void);
void ck_usb_dcd_stop(void);
void ck_usb_dcd_open(uint8_t endpoint);
void ck_usb_dcd_close(uint8_t endpoint);
void ck_usb_dcd_stall(uint8_t endpoint, uint8_t halt);
void ck_usb_dcd_address(uint8_t address);
void ck_usb_dcd_receive(uint8_t endpoint);
uint8_t ck_usb_dcd_write(uint8_t endpoint, const uint8_t *bytes, uint16_t length);
void ck_usb_dcd_ready(uint8_t ready);
/* Hardware event calls, IRQ masked. OUT returns 1 to release FIFO, 0 to NAK. */
void ck_usb_reset(void);
void ck_usb_suspend(void);
void ck_usb_resume(void);
void ck_usb_setup(const uint8_t *bytes, uint16_t length);
void ck_usb_in(uint8_t endpoint);
uint8_t ck_usb_out(uint8_t endpoint, const uint8_t *bytes, uint16_t length);
/* Packet adapters may call these from masked main loop/timer/USB IRQ. */
uint8_t ck_usb_configured(void);
uint8_t ck_usb_tx_idle(uint8_t endpoint);
int32_t ck_usb_submit(uint8_t endpoint, const uint8_t *bytes, uint16_t length, uint8_t zlp);
void ck_usb_receive(uint8_t endpoint);
void usb_device_init(void);
void usb_device_deinit(void);
/* Packet mailboxes; these callbacks do not enter applet/core Rust state. */
void ck_ccid_packet_reset(void);
uint8_t ck_ccid_packet_out(const uint8_t *bytes, uint16_t length);
void ck_hid_packet_reset(void);
uint8_t ck_hid_packet_out(const uint8_t *bytes);
void ck_keyboard_packet_reset(void);
#endif
