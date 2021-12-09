// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_QEMU_H
#define CANOKEY_QEMU_H

/* Implemented by qemu, note the void* key */
int canokey_emu_stall_ep(void* key, uint8_t ep);
int canokey_emu_set_address(void* key, uint8_t addr);
int canokey_emu_prepare_receive(void* key, uint8_t ep, uint8_t *pbuf, uint16_t size);
int canokey_emu_transmit(void* key, uint8_t ep, const uint8_t *pbuf, uint16_t size);
uint32_t canokey_emu_get_rx_data_size(void* key, uint8_t ep);

/* Implemented in qemu.c */
int canokey_emu_init(void* key, const char* file); /* store void* key in the lib */
void canokey_emu_reset(void);
void canokey_emu_device_loop(void);
void canokey_emu_setup(int request, int value, int index, int length);
void canokey_emu_data_out(uint8_t ep, uint8_t *data);
void canokey_emu_data_in(uint8_t ep);

#endif /* CANOKEY_QEMU_H */
