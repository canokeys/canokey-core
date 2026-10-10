/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __KBDHID_H_INCLUDED__
#define __KBDHID_H_INCLUDED__

#include <common.h>
#include <stdbool.h>

uint8_t KBDHID_Init(void);
uint8_t KBDHID_Loop(void);
void KBDHID_Eject(void);

/*
 * Optional platform ASCII translation override.
 *
 * Return true after filling a HID modifier and usage. Return false to let
 * KBDHID use its built-in QWERTY mapping.
 */
bool kbdhid_platform_translate_ascii(uint8_t ch, uint8_t *modifier, uint8_t *usage);

#endif // __KBDHID_H_INCLUDED__
