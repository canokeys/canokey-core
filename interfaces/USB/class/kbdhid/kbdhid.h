/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __KBDHID_H_INCLUDED__
#define __KBDHID_H_INCLUDED__

#include <common.h>

uint8_t KBDHID_Init(void);
uint8_t KBDHID_Loop(void);
void KBDHID_Eject(void);

#endif // __KBDHID_H_INCLUDED__
