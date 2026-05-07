/* SPDX-License-Identifier: Apache-2.0 */
#ifndef __KBDHID_H_INCLUDED__
#define __KBDHID_H_INCLUDED__

#include <common.h>

uint8_t KBDHID_Init(void);
uint8_t KBDHID_Loop(void);
void KBDHID_Eject(void);
uint8_t KBDHID_SetFeatureReport(const uint8_t *report, uint16_t len);
uint8_t KBDHID_GetFeatureReport(uint8_t *report, uint16_t len);

#endif // __KBDHID_H_INCLUDED__
