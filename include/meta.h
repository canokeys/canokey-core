/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_META_H
#define CANOKEY_CORE_INCLUDE_META_H

#include <apdu.h>

#define META_INS_SELECT 0xA4
#define META_INS_READ_META 0x1D

int meta_process_apdu(const CAPDU *capdu, RAPDU *rapdu);

#endif // CANOKEY_CORE_INCLUDE_META_H
