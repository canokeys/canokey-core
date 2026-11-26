/* SPDX-License-Identifier: Apache-2.0 */
/* Native C support declarations. */
#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <stdbool.h>

#include <stdint.h>

// only for test
#define TESTMODE_ERR_WRITE 0
#define TESTMODE_ERR_READ 1

void testmode_inject_error(uint8_t p1, uint8_t p2, uint16_t len, const uint8_t *data);
bool testmode_err_triggered(const char *filename, bool file_wr);

#endif // _DEVICE_H_
