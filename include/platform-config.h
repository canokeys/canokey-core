/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_PLATFORM_CONFIG_H_
#define CANOKEY_CORE_INCLUDE_PLATFORM_CONFIG_H_

#include <stddef.h>
#include <stdint.h>

#define PLATFORM_CONFIG_PAGE_SIZE 512u

/*
 * Platform storage hooks for the core-owned config page.
 *
 * Reads may address any byte range in the page. Writes are always full-page:
 * platform_config_page_write() is called only with PLATFORM_CONFIG_PAGE_SIZE
 * bytes, and ports backed by erase-block flash should reject partial writes.
 */
int platform_config_page_read(size_t off, void *buf, size_t len);
int platform_config_page_write(const void *page, size_t len);

#endif // CANOKEY_CORE_INCLUDE_PLATFORM_CONFIG_H_
