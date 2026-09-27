// SPDX-License-Identifier: Apache-2.0
#ifndef CANOKEY_PLATFORM_CONFIG_LAYOUT_H
#define CANOKEY_PLATFORM_CONFIG_LAYOUT_H
/* Native-endian on-flash format owned and statically checked by
 * src/platform-config.c. The CIU port's platform/rust-core/services.c includes
 * this layout to read identity for Rust; that reader must not initialize it. */
#define CONFIG_MAGIC 0x434B4346u
#define CONFIG_VERSION 1u
#define CONFIG_HEADER_LEN 0x20u
#define CONFIG_FLAG_SN_VALID (1u << 5)
#define CONFIG_PAGE_BYTES 512u
#define CONFIG_MAGIC_OFFSET 4u
#define CONFIG_VERSION_OFFSET 8u
#define CONFIG_HEADER_LEN_OFFSET 9u
#define CONFIG_PAGE_LEN_OFFSET 10u
#define CONFIG_FLAGS_OFFSET 12u
#define CONFIG_SERIAL_OFFSET 16u
#define CONFIG_CRC_OFFSET 508u
#define CONFIG_CRC_BYTES (CONFIG_CRC_OFFSET - CONFIG_MAGIC_OFFSET)
#endif
