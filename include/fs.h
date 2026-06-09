/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CORE_INCLUDE_FS_H
#define CANOKEY_CORE_INCLUDE_FS_H

#include <lfs.h>

#define LFS_CACHE_SIZE 512

int fs_format(const struct lfs_config *cfg);
int fs_mount(const struct lfs_config *cfg);
int read_file(const char *path, void *buf, lfs_soff_t off, lfs_size_t len);
int write_file(const char *path, const void *buf, lfs_soff_t off, lfs_size_t len, uint8_t trunc);
int append_file(const char *path, const void *buf, lfs_size_t len);
int truncate_file(const char *path, lfs_size_t len);
int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len);
int write_attr(const char *path, uint8_t attr, const void *buf, lfs_size_t len);
int remove_attr(const char *path, uint8_t attr);
int get_file_size(const char *path);
int fs_rename(const char *old, const char *new);
int remove_file(const char *path);

/**
 * Get the total size (in KiB) of the file system.
 *
 * @return The total file system size.
 */
int get_fs_size(void);

/**
 * Get the used size (in KiB) of the file system.
 *
 * @return The used file system size.
 */
int get_fs_usage(void);

/**
 * Estimate currently available file system space in bytes.
 *
 * LittleFS allocates storage in blocks and may need additional metadata blocks
 * for a write. Treat this as an estimate for admission control, not as a
 * guarantee that a later write cannot fail.
 *
 * @return Estimated free bytes, or a negative LittleFS error.
 */
int get_fs_free_bytes(void);

/**
 * Return whether the file system has enough estimated space for a write while
 * keeping reserve_bytes free.
 */
int fs_has_free_space(lfs_size_t write_bytes, lfs_size_t reserve_bytes);

#endif // CANOKEY_CORE_INCLUDE_FS_H
