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

/**
 * Write file data from offset 0 and commit the listed attributes together
 * with the data in a single atomic commit.
 *
 * Atomic-update contract: the file data and every listed attribute become
 * visible in one commit. Existing attributes not listed in attrs are
 * preserved. A zero-length attribute is legal: it exists but holds no bytes,
 * and its buffer may be NULL. On storage error the outcome is uncertain:
 * after a remount the file is either the old version or the complete new
 * version, never a mix of both.
 *
 * Arguments are validated before the file is opened, and a validation failure
 * returns LFS_ERR_INVAL without modifying the storage:
 * - len must not exceed the filesystem file size limit,
 * - attr_count must be non-negative, and attrs must be non-NULL when
 *   attr_count > 0,
 * - each attribute size must not exceed the filesystem attribute limit, and
 *   its buffer must be non-NULL when the size is non-zero,
 * - buf must be non-NULL when len > 0 (len == 0 skips the data write).
 *
 * Error propagation mirrors the other helpers: an open failure is returned
 * immediately; after a successful open every path closes the file, a prior
 * write error is preserved and returned, and otherwise the error of the
 * closing commit is returned. Success is never reported when the commit
 * failed.
 */
int write_file_attrs(const char *path,
                     const struct lfs_attr *attrs, int attr_count,
                     const void *buf, lfs_size_t len, uint8_t trunc);

/**
 * Commit several attributes on an existing file in a single commit, without
 * touching the file data.
 *
 * The file must exist: it is opened without LFS_O_CREAT, so a missing file
 * fails and is not created. The atomic-update contract, error contract, and
 * pre-open validation rules of write_file_attrs apply unchanged.
 */
int set_attrs_commit(const char *path,
                     const struct lfs_attr *attrs, int attr_count);
int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len);
int write_attr(const char *path, uint8_t attr, const void *buf, lfs_size_t len);
int remove_attr(const char *path, uint8_t attr);
int get_file_size(const char *path);

/**
 * Return the payload length of a LittleFS user attribute without reading it.
 *
 * Returns LFS_ERR_NOENT when the file is absent and LFS_ERR_NOATTR when the
 * file exists but the requested attribute is absent.
 */
int get_attr_size(const char *path, uint8_t attr);
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
 * Get the used size (in bytes) of the file system.
 *
 * This is LittleFS physical block usage, including metadata and copy-on-write
 * overhead. It is not the sum of file payload lengths.
 */
int get_fs_usage_bytes(void);

/**
 * Estimate currently available file system space in bytes.
 *
 * LittleFS allocates storage in blocks and may need additional metadata blocks
 * for a write. Treat this as an estimate for admission control, not as a
 * guarantee that a later write cannot fail. Callers still need to handle
 * LFS_ERR_NOSPC from the actual write path.
 *
 * @return Estimated free bytes, or a negative LittleFS error.
 */
int get_fs_free_bytes(void);

/**
 * Return whether the file system has enough estimated space for a write while
 * keeping reserve_bytes free.
 *
 * This helper uses subtraction rather than adding write_bytes and reserve_bytes
 * so oversized requests cannot wrap around and appear admissible.
 *
 * @return 1 if enough estimated space is available, 0 if not, or a negative
 * LittleFS error.
 */
int fs_has_free_space(lfs_size_t write_bytes, lfs_size_t reserve_bytes);

#endif // CANOKEY_CORE_INCLUDE_FS_H
