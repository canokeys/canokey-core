#ifndef CANOKEY_CORE_INCLUDE_FS_H
#define CANOKEY_CORE_INCLUDE_FS_H

#include <lfs.h>

int fs_init(struct lfs_config *cfg);
int read_file(const char *path, void *buf, lfs_size_t len);
int write_file(const char *path, const void *buf, lfs_size_t len);
int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len);
int write_attr(const char *path, uint8_t attr, const void *buf, lfs_size_t len);
int get_file_size(const char *path);

#endif // CANOKEY_CORE_INCLUDE_FS_H
