#ifndef CANOKEY_CORE_INCLUDE_UTIL_H
#define CANOKEY_CORE_INCLUDE_UTIL_H

#include <lfs.h>

int read_file(lfs_t *lfs, const char *path, void *buf, lfs_size_t len);
int write_file(lfs_t *lfs, const char *path, const void *buf, lfs_size_t len);

#endif // CANOKEY_CORE_INCLUDE_UTIL_H
