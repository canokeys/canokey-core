#ifndef CANOKEY_CORE_INCLUDE_CORE_H
#define CANOKEY_CORE_INCLUDE_CORE_H

#include <lfs.h>

extern lfs_t g_lfs;

int init(struct lfs_config *cfg);

#endif // CANOKEY_CORE_INCLUDE_CORE_H
