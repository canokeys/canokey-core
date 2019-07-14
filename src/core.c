#include <core.h>

lfs_t g_lfs;

int init(struct lfs_config *cfg) {
  int err = lfs_mount(&g_lfs, cfg);
  if (err) { // should happen for the first boot
    lfs_format(&g_lfs, cfg);
    lfs_mount(&g_lfs, cfg);
  }
  return 0;
}
