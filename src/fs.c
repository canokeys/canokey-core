// SPDX-License-Identifier: Apache-2.0
#include <fs.h>
#include <device.h>

static lfs_t lfs;

static alignas(4) uint8_t file_buffer[LFS_CACHE_SIZE];

static struct lfs_file_config file_config = {
    .buffer = file_buffer
};

int fs_format(const struct lfs_config *cfg) { return lfs_format(&lfs, cfg); }

int fs_mount(const struct lfs_config *cfg) { return lfs_mount(&lfs, cfg); }

int read_file(const char *path, void *buf, lfs_soff_t off, lfs_size_t len) {
  lfs_file_t f;
  lfs_ssize_t read_length;
  int err = lfs_file_opencfg(&lfs, &f, path, LFS_O_RDONLY, &file_config);
  if (err < 0) return err;
  err = lfs_file_seek(&lfs, &f, off, LFS_SEEK_SET);
  if (err < 0) goto err_close;
  read_length = lfs_file_read(&lfs, &f, buf, len);
  if (read_length < 0) {
    err = read_length;
    goto err_close;
  }
  err = lfs_file_close(&lfs, &f);
  if (err < 0) return err;
  return read_length;

err_close:
  lfs_file_close(&lfs, &f);
  return err;
}

int write_file(const char *path, const void *buf, lfs_soff_t off, lfs_size_t len, uint8_t trunc) {
  lfs_file_t f;
#ifdef TEST
  if (testmode_err_triggered(path, true)) {
    return LFS_ERR_IO;
  }
#endif
  int flags = LFS_O_WRONLY | LFS_O_CREAT;
  if (trunc) flags |= LFS_O_TRUNC;
  int err = lfs_file_opencfg(&lfs, &f, path, flags, &file_config);
  if (err < 0) return err;
  err = lfs_file_seek(&lfs, &f, off, LFS_SEEK_SET);
  if (err < 0) goto err_close;
  if (len > 0) {
    err = lfs_file_write(&lfs, &f, buf, len);
    if (err < 0) goto err_close;
  }
  err = lfs_file_close(&lfs, &f);
  if (err < 0) return err;
  return 0;
  err_close:
  lfs_file_close(&lfs, &f);
  return err;
}

int append_file(const char *path, const void *buf, lfs_size_t len) {
  lfs_file_t f;
  int err = lfs_file_opencfg(&lfs, &f, path, LFS_O_WRONLY | LFS_O_CREAT, &file_config);
  if (err < 0) return err;
  err = lfs_file_seek(&lfs, &f, 0, LFS_SEEK_END);
  if (err < 0) goto err_close;
  if (len > 0) {
    err = lfs_file_write(&lfs, &f, buf, len);
    if (err < 0) goto err_close;
  }
  err = lfs_file_close(&lfs, &f);
  if (err < 0) return err;
  return 0;
  err_close:
  lfs_file_close(&lfs, &f);
  return err;
}

int truncate_file(const char *path, lfs_size_t len) {
  lfs_file_t f;
  int flags = LFS_O_WRONLY | LFS_O_CREAT;
  int err = lfs_file_opencfg(&lfs, &f, path, flags, &file_config);
  if (err < 0) return err;
  err = lfs_file_truncate(&lfs, &f, len);
  if (err < 0) goto err_close;
  err = lfs_file_close(&lfs, &f);
  if (err < 0) return err;
  return 0;
  err_close:
  lfs_file_close(&lfs, &f);
  return err;
}

int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len) {
  return lfs_getattr(&lfs, path, attr, buf, len);
}

int write_attr(const char *path, uint8_t attr, const void *buf, lfs_size_t len) {
  return lfs_setattr(&lfs, path, attr, buf, len);
}

int get_file_size(const char *path) {
  lfs_file_t f;
  int err = lfs_file_opencfg(&lfs, &f, path, LFS_O_RDONLY, &file_config);
  if (err < 0) return err;
  int size = lfs_file_size(&lfs, &f);
  if (size < 0) {
    err = size;
    goto err_close;
  }
  err = lfs_file_close(&lfs, &f);
  if (err < 0) return err;
  return size;
  err_close:
  lfs_file_close(&lfs, &f);
  return err;
}

int get_fs_size(void) { return (int) (lfs.cfg->block_size * lfs.cfg->block_count) / 1024; }

int get_fs_usage(void) {
  int blocks = lfs_fs_size(&lfs);
  if (blocks < 0) return blocks;
  return (int) (lfs.cfg->block_size * blocks) / 1024;
}

int fs_rename(const char *old, const char *new) { return lfs_rename(&lfs, old, new); }
