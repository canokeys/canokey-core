#include <fs.h>

static lfs_t lfs;

int fs_init(struct lfs_config *cfg) {
  int err = lfs_mount(&lfs, cfg);
  if (err) { // should happen for the first boot
    lfs_format(&lfs, cfg);
    lfs_mount(&lfs, cfg);
  }
  return 0;
}

int read_file(const char *path, void *buf, lfs_size_t len) {
  lfs_file_t f;
  int err = lfs_file_open(&lfs, &f, path, LFS_O_RDONLY);
  if (err < 0)
    return err;
  lfs_ssize_t read_length = lfs_file_read(&lfs, &f, buf, len);
  if (read_length < 0)
    return read_length;
  err = lfs_file_close(&lfs, &f);
  if (err < 0)
    return err;
  return read_length;
}

int write_file(const char *path, const void *buf, lfs_size_t len) {
  lfs_file_t f;
  int err =
      lfs_file_open(&lfs, &f, path, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC);
  if (err < 0)
    return err;
  err = lfs_file_write(&lfs, &f, buf, len);
  if (err < 0)
    return err;
  err = lfs_file_close(&lfs, &f);
  if (err < 0)
    return err;
  return 0;
}

int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len) {
  return lfs_getattr(&lfs, path, attr, buf, len);
}

int write_attr(const char *path, uint8_t attr, const void *buf,
               lfs_size_t len) {
  return lfs_setattr(&lfs, path, attr, buf, len);
}

int get_file_size(const char *path) {
  lfs_file_t f;
  int err = lfs_file_open(&lfs, &f, path, LFS_O_RDONLY);
  if (err < 0)
    return err;
  err = lfs_file_close(&lfs, &f);
  if (err < 0)
    return err;
  return lfs_file_size(&lfs, &f);
}
