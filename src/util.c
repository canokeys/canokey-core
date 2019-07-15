#include <util.h>

int read_file(lfs_t *lfs, const char *path, void *buf, lfs_size_t len) {
  lfs_file_t f;
  int err = lfs_file_open(lfs, &f, path, LFS_O_RDONLY);
  if (err < 0)
    return err;
  lfs_ssize_t read_length = lfs_file_read(lfs, &f, buf, len);
  if (read_length < 0)
    return read_length;
  err = lfs_file_close(lfs, &f);
  if (err < 0)
    return err;
  return read_length;
}

int write_file(lfs_t *lfs, const char *path, const void *buf, lfs_size_t len) {
  lfs_file_t f;
  int err = lfs_file_open(lfs, &f, path, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC);
  if (err < 0)
    return err;
  err = lfs_file_write(lfs, &f, buf, len);
  if (err < 0)
    return err;
  err = lfs_file_close(lfs, &f);
  if (err < 0)
    return err;
  return 0;
}
