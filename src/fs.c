// SPDX-License-Identifier: Apache-2.0
#include <fs.h>
#include <device.h>

static lfs_t lfs;

static alignas(4) uint8_t file_buffer[LFS_CACHE_SIZE];

static struct lfs_file_config file_config = {.buffer = file_buffer};

// Ownership of the shared file cache (file_buffer): the wrappers below borrow
// it for a single call, while an fs_reader_t holds it from open to close. A
// nested borrower would corrupt the reader's cache, so TEST builds reject it
// with LFS_ERR_INVAL and set a queryable conflict flag. Without TEST the
// checks compile out and behavior is unchanged.
#ifdef TEST
static const void *cache_owner;
static bool cache_conflict;

bool fs_cache_conflict(void) { return cache_conflict; }

void fs_cache_conflict_reset(void) { cache_conflict = false; }

static int cache_acquire(const void *owner) {
  if (cache_owner != NULL) {
    cache_conflict = true;
    return LFS_ERR_INVAL;
  }
  cache_owner = owner;
  return 0;
}

static int cache_verify(const void *owner) {
  if (cache_owner != owner) {
    cache_conflict = true;
    return LFS_ERR_INVAL;
  }
  return 0;
}

static void cache_release(const void *owner) {
  if (cache_owner == owner) cache_owner = NULL;
}
#else
static int cache_acquire(const void *owner) {
  (void)owner;
  return 0;
}
static int cache_verify(const void *owner) {
  (void)owner;
  return 0;
}
static void cache_release(const void *owner) { (void)owner; }
#endif

int fs_format(const struct lfs_config *cfg) {
  const int err = cache_acquire(fs_format);
  if (err < 0) return err;
  const int ret = lfs_format(&lfs, cfg);
  cache_release(fs_format);
  return ret;
}

int fs_mount(const struct lfs_config *cfg) {
  const int err = cache_acquire(fs_mount);
  if (err < 0) return err;
  const int ret = lfs_mount(&lfs, cfg);
  cache_release(fs_mount);
  return ret;
}

// Always close an opened file, preserving the operation's original error.
static int close_file_result(lfs_file_t *file, int result) {
  const int close_result = lfs_file_close(&lfs, file);
  if (result < 0) return result;
  return close_result < 0 ? close_result : result;
}

int read_file(const char *path, void *buf, lfs_soff_t off, lfs_size_t len) {
  int err = cache_acquire(read_file);
  if (err < 0) return err;
  lfs_file_t f;
  err = lfs_file_opencfg(&lfs, &f, path, LFS_O_RDONLY, &file_config);
  if (err >= 0) {
    err = lfs_file_seek(&lfs, &f, off, LFS_SEEK_SET);
    if (err >= 0) err = lfs_file_read(&lfs, &f, buf, len);
    err = close_file_result(&f, err);
  }
  cache_release(read_file);
  return err;
}

static int write_file_at(const char *path, const void *buf, lfs_soff_t off, lfs_size_t len, int flags) {
  int err = cache_acquire(write_file_at);
  if (err < 0) return err;
  lfs_file_t f;
  err = lfs_file_opencfg(&lfs, &f, path, LFS_O_WRONLY | LFS_O_CREAT | flags, &file_config);
  if (err >= 0) {
    err = lfs_file_seek(&lfs, &f, off, flags & LFS_O_APPEND ? LFS_SEEK_END : LFS_SEEK_SET);
    if (err >= 0 && len > 0) err = lfs_file_write(&lfs, &f, buf, len);
    err = close_file_result(&f, err < 0 ? err : 0);
  }
  cache_release(write_file_at);
  return err;
}

int write_file(const char *path, const void *buf, lfs_soff_t off, lfs_size_t len, uint8_t trunc) {
#ifdef TEST
  if (testmode_err_triggered(path, true)) return LFS_ERR_IO;
#endif
  return write_file_at(path, buf, off, len, trunc ? LFS_O_TRUNC : 0);
}

int append_file(const char *path, const void *buf, lfs_size_t len) {
  return write_file_at(path, buf, 0, len, LFS_O_APPEND);
}

int truncate_file(const char *path, lfs_size_t len) {
  int err = cache_acquire(truncate_file);
  if (err < 0) return err;
  lfs_file_t f;
  err = lfs_file_opencfg(&lfs, &f, path, LFS_O_WRONLY | LFS_O_CREAT, &file_config);
  if (err >= 0) err = close_file_result(&f, lfs_file_truncate(&lfs, &f, len));
  cache_release(truncate_file);
  return err;
}

// Pre-open validation for the attr-batched helpers; a failure here must not
// modify the storage.
static int validate_attrs_write(const struct lfs_attr *attrs, int attr_count, const void *buf, lfs_size_t len) {
  if (len > lfs.file_max) return LFS_ERR_INVAL;
  if (len > 0 && buf == NULL) return LFS_ERR_INVAL;
  if (attr_count < 0 || (attr_count > 0 && attrs == NULL)) return LFS_ERR_INVAL;
  for (int i = 0; i < attr_count; ++i) {
    if (attrs[i].size > lfs.attr_max) return LFS_ERR_INVAL;
    if (attrs[i].size > 0 && attrs[i].buffer == NULL) return LFS_ERR_INVAL;
  }
  return 0;
}

// Open with the caller-supplied attrs, optionally write from offset 0, and
// always close; littlefs keeps the config pointer, so it must outlive close.
static int opencfg_attrs_close(const char *path, int flags, const struct lfs_attr *attrs, int attr_count,
                               const void *buf, lfs_size_t len) {
  int err = cache_acquire(opencfg_attrs_close);
  if (err < 0) return err;
  struct lfs_file_config cfg = {
      .buffer = file_buffer,
      .attrs = (struct lfs_attr *)attrs,
      .attr_count = (lfs_size_t)attr_count,
  };
  lfs_file_t f;
  err = lfs_file_opencfg(&lfs, &f, path, flags, &cfg);
  if (err >= 0) {
    if (len > 0) err = lfs_file_write(&lfs, &f, buf, len);
    err = close_file_result(&f, err < 0 ? err : 0);
  }
  cache_release(opencfg_attrs_close);
  return err;
}

int write_file_attrs(const char *path, const struct lfs_attr *attrs, int attr_count, const void *buf, lfs_size_t len,
                     uint8_t trunc) {
#ifdef TEST
  if (testmode_err_triggered(path, true)) return LFS_ERR_IO;
#endif
  int err = validate_attrs_write(attrs, attr_count, buf, len);
  if (err < 0) return err;
  return opencfg_attrs_close(path, LFS_O_WRONLY | LFS_O_CREAT | (trunc ? LFS_O_TRUNC : 0), attrs, attr_count, buf, len);
}

int set_attrs_commit(const char *path, const struct lfs_attr *attrs, int attr_count) {
  int err = validate_attrs_write(attrs, attr_count, NULL, 0);
  if (err < 0) return err;
  return opencfg_attrs_close(path, LFS_O_WRONLY, attrs, attr_count, NULL, 0);
}

int read_attr(const char *path, uint8_t attr, void *buf, lfs_size_t len) {
#ifdef TEST
  if (testmode_err_triggered(path, false)) return LFS_ERR_IO;
#endif
  return lfs_getattr(&lfs, path, attr, buf, len);
}

int write_attr(const char *path, uint8_t attr, const void *buf, lfs_size_t len) {
  return lfs_setattr(&lfs, path, attr, buf, len);
}

int remove_attr(const char *path, uint8_t attr) {
  return lfs_removeattr(&lfs, path, attr);
}

int get_file_size(const char *path) {
  int err = cache_acquire(get_file_size);
  if (err < 0) return err;
  lfs_file_t f;
  err = lfs_file_opencfg(&lfs, &f, path, LFS_O_RDONLY, &file_config);
  if (err >= 0) err = close_file_result(&f, lfs_file_size(&lfs, &f));
  cache_release(get_file_size);
  return err;
}

int fs_reader_open(fs_reader_t *reader, const char *path) {
  if (reader->opened) return LFS_ERR_INVAL;
  int err = cache_acquire(reader);
  if (err < 0) return err;
  err = lfs_file_opencfg(&lfs, &reader->file, path, LFS_O_RDONLY, &file_config);
  if (err < 0) {
    cache_release(reader);
    return err;
  }
  reader->opened = true;
  return 0;
}

lfs_soff_t fs_reader_size(fs_reader_t *reader) {
  if (!reader->opened) return LFS_ERR_INVAL;
  const int err = cache_verify(reader);
  if (err < 0) return err;
  return lfs_file_size(&lfs, &reader->file);
}

int fs_reader_read_at(fs_reader_t *reader, void *buf, lfs_soff_t off, lfs_size_t len) {
  if (!reader->opened) return LFS_ERR_INVAL;
  int err = cache_verify(reader);
  if (err < 0) return err;
  err = lfs_file_seek(&lfs, &reader->file, off, LFS_SEEK_SET);
  if (err < 0) return err;
  return lfs_file_read(&lfs, &reader->file, buf, len);
}

int fs_reader_close(fs_reader_t *reader) {
  if (!reader->opened) return 0;
  reader->opened = false;
  const int err = lfs_file_close(&lfs, &reader->file);
  cache_release(reader);
  return err;
}

int get_attr_size(const char *path, uint8_t attr) {
  // lfs_getattr's read path does memset(buffer + n, 0, len - n) unconditionally;
  // a NULL probe buffer trips UBSan's nonnull check even when len is 0.
  static uint8_t attr_probe;
  return lfs_getattr(&lfs, path, attr, &attr_probe, 0);
}

int get_fs_size(void) { return (int)(lfs.cfg->block_size * lfs.cfg->block_count) / 1024; }

int get_fs_usage(void) {
  const int bytes = get_fs_usage_bytes();
  return bytes < 0 ? bytes : bytes / 1024;
}

int get_fs_usage_bytes(void) {
  int blocks = lfs_fs_size(&lfs);
  if (blocks < 0) return blocks;
  return (int)(lfs.cfg->block_size * (lfs_size_t)blocks);
}

int get_fs_free_bytes(void) {
  int blocks = lfs_fs_size(&lfs);
  if (blocks < 0) return blocks;
  if (blocks >= (int)lfs.cfg->block_count) return 0;
  return (int)(lfs.cfg->block_size * (lfs.cfg->block_count - (lfs_size_t)blocks));
}

int fs_has_free_space(lfs_size_t write_bytes, lfs_size_t reserve_bytes) {
  int free_bytes = get_fs_free_bytes();
  if (free_bytes < 0) return free_bytes;
  if ((lfs_size_t)free_bytes < reserve_bytes) return 0;
  return (lfs_size_t)free_bytes - reserve_bytes >= write_bytes;
}

int fs_rename(const char *old, const char *new) { return lfs_rename(&lfs, old, new); }

int remove_file(const char *path) { return lfs_remove(&lfs, path); }
