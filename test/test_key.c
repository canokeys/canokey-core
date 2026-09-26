// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <bd/lfs_filebd.h>
#include <crypto-util.h>
#include <device.h>
#include <fs.h>
#include <key.h>
#include <lfs.h>
#include <pin.h>

#define PATH "key"

static void test_encode_invalid_type(void **state) {
  (void)state;

  uint8_t buf[1] = {0};
  ck_key_t key = {.meta.type = KEY_TYPE_PKC_END};

  assert_int_equal(ck_encode_public_key(&key, buf, false), -1);
  key.meta.type = AES128;
  assert_int_equal(ck_encode_public_key(&key, buf, true), -1);
}

static void test_read_key_rejects_short_material(void **state) {
  (void)state;
  const key_meta_t meta = {.type = MLKEM768, .origin = KEY_ORIGIN_IMPORTED, .usage = KEY_AGREEMENT};
  uint8_t short_seed[MLKEM768_KEYGEN_SEED_BYTES - 1];
  memset(short_seed, 0x5A, sizeof(short_seed));
  assert_int_equal(write_file(PATH, short_seed, 0, sizeof(short_seed), 1), 0);
  assert_int_equal(ck_write_key_metadata(PATH, &meta), 0);

  ck_key_t key;
  memset(&key, 0xA5, sizeof(key));
  assert_int_equal(ck_read_key(PATH, &key), LFS_ERR_CORRUPT);
  const uint8_t zero[sizeof(rsa_key_t)] = {0};
  assert_memory_equal(key.data, zero, sizeof(zero));
}

static void test_read_empty_key_ignores_stale_material(void **state) {
  (void)state;
  uint8_t stale_ecc_material[sizeof(ecc_key_t)];
  memset(stale_ecc_material, 0x5A, sizeof(stale_ecc_material));
  assert_int_equal(write_file(PATH, stale_ecc_material, 0, sizeof(stale_ecc_material), 1), 0);

  const key_meta_t meta = {
      .type = RSA2048,
      .origin = KEY_ORIGIN_NOT_PRESENT,
      .usage = SIGN,
      .pin_policy = PIN_POLICY_ONCE,
      .touch_policy = TOUCH_POLICY_CACHED,
  };
  assert_int_equal(ck_write_key_metadata(PATH, &meta), 0);

  ck_key_t key;
  memset(&key, 0xA5, sizeof(key));
  assert_int_equal(ck_read_key(PATH, &key), 0);
  assert_memory_equal(&key.meta, &meta, sizeof(meta));
  const uint8_t zero[sizeof(rsa_key_t)] = {0};
  assert_memory_equal(key.data, zero, sizeof(zero));
}

static void test_fs_file_operations(void **state) {
  (void)state;
  const char *path = "fs-io";
  uint8_t buf[16];
  assert_int_equal(get_file_size(path), LFS_ERR_NOENT);
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), LFS_ERR_NOENT);
  assert_int_equal(append_file(path, NULL, 0), 0);
  assert_int_equal(get_file_size(path), 0);
  assert_int_equal(write_file(path, "abcd", 0, 4, 0), 0);
  assert_int_equal(write_file(path, "XY", 1, 2, 0), 0);
  assert_int_equal(append_file(path, "ef", 2), 0);
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 6);
  assert_memory_equal(buf, "aXYdef", 6);
  assert_int_equal(read_file(path, buf, 2, 3), 3);
  assert_memory_equal(buf, "Yde", 3);
  assert_int_equal(read_file(path, buf, -1, 1), LFS_ERR_INVAL);
  // A failed operation must close the shared file before the next operation.
  assert_int_equal(write_file(path, "!", -1, 1, 0), LFS_ERR_INVAL);
  assert_int_equal(append_file(path, NULL, 0), 0);
  assert_int_equal(get_file_size(path), 6);
  assert_int_equal(truncate_file(path, 3), 0);
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 3);
  assert_memory_equal(buf, "aXY", 3);
  assert_int_equal(truncate_file(path, 5), 0);
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 5);
  assert_memory_equal(buf, "aXY\0\0", 5);
  assert_int_equal(write_attr(path, 0x94, "name", 4), 0);
  assert_int_equal(write_file(path, NULL, 0, 0, 1), 0);
  assert_int_equal(get_file_size(path), 0);
  assert_int_equal(read_attr(path, 0x94, buf, sizeof(buf)), 4);
  assert_memory_equal(buf, "name", 4);
  assert_int_equal(remove_file(path), 0);
}

// Fault-injecting block device wrappers for the fs-helper error-path tests,
// swapping cfg.prog/erase/sync like test_piv.c's container_name_prog does.
static const struct lfs_config *test_fs_cfg;
static int fault_prog_budget = -1;  // >= 0: fail the (budget+1)-th call
static int fault_erase_budget = -1;
static int fault_sync_budget = -1;
static bool fault_after;            // run the underlying op before failing
static unsigned bd_prog_count, bd_erase_count;

static int counted_bd_prog(const struct lfs_config *cfg, lfs_block_t block, lfs_off_t off, const void *buffer,
                           lfs_size_t size) {
  ++bd_prog_count;
  if (fault_prog_budget >= 0 && fault_prog_budget-- == 0) {
    if (fault_after) lfs_filebd_prog(cfg, block, off, buffer, size);
    return LFS_ERR_IO;
  }
  return lfs_filebd_prog(cfg, block, off, buffer, size);
}

static int counted_bd_erase(const struct lfs_config *cfg, lfs_block_t block) {
  ++bd_erase_count;
  if (fault_erase_budget >= 0 && fault_erase_budget-- == 0) {
    if (fault_after) lfs_filebd_erase(cfg, block);
    return LFS_ERR_IO;
  }
  return lfs_filebd_erase(cfg, block);
}

static int counted_bd_sync(const struct lfs_config *cfg) {
  if (fault_sync_budget >= 0 && fault_sync_budget-- == 0) {
    if (fault_after) lfs_filebd_sync(cfg);
    return LFS_ERR_IO;
  }
  return lfs_filebd_sync(cfg);
}

static void faults_disarm(void) {
  fault_prog_budget = fault_erase_budget = fault_sync_budget = -1;
  fault_after = false;
}

// Power-cut inspection: mount a fresh lfs_t on the same block device while
// the abandoned instance is neither unmounted nor closed.
static lfs_t fresh_lfs;

static void fresh_mount(void) {
  memset(&fresh_lfs, 0, sizeof(fresh_lfs));
  assert_int_equal(lfs_mount(&fresh_lfs, test_fs_cfg), 0);
}

static void fresh_unmount(void) { assert_int_equal(lfs_unmount(&fresh_lfs), 0); }

static int fresh_file_read(const char *path, void *buf, lfs_size_t len) {
  lfs_file_t f;
  int err = lfs_file_open(&fresh_lfs, &f, path, LFS_O_RDONLY);
  if (err < 0) return err;
  err = lfs_file_read(&fresh_lfs, &f, buf, len);
  int close_err = lfs_file_close(&fresh_lfs, &f);
  return err < 0 ? err : close_err < 0 ? close_err : err;
}

static void test_write_file_attrs_commit(void **state) {
  (void)state;
  const char *path = "wfa";
  uint8_t buf[16];
  const uint8_t meta_v2[] = {'n', '2', 'x'};
  const uint8_t keep[] = {'k', 'e', 'e', 'p'};

  assert_int_equal(write_file(path, "old-data", 0, 8, 1), 0);
  assert_int_equal(write_attr(path, 0x10, "m1", 2), 0);
  assert_int_equal(write_attr(path, 0x11, keep, sizeof(keep)), 0);

  const struct lfs_attr attrs[] = {
      {.type = 0x10, .buffer = (void *)meta_v2, .size = sizeof(meta_v2)},
      {.type = 0x30, .buffer = NULL, .size = 0}, // zero-length attr
  };
  assert_int_equal(write_file_attrs(path, attrs, 2, "new-data!", 9, 1), 0);

  // Data and the listed attrs are committed together.
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 9);
  assert_memory_equal(buf, "new-data!", 9);
  assert_int_equal(read_attr(path, 0x10, buf, sizeof(buf)), sizeof(meta_v2));
  assert_memory_equal(buf, meta_v2, sizeof(meta_v2));
  // Unlisted pre-existing attrs are preserved.
  assert_int_equal(read_attr(path, 0x11, buf, sizeof(buf)), sizeof(keep));
  assert_memory_equal(buf, keep, sizeof(keep));
  // Zero-length attr round trip: present but empty.
  assert_int_equal(get_attr_size(path, 0x30), 0);
  assert_int_equal(read_attr(path, 0x30, buf, sizeof(buf)), 0);
  // Same on-disk USERATTR format as write_attr/read_attr, both directions.
  assert_int_equal(write_attr(path, 0x30, "z", 1), 0);
  const struct lfs_attr empty = {.type = 0x30, .buffer = NULL, .size = 0};
  assert_int_equal(set_attrs_commit(path, &empty, 1), 0);
  assert_int_equal(get_attr_size(path, 0x30), 0);

  // len == 0 skips the data write; without trunc the content is kept.
  assert_int_equal(write_file_attrs(path, NULL, 0, NULL, 0, 0), 0);
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 9);
  assert_memory_equal(buf, "new-data!", 9);
  // With trunc the file is emptied while attrs are still committed.
  assert_int_equal(write_file_attrs(path, &empty, 1, NULL, 0, 1), 0);
  assert_int_equal(get_file_size(path), 0);
  assert_int_equal(get_attr_size(path, 0x30), 0);
  assert_int_equal(remove_file(path), 0);
}

static void test_write_file_attrs_validation(void **state) {
  (void)state;
  const char *path = "wfa-inval";
  uint8_t attr_storage[8], dummy = 0;
  const struct lfs_attr good = {.type = 0x10, .buffer = (void *)"a1", .size = 2};
  const struct lfs_attr oversized = {.type = 0x10, .buffer = attr_storage, .size = LFS_ATTR_MAX + 1};
  const struct lfs_attr null_buf = {.type = 0x10, .buffer = NULL, .size = 1};

  assert_int_equal(write_file(path, "data", 0, 4, 1), 0);
  assert_int_equal(write_attr(path, 0x10, "a1", 2), 0);

  // Each of these fails before the file is opened; the disk must not change.
  assert_int_equal(write_file_attrs(path, &good, -1, "zz", 2, 1), LFS_ERR_INVAL);
  assert_int_equal(write_file_attrs(path, NULL, 1, "zz", 2, 1), LFS_ERR_INVAL);
  assert_int_equal(write_file_attrs(path, &oversized, 1, "zz", 2, 1), LFS_ERR_INVAL);
  assert_int_equal(write_file_attrs(path, &null_buf, 1, "zz", 2, 1), LFS_ERR_INVAL);
  assert_int_equal(write_file_attrs(path, &good, 1, NULL, 2, 1), LFS_ERR_INVAL);
  assert_int_equal(write_file_attrs(path, &good, 1, &dummy, (lfs_size_t)LFS_FILE_MAX + 1, 1), LFS_ERR_INVAL);
  assert_int_equal(set_attrs_commit(path, &good, -1), LFS_ERR_INVAL);
  assert_int_equal(set_attrs_commit(path, &oversized, 1), LFS_ERR_INVAL);

  uint8_t buf[8];
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 4);
  assert_memory_equal(buf, "data", 4);
  assert_int_equal(read_attr(path, 0x10, buf, sizeof(buf)), 2);
  assert_memory_equal(buf, "a1", 2);
  assert_int_equal(remove_file(path), 0);
}

static void test_set_attrs_commit(void **state) {
  (void)state;
  const char *path = "sac";
  const struct lfs_attr attr = {.type = 0x10, .buffer = (void *)"a1", .size = 2};

  // A missing file must fail and must not be created.
  assert_int_equal(set_attrs_commit("sac-missing", &attr, 1), LFS_ERR_NOENT);
  assert_int_equal(get_file_size("sac-missing"), LFS_ERR_NOENT);

  assert_int_equal(write_file(path, "content", 0, 7, 1), 0);
  assert_int_equal(write_attr(path, 0x11, "keep", 4), 0);

  const struct lfs_attr attrs[] = {
      {.type = 0x10, .buffer = (void *)"a1", .size = 2},
      {.type = 0x12, .buffer = (void *)"b22", .size = 3},
  };
  assert_int_equal(set_attrs_commit(path, attrs, 2), 0);

  uint8_t buf[8];
  // Content and unlisted attrs are untouched.
  assert_int_equal(read_file(path, buf, 0, sizeof(buf)), 7);
  assert_memory_equal(buf, "content", 7);
  assert_int_equal(read_attr(path, 0x10, buf, sizeof(buf)), 2);
  assert_memory_equal(buf, "a1", 2);
  assert_int_equal(read_attr(path, 0x12, buf, sizeof(buf)), 3);
  assert_memory_equal(buf, "b22", 3);
  assert_int_equal(read_attr(path, 0x11, buf, sizeof(buf)), 4);
  assert_memory_equal(buf, "keep", 4);
  assert_int_equal(remove_file(path), 0);
}

static void test_write_file_attrs_error_reporting(void **state) {
  (void)state;
  const char *path = "wfa-err";
  assert_int_equal(write_file(path, "v1", 0, 2, 1), 0);

  // len > cache_size forces a flush from inside lfs_file_write; failing that
  // prog makes the write itself fail while the closing commit succeeds. The
  // preserved write error must still be reported.
  static uint8_t big[600];
  memset(big, 0x5A, sizeof(big));
  fault_prog_budget = 0;
  assert_int_equal(write_file_attrs(path, NULL, 0, big, sizeof(big), 1), LFS_ERR_IO);
  faults_disarm();

  // A small write stays in the file cache, so the first failing prog happens
  // in the closing commit; the commit error must be reported instead of
  // success.
  fault_prog_budget = 0;
  assert_int_equal(write_file_attrs(path, NULL, 0, "v2", 2, 1), LFS_ERR_IO);
  faults_disarm();

  // Same for set_attrs_commit: nothing is written, so any failure comes from
  // the closing commit.
  const struct lfs_attr attr = {.type = 0x10, .buffer = (void *)"a1", .size = 2};
  fault_prog_budget = 0;
  assert_int_equal(set_attrs_commit(path, &attr, 1), LFS_ERR_IO);
  faults_disarm();

  assert_int_equal(write_file_attrs(path, NULL, 0, "v3", 2, 1), 0);
  assert_int_equal(remove_file(path), 0);
}

// After a fault on an existing file, the remounted image must show either the
// complete old version or the complete new version, never a mix.
static void assert_remounted_old_or_new(const char *path, const uint8_t *old_data, const uint8_t *new_data,
                                        lfs_size_t len, uint8_t attr_type) {
  uint8_t buf[320], abuf[8];
  fresh_mount();
  assert_int_equal(fresh_file_read(path, buf, len), (int)len);
  assert_int_equal(lfs_getattr(&fresh_lfs, path, attr_type, abuf, 2), 2);
  const bool data_is_old = memcmp(buf, old_data, len) == 0;
  const bool attr_is_old = memcmp(abuf, "v1", 2) == 0;
  const bool data_is_new = memcmp(buf, new_data, len) == 0;
  const bool attr_is_new = memcmp(abuf, "v2", 2) == 0;
  assert_true((data_is_old && attr_is_old) || (data_is_new && attr_is_new));
  fresh_unmount();
}

// After a fault creating a new file, the remounted image must show one of:
// absent, an empty file without the attrs, or the complete new file.
static void assert_remounted_new_file(const char *path, const uint8_t *data, lfs_size_t len, uint8_t attr_type) {
  uint8_t buf[320], abuf[8];
  fresh_mount();
  const int n = fresh_file_read(path, buf, sizeof(buf));
  if (n == 0) {
    assert_int_equal(lfs_getattr(&fresh_lfs, path, attr_type, abuf, sizeof(abuf)), LFS_ERR_NOATTR);
  } else if (n > 0) {
    assert_int_equal(n, (int)len);
    assert_memory_equal(buf, data, len);
    assert_int_equal(lfs_getattr(&fresh_lfs, path, attr_type, abuf, sizeof(abuf)), 2);
    assert_memory_equal(abuf, "v2", 2);
  } else {
    assert_int_equal(n, LFS_ERR_NOENT);
  }
  fresh_unmount();
}

enum fault_stage { FAULT_PROG, FAULT_ERASE, FAULT_SYNC };

static void arm_fault(int stage, bool after) {
  faults_disarm();
  fault_after = after;
  if (stage == FAULT_PROG) fault_prog_budget = 0;
  if (stage == FAULT_ERASE) fault_erase_budget = 0;
  if (stage == FAULT_SYNC) fault_sync_budget = 0;
}

static void run_existing_file_fault(int stage, bool after, const char *path, const uint8_t *old_data,
                                    const uint8_t *new_data, lfs_size_t len) {
  const struct lfs_attr attr_v1 = {.type = 0x20, .buffer = (void *)"v1", .size = 2};
  const struct lfs_attr attr_v2 = {.type = 0x20, .buffer = (void *)"v2", .size = 2};

  if (stage == FAULT_ERASE) {
    // Erases only happen once a metadata pair is full; write until one fires.
    bool fired = false;
    for (int i = 0; i < 64 && !fired; ++i) {
      faults_disarm();
      assert_int_equal(write_file_attrs(path, &attr_v1, 1, old_data, len, 1), 0);
      const unsigned before = bd_erase_count;
      arm_fault(stage, after);
      const int rc = write_file_attrs(path, &attr_v2, 1, new_data, len, 1);
      faults_disarm();
      if (bd_erase_count != before) {
        assert_int_equal(rc, LFS_ERR_IO);
        fired = true;
      } else {
        assert_int_equal(rc, 0);
      }
    }
    assert_true(fired);
  } else {
    faults_disarm();
    assert_int_equal(write_file_attrs(path, &attr_v1, 1, old_data, len, 1), 0);
    arm_fault(stage, after);
    assert_int_equal(write_file_attrs(path, &attr_v2, 1, new_data, len, 1), LFS_ERR_IO);
    faults_disarm();
  }

  assert_remounted_old_or_new(path, old_data, new_data, len, 0x20);

  // Restore a known state for later scenarios.
  assert_int_equal(write_file_attrs(path, &attr_v1, 1, old_data, len, 1), 0);
  assert_int_equal(remove_file(path), 0);
}

static void run_new_file_fault(int stage, bool after, const char *path, const uint8_t *data, lfs_size_t len) {
  const struct lfs_attr attr_v2 = {.type = 0x20, .buffer = (void *)"v2", .size = 2};
  int rc;

  if (stage == FAULT_ERASE) {
    bool fired = false;
    for (int i = 0; i < 64 && !fired; ++i) {
      faults_disarm();
      remove_file(path);
      const unsigned before = bd_erase_count;
      arm_fault(stage, after);
      rc = write_file_attrs(path, &attr_v2, 1, data, len, 1);
      faults_disarm();
      if (bd_erase_count != before) {
        assert_int_equal(rc, LFS_ERR_IO);
        fired = true;
      } else {
        assert_int_equal(rc, 0);
      }
    }
    assert_true(fired);
  } else {
    faults_disarm();
    remove_file(path);
    arm_fault(stage, after);
    rc = write_file_attrs(path, &attr_v2, 1, data, len, 1);
    faults_disarm();
    assert_int_equal(rc, LFS_ERR_IO);
  }

  assert_remounted_new_file(path, data, len, 0x20);
  remove_file(path);
}

static void test_write_file_attrs_fault_recovery(void **state) {
  (void)state;
  const uint8_t old_data[] = "version-one";
  const uint8_t new_data[] = "version-two";
  uint8_t big_old[300], big_new[300];
  memset(big_old, 0x11, sizeof(big_old));
  memset(big_new, 0x22, sizeof(big_new));

  for (int stage = FAULT_PROG; stage <= FAULT_SYNC; ++stage) {
    for (int after = 0; after <= 1; ++after) {
      // Representative inline (small) and non-inline (300-byte) updates.
      run_existing_file_fault(stage, after, "fex-s", old_data, new_data, sizeof(old_data) - 1);
      run_existing_file_fault(stage, after, "fex-b", big_old, big_new, sizeof(big_old));
      run_new_file_fault(stage, after, "fnew-s", new_data, sizeof(new_data) - 1);
      run_new_file_fault(stage, after, "fnew-b", big_new, sizeof(big_new));
    }
  }
}

static void test_pin_batched_retry_updates(void **state) {
  (void)state;
  static pin_t pin = {.min_length = 4, .max_length = 8, .is_validated = 0, .path = "pin-batch"};
  uint8_t retries = 0xFF;

  // pin_create commits the secret and both retry counters together.
  assert_int_equal(pin_create(&pin, "1234", 4, 3), 0);
  assert_int_equal(pin_get_size(&pin), 4);
  assert_int_equal(pin_get_retries(&pin), 3);
  assert_int_equal(pin_get_default_retries(&pin), 3);

  // A successful verify at default retries performs no prog or erase.
  const unsigned prog_before = bd_prog_count, erase_before = bd_erase_count;
  assert_int_equal(pin_verify(&pin, "1234", 4, NULL), 0);
  assert_int_equal(pin.is_validated, 1);
  assert_int_equal(bd_prog_count, prog_before);
  assert_int_equal(bd_erase_count, erase_before);

  // A failed verify decrements (commits); the next successful verify restores
  // the default and that restore commits as well.
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 2);
  assert_int_equal(pin.is_validated, 0);
  assert_true(bd_prog_count > prog_before);
  const unsigned prog_after_fail = bd_prog_count;
  assert_int_equal(pin_verify(&pin, "1234", 4, NULL), 0);
  assert_int_equal(pin.is_validated, 1);
  assert_true(bd_prog_count > prog_after_fail);
  assert_int_equal(pin_get_retries(&pin), 3);

  // Blocked PIN: ctr == 0 rejects even the correct secret.
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 0);
  assert_int_equal(pin_verify(&pin, "1234", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(retries, 0);
  assert_int_equal(pin.is_validated, 0);

  // A write failure during the retry restore must not leave is_validated set.
  assert_int_equal(pin_set_retries(&pin, 3), 0);
  assert_int_equal(pin_verify(&pin, "0000", 4, &retries), PIN_AUTH_FAIL);
  assert_int_equal(pin_get_retries(&pin), 2);
  fault_prog_budget = 0;
  assert_int_equal(pin_verify(&pin, "1234", 4, NULL), PIN_IO_FAIL);
  assert_int_equal(pin.is_validated, 0);
  faults_disarm();
  assert_int_equal(pin_verify(&pin, "1234", 4, NULL), 0);
  assert_int_equal(pin.is_validated, 1);
  assert_int_equal(pin_get_retries(&pin), 3);

  // Missing DEFAULT_RETRY_ATTR on the success path fails without validating.
  static pin_t partial = {.min_length = 4, .max_length = 8, .is_validated = 0, .path = "pin-partial"};
  const uint8_t three = 3;
  assert_int_equal(write_file("pin-partial", "1234", 0, 4, 1), 0);
  assert_int_equal(write_attr("pin-partial", 0 /* RETRY_ATTR */, &three, 1), 0);
  assert_int_equal(pin_verify(&partial, "1234", 4, NULL), PIN_IO_FAIL);
  assert_int_equal(partial.is_validated, 0);

  // Missing files fail without being created.
  static pin_t absent = {.min_length = 4, .max_length = 8, .is_validated = 0, .path = "pin-absent"};
  assert_int_equal(pin_set_retries(&absent, 5), PIN_IO_FAIL);
  assert_int_equal(get_file_size("pin-absent"), LFS_ERR_NOENT);
  assert_int_equal(pin_update(&absent, "1234", 4), PIN_IO_FAIL);
  assert_int_equal(get_file_size("pin-absent"), LFS_ERR_NOENT);
  assert_int_equal(pin_clear(&absent), PIN_IO_FAIL);
  assert_int_equal(get_file_size("pin-absent"), LFS_ERR_NOENT);

  // pin_update merges the data update and the retry reset into one commit.
  assert_int_equal(pin_update(&pin, "5678", 4), 0);
  assert_int_equal(pin.is_validated, 0);
  assert_int_equal(pin_get_retries(&pin), 3);
  assert_int_equal(pin_verify(&pin, "5678", 4, NULL), 0);
  assert_int_equal(pin.is_validated, 1);

  // pin_clear truncates the secret and resets the retry counter.
  assert_int_equal(pin_clear(&pin), 0);
  assert_int_equal(pin_get_size(&pin), 0);
  assert_int_equal(pin_get_retries(&pin), 0);

  assert_int_equal(remove_file("pin-batch"), 0);
  assert_int_equal(remove_file("pin-partial"), 0);
}

static void test_fs_reader_lifecycle(void **state) {
  (void)state;
  const char *path = "reader";
  uint8_t buf[16];

  fs_reader_t reader = {0};
  // Close on a zero-initialized reader is a safe no-op; size/read_at are not.
  assert_int_equal(fs_reader_close(&reader), 0);
  assert_int_equal(fs_reader_size(&reader), LFS_ERR_INVAL);
  assert_int_equal(fs_reader_read_at(&reader, buf, 0, 1), LFS_ERR_INVAL);

  assert_int_equal(write_file(path, "0123456789", 0, 10, 1), 0);
  assert_int_equal(fs_reader_open(&reader, path), 0);
  // Opening an already-open reader is rejected and keeps ownership.
  assert_int_equal(fs_reader_open(&reader, path), LFS_ERR_INVAL);
  assert_int_equal(fs_reader_size(&reader), 10);
  assert_int_equal(fs_reader_read_at(&reader, buf, 0, 4), 4);
  assert_memory_equal(buf, "0123", 4);
  assert_int_equal(fs_reader_read_at(&reader, buf, 6, 4), 4);
  assert_memory_equal(buf, "6789", 4);
  // Short reads at EOF return the actual byte count.
  assert_int_equal(fs_reader_read_at(&reader, buf, 8, 4), 2);
  assert_memory_equal(buf, "89", 2);
  assert_int_equal(fs_reader_read_at(&reader, buf, 10, 4), 0);
  assert_int_equal(fs_reader_read_at(&reader, buf, -1, 1), LFS_ERR_INVAL);

  // While the reader owns the shared cache, other cache users are rejected.
  fs_reader_t other = {0};
  const struct lfs_attr attr = {.type = 0x40, .buffer = (void *)"a", .size = 1};
  assert_int_equal(read_file(path, buf, 0, 1), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(write_file(path, "x", 0, 1, 0), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(append_file(path, "x", 1), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(truncate_file(path, 1), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(get_file_size(path), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(write_file_attrs(path, &attr, 1, "x", 1, 0), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(set_attrs_commit(path, &attr, 1), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(fs_format(test_fs_cfg), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  assert_int_equal(fs_mount(test_fs_cfg), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  // A second reader cannot open while the first owns the cache.
  assert_int_equal(fs_reader_open(&other, path), LFS_ERR_INVAL);
  assert_true(fs_cache_conflict());
  fs_cache_conflict_reset();
  // Attribute-only helpers do not use the shared cache and keep working.
  assert_int_equal(write_attr(path, 0x41, "m", 1), 0);
  assert_int_equal(read_attr(path, 0x41, buf, sizeof(buf)), 1);

  // The reader is undisturbed by the rejected attempts.
  assert_int_equal(fs_reader_read_at(&reader, buf, 0, 10), 10);
  assert_memory_equal(buf, "0123456789", 10);

  assert_int_equal(fs_reader_close(&reader), 0);
  assert_int_equal(fs_reader_close(&reader), 0); // double close is safe

  // Ownership is released: wrappers and a new reader work again.
  assert_int_equal(read_file(path, buf, 0, 10), 10);
  assert_int_equal(fs_reader_open(&other, path), 0);
  assert_int_equal(fs_reader_close(&other), 0);
  assert_int_equal(remove_file(path), 0);
}

static void test_fs_reader_open_failure_releases_cache(void **state) {
  (void)state;
  fs_reader_t reader = {0};
  assert_int_equal(fs_reader_open(&reader, "reader-missing"), LFS_ERR_NOENT);
  assert_false(reader.opened);
  // The failed open released the cache: a new reader can open right away.
  assert_int_equal(write_file("reader-ok", "a", 0, 1, 1), 0);
  assert_int_equal(fs_reader_open(&reader, "reader-ok"), 0);
  assert_int_equal(fs_reader_close(&reader), 0);
  assert_int_equal(remove_file("reader-ok"), 0);
}

static void test_fs_wrapper_error_paths_release_cache(void **state) {
  (void)state;
  fs_reader_t reader = {0};
  assert_int_equal(write_file("reader-io", "a", 0, 1, 1), 0);

  // An injected write error returns before any disk touch; the cache stays free.
  testmode_inject_error(TESTMODE_ERR_WRITE, 0, 9, (const uint8_t *)"reader-io");
  assert_int_equal(write_file("reader-io", "b", 0, 1, 1), LFS_ERR_IO);
  assert_int_equal(fs_reader_open(&reader, "reader-io"), 0);
  assert_int_equal(fs_reader_close(&reader), 0);

  // A seek error after the borrow also releases the cache.
  assert_int_equal(write_file("reader-io", "b", -1, 1, 0), LFS_ERR_INVAL);
  assert_int_equal(fs_reader_open(&reader, "reader-io"), 0);
  assert_int_equal(fs_reader_close(&reader), 0);

  assert_int_equal(remove_file("reader-io"), 0);
}

static void test_fs_generation(void **state) {
  (void)state;
  uint8_t buf[4];
  const struct lfs_attr attr = {.type = 0x50, .buffer = (void *)"a", .size = 1};

  assert_int_equal(write_file("gen", "a", 0, 1, 1), 0);
  const uint32_t g0 = fs_generation();

  // Read-only operations do not advance the generation.
  assert_int_equal(read_file("gen", buf, 0, 1), 1);
  assert_int_equal(get_file_size("gen"), 1);
  assert_int_equal(read_attr("gen", 0x50, buf, sizeof(buf)), LFS_ERR_NOATTR);
  assert_int_equal(get_attr_size("gen", 0x50), LFS_ERR_NOATTR);
  assert_true(get_fs_free_bytes() > 0);
  fs_reader_t reader = {0};
  assert_int_equal(fs_reader_open(&reader, "gen"), 0);
  assert_int_equal(fs_reader_size(&reader), 1);
  assert_int_equal(fs_reader_read_at(&reader, buf, 0, 1), 1);
  assert_int_equal(fs_reader_close(&reader), 0);
  assert_int_equal(fs_generation(), g0);

  // Every mutating entry advances the generation exactly once.
  uint32_t g = g0;
  assert_int_equal(write_file("gen", "b", 0, 1, 0), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(append_file("gen", "c", 1), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(truncate_file("gen", 1), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(write_attr("gen", 0x50, "a", 1), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(remove_attr("gen", 0x50), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(write_file_attrs("gen", &attr, 1, "d", 1, 0), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(set_attrs_commit("gen", &attr, 1), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(fs_rename("gen", "gen2"), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(remove_file("gen2"), 0);
  assert_int_equal(fs_generation(), ++g);

  // Failed mutation attempts also advance it (a failed write may still have
  // compacted): first via the TEST injection hook, then a mid-commit prog
  // failure.
  testmode_inject_error(TESTMODE_ERR_WRITE, 0, 3, (const uint8_t *)"gen");
  assert_int_equal(write_file("gen", "x", 0, 1, 1), LFS_ERR_IO);
  assert_int_equal(fs_generation(), ++g);
  fault_prog_budget = 0;
  assert_int_equal(write_file_attrs("gen", &attr, 1, "x", 1, 1), LFS_ERR_IO);
  assert_int_equal(fs_generation(), ++g);
  faults_disarm();

  // Format and mount advance it too, and the fs keeps working afterwards.
  assert_int_equal(fs_format(test_fs_cfg), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(fs_mount(test_fs_cfg), 0);
  assert_int_equal(fs_generation(), ++g);
  assert_int_equal(write_file("gen", "z", 0, 1, 1), 0);
  assert_int_equal(read_file("gen", buf, 0, 1), 1);
  assert_int_equal(buf[0], 'z');
}

int main() {
  struct lfs_config cfg;
  lfs_filebd_t bd;
  struct lfs_filebd_config bdcfg = {.read_size = 1, .prog_size = 512, .erase_size = 512, .erase_count = 256};
  bd.cfg = &bdcfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.context = &bd;
  cfg.read = &lfs_filebd_read;
  cfg.prog = &counted_bd_prog;
  cfg.erase = &counted_bd_erase;
  cfg.sync = &counted_bd_sync;
  test_fs_cfg = &cfg;
  cfg.read_size = 1;
  cfg.prog_size = 512;
  cfg.block_size = 512;
  cfg.block_count = 256;
  cfg.block_cycles = 50000;
  cfg.cache_size = 512;
  cfg.lookahead_size = 32;
  // Static littlefs work buffers: the generation test formats and remounts
  // mid-suite, and malloc'd buffers would leak on every re-init.
  static uint8_t read_buffer[512], prog_buffer[512], lookahead_buffer[32];
  cfg.read_buffer = read_buffer;
  cfg.prog_buffer = prog_buffer;
  cfg.lookahead_buffer = lookahead_buffer;
  lfs_filebd_create(&cfg, "lfs-root-key", &bdcfg);

  fs_format(&cfg);
  fs_mount(&cfg);

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_fs_file_operations),
      cmocka_unit_test(test_write_file_attrs_commit),
      cmocka_unit_test(test_write_file_attrs_validation),
      cmocka_unit_test(test_set_attrs_commit),
      cmocka_unit_test(test_write_file_attrs_error_reporting),
      cmocka_unit_test(test_write_file_attrs_fault_recovery),
      cmocka_unit_test(test_pin_batched_retry_updates),
      cmocka_unit_test(test_fs_reader_lifecycle),
      cmocka_unit_test(test_fs_reader_open_failure_releases_cache),
      cmocka_unit_test(test_fs_wrapper_error_paths_release_cache),
      cmocka_unit_test(test_encode_invalid_type),
      cmocka_unit_test(test_read_key_rejects_short_material),
      cmocka_unit_test(test_read_empty_key_ignores_stale_material),
      // Formats the fs; keep last.
      cmocka_unit_test(test_fs_generation),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
