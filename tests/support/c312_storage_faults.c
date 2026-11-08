// SPDX-License-Identifier: Apache-2.0
// Included only by the fault adapter, after pinned test initialization headers.
// Its original fs.c is compiled with read_file renamed, preserving the file
// implementation and all applet/transport code behind this one host-only seam.
int portable_read_file_real(const char *path, void *buf, lfs_soff_t off, lfs_size_t len);
// Rust record IDs select the equivalent pinned C file, not a shared layout.
enum { FAULT_RECORD_BLOB = 180, FAULT_RECORD_CERTIFICATE = 183 };
// Marks bytes a short backend read did not initialize.
enum { READ_FAULT_POISON = 0xa5 };
static const char *portable_fault_path;
static unsigned portable_fault_skip;
static int portable_fault_return;
static unsigned portable_fault_hits;
static lfs_soff_t portable_fault_offset;
static lfs_size_t portable_fault_requested;

int read_file(const char *path, void *buf, lfs_soff_t off, lfs_size_t len) {
  if (!portable_fault_path || strcmp(path, portable_fault_path) != 0)
    return portable_read_file_real(path, buf, off, len);
  if (portable_fault_skip != 0) {
    --portable_fault_skip;
    return portable_read_file_real(path, buf, off, len);
  }
  portable_fault_path = NULL;
  ++portable_fault_hits;
  portable_fault_offset = off;
  portable_fault_requested = len;
  assert_true(portable_fault_return < 0 || (lfs_size_t)portable_fault_return < len);
  memset(buf, READ_FAULT_POISON, len);
  lfs_size_t n = portable_fault_return < 0 ? len : (lfs_size_t)portable_fault_return;
  assert_int_equal(portable_read_file_real(path, buf, off, n), n);
  return portable_fault_return;
}

static char *portable_fault_fgets(char *line, int size, FILE *stream) {
  while (fgets(line, size, stream)) {
    if (strcmp(line, "FAULT STATUS\n") == 0) {
      printf("FAULT %u %u %ld %lu %d\n", portable_fault_path != NULL,
             portable_fault_hits, (long)portable_fault_offset,
             (unsigned long)portable_fault_requested, portable_fault_return);
    } else if (strncmp(line, "FAULT ARM ", 10) == 0) {
      unsigned record;
      assert_int_equal(sscanf(line + 10, "%u %u %d", &record,
                             &portable_fault_skip, &portable_fault_return), 3);
      assert_true(record == FAULT_RECORD_BLOB || record == FAULT_RECORD_CERTIFICATE);
      assert_true(portable_fault_return >= -1 && portable_fault_return <= 1);
      portable_fault_path = record == FAULT_RECORD_BLOB ? "ctap_lb" : "ctap_cert";
      portable_fault_hits = 0;
      portable_fault_offset = 0;
      portable_fault_requested = 0;
      printf("FAULT ARMED\n");
    } else {
      return line;
    }
  }
  return NULL;
}
#define fgets portable_fault_fgets
