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
#include <ml-dsa-65.h>
#include <pin.h>

#define PATH "key"

static void test_encode_rsa(void **state) {
  (void)state;

  uint8_t buf[1024];
  uint8_t expected[525] = {
      0x82, 0x02, 0x0a, 0x81, 0x82, 0x02, 0x00, 0xbe, 0x0b, 0x66, 0x3c, 0x1c, 0xb9, 0x6d, 0x9c, 0x26, 0x8b, 0xe6, 0xc3,
      0x6f, 0x0d, 0xb3, 0xb7, 0xa3, 0xa2, 0xa6, 0xd7, 0xcf, 0x0a, 0x62, 0x63, 0xb7, 0x31, 0xd3, 0x63, 0xb0, 0x14, 0xc4,
      0x08, 0xf7, 0x87, 0xd0, 0xd9, 0x43, 0x2c, 0x12, 0xb6, 0xc6, 0x35, 0x5d, 0x36, 0xb5, 0x7b, 0xe7, 0xaf, 0xe5, 0x5a,
      0xf5, 0x39, 0x85, 0xe0, 0xaf, 0xca, 0x9a, 0x44, 0x68, 0xf0, 0x23, 0xa8, 0x78, 0xc3, 0x45, 0x70, 0x0b, 0xee, 0x55,
      0x5b, 0x9a, 0x06, 0xbe, 0xfa, 0x5e, 0x54, 0x0a, 0xd9, 0xc2, 0xd6, 0x83, 0x66, 0xef, 0x21, 0x12, 0x28, 0xc6, 0x49,
      0xb5, 0x4a, 0x59, 0x9a, 0xf0, 0x98, 0xa3, 0x49, 0x83, 0x55, 0x53, 0xf3, 0x6d, 0x58, 0x17, 0x68, 0x6d, 0x36, 0x12,
      0x17, 0x05, 0x0d, 0xaf, 0x4b, 0x51, 0xae, 0x4c, 0x88, 0x52, 0xe0, 0x2c, 0xc1, 0xaf, 0x3b, 0x14, 0x0e, 0xfb, 0x7b,
      0x9b, 0x03, 0x63, 0xbd, 0xca, 0x84, 0x81, 0x7b, 0x1c, 0xb3, 0x40, 0xa2, 0xce, 0x28, 0x8d, 0xd6, 0xe0, 0xb6, 0xae,
      0xb2, 0x6d, 0x84, 0x21, 0x7d, 0xf0, 0x56, 0xc5, 0xa8, 0x98, 0xec, 0x42, 0x28, 0x7d, 0x2d, 0x25, 0xe5, 0x3d, 0x34,
      0x89, 0xdd, 0x41, 0x33, 0xc5, 0xf7, 0x03, 0xef, 0xe6, 0xf7, 0x78, 0xc1, 0x65, 0xac, 0xf8, 0xff, 0x71, 0xa1, 0xc1,
      0xc5, 0x4d, 0xf3, 0x58, 0x70, 0xf7, 0x5a, 0x31, 0x3f, 0x20, 0x47, 0x8b, 0x36, 0x14, 0x76, 0x1e, 0x14, 0x9b, 0x1e,
      0xc4, 0x37, 0x50, 0xfa, 0xc8, 0x55, 0xe6, 0x44, 0xef, 0x10, 0x92, 0x57, 0x8f, 0x05, 0x4f, 0xd4, 0xe6, 0xb5, 0x0d,
      0x87, 0x71, 0xad, 0x3f, 0x60, 0x65, 0xba, 0xc3, 0xba, 0xd5, 0xbe, 0xb4, 0xa1, 0xb8, 0xa1, 0x07, 0x97, 0x69, 0x29,
      0x12, 0xc5, 0x8a, 0x41, 0xd9, 0x18, 0x5e, 0xd3, 0x37, 0x73, 0xe7, 0x2d, 0xfa, 0xf5, 0x1a, 0x44, 0x71, 0xb3, 0x6e,
      0x4e, 0x97, 0xb2, 0xb6, 0xaa, 0xc8, 0xb4, 0x96, 0x5b, 0x44, 0xb1, 0x61, 0x27, 0x5d, 0xc3, 0xfb, 0x81, 0x21, 0x15,
      0x2c, 0x6e, 0x92, 0xb7, 0x36, 0x57, 0x44, 0x15, 0x2d, 0xe3, 0xeb, 0x1d, 0xc6, 0xb4, 0x25, 0x3a, 0x8f, 0xf9, 0x73,
      0xaa, 0x90, 0x22, 0xd3, 0xbc, 0x70, 0x27, 0x3c, 0xc0, 0x69, 0x6e, 0x37, 0x71, 0x48, 0xcf, 0x51, 0x0b, 0x5a, 0xb3,
      0x0c, 0x7a, 0x05, 0xab, 0x8f, 0xd2, 0x31, 0x4a, 0xc1, 0xb7, 0xb8, 0x8a, 0xc0, 0x4b, 0x8e, 0x4d, 0x9c, 0x30, 0x0e,
      0x8a, 0x9e, 0x6d, 0x8e, 0xe5, 0xde, 0x47, 0xa2, 0x15, 0x93, 0x28, 0x86, 0x7c, 0x89, 0x1d, 0x20, 0x55, 0x2b, 0x7b,
      0x87, 0xc9, 0x7c, 0x50, 0xb4, 0x38, 0x98, 0x48, 0xb4, 0x00, 0x8d, 0x99, 0x26, 0x7d, 0x6c, 0x24, 0x40, 0xea, 0xff,
      0x93, 0x1b, 0x46, 0x49, 0x2f, 0xb0, 0x04, 0x4d, 0x92, 0xe5, 0xb8, 0xce, 0xd8, 0x11, 0x7a, 0xa8, 0x72, 0xdd, 0x99,
      0x5c, 0xc5, 0xb1, 0xa9, 0x2c, 0xdc, 0x6f, 0xb9, 0xb0, 0x4f, 0x08, 0x48, 0xcc, 0xf5, 0xd6, 0xdf, 0xeb, 0x94, 0x79,
      0x10, 0x04, 0xdd, 0x4a, 0x01, 0x4b, 0x47, 0x2b, 0xcc, 0x22, 0x83, 0x1a, 0x71, 0xc3, 0x5f, 0xb7, 0x6c, 0x94, 0x6a,
      0x4e, 0xb3, 0x84, 0x23, 0x17, 0x80, 0x7d, 0x70, 0x11, 0xde, 0xc9, 0x3c, 0x2e, 0xe0, 0xff, 0x66, 0x53, 0x6b, 0x83,
      0x30, 0x16, 0xea, 0xcf, 0xf2, 0xe1, 0x9d, 0xc1, 0x81, 0xeb, 0x3b, 0x2b, 0x02, 0x1b, 0x2c, 0x26, 0x41, 0xca, 0x9f,
      0x9c, 0x3b, 0x96, 0x93, 0x6b, 0x6c, 0xd6, 0xf1, 0x0c, 0x05, 0x73, 0xbf, 0xc2, 0x92, 0xe9, 0x34, 0x36, 0x51, 0x66,
      0x42, 0x18, 0x25, 0x3b, 0xc3, 0x3f, 0x3b, 0xe2, 0x5a, 0xf7, 0x2d, 0x58, 0xf4, 0x92, 0xd5, 0xb7, 0x12, 0x31, 0x98,
      0x66, 0x49, 0x78, 0x0f, 0xa7, 0xef, 0x82, 0x04, 0x00, 0x01, 0x00, 0x01};

  uint8_t p[] = {
      0xeb, 0x62, 0x84, 0x34, 0xbc, 0xc2, 0xb8, 0x9b, 0xaf, 0xb2, 0xfe, 0x3e, 0x64, 0xa9, 0x32, 0xdc, 0x8b, 0xe9, 0x0c,
      0x11, 0xe9, 0x54, 0x58, 0x9c, 0x11, 0x20, 0xc9, 0x38, 0x88, 0x2e, 0xe8, 0xbb, 0xa7, 0x86, 0xbe, 0x21, 0x78, 0x73,
      0x05, 0xa9, 0xbc, 0xb6, 0x3c, 0x9f, 0x7a, 0xc3, 0xc2, 0x83, 0x8f, 0x0c, 0x84, 0x58, 0xac, 0xfc, 0x2b, 0x62, 0xe7,
      0xcb, 0xf8, 0xc1, 0x59, 0x8a, 0x6d, 0x8c, 0x0d, 0x9e, 0x34, 0x36, 0x62, 0xe3, 0x7e, 0x37, 0xae, 0xfb, 0xe4, 0x9b,
      0x3f, 0xce, 0x5c, 0xaa, 0xfb, 0x36, 0xf0, 0x3a, 0xa1, 0x54, 0xfd, 0x99, 0x6f, 0x15, 0xd6, 0xce, 0xc4, 0xe8, 0xf8,
      0xf1, 0x63, 0x18, 0x2f, 0xf7, 0xc5, 0x33, 0xeb, 0x40, 0x14, 0x0e, 0x36, 0x86, 0x1c, 0xf3, 0x8e, 0x59, 0x2e, 0x45,
      0x12, 0x7e, 0x3e, 0x02, 0xa2, 0x84, 0xfc, 0xf9, 0x56, 0xb0, 0xd8, 0x4e, 0xfc, 0x6d, 0x00, 0x0e, 0xcd, 0x9b, 0x6d,
      0x08, 0x9f, 0x12, 0x2a, 0x84, 0x72, 0x54, 0x78, 0xe2, 0xcf, 0x86, 0xfc, 0xe5, 0x17, 0x09, 0x60, 0xc9, 0xce, 0x83,
      0x8a, 0x2d, 0x71, 0x70, 0x3e, 0x4b, 0xa6, 0xbc, 0xdf, 0x4e, 0x30, 0x3f, 0xff, 0x1f, 0xb1, 0xe8, 0x23, 0x6e, 0x02,
      0x48, 0x4e, 0x87, 0xf1, 0xda, 0x18, 0x57, 0xa8, 0xda, 0xbd, 0xeb, 0x5e, 0xb0, 0x45, 0x67, 0x3b, 0x1a, 0x06, 0xc1,
      0xff, 0x08, 0xc5, 0xc2, 0x12, 0x71, 0xa4, 0x32, 0xc3, 0x5c, 0x6c, 0x9b, 0x38, 0x13, 0x71, 0x02, 0xd9, 0x92, 0x93,
      0x11, 0x90, 0x3a, 0xfb, 0xd1, 0xae, 0x05, 0x73, 0xe7, 0x2b, 0x4b, 0x38, 0x1e, 0xb6, 0xbd, 0x15, 0x42, 0x36, 0x07,
      0x3e, 0xaa, 0x42, 0x2b, 0xc9, 0x8b, 0xe4, 0xf1, 0x41, 0xbb, 0x72, 0x2a, 0x51, 0xb6, 0x8a, 0x28, 0x7a, 0x89, 0x6b,
      0xf5, 0x3a, 0x79, 0xc4, 0x36, 0x46, 0x84, 0x2e, 0xff};
  uint8_t q[] = {
      0xce, 0xb0, 0x52, 0xc9, 0x73, 0x26, 0x14, 0xfe, 0xe3, 0xc0, 0xa1, 0x97, 0xa5, 0xae, 0x0f, 0xcd, 0x83, 0x42, 0x22,
      0x43, 0x91, 0x8a, 0xb8, 0x3b, 0xc6, 0x78, 0x65, 0x6a, 0xe0, 0x34, 0x42, 0x32, 0xa7, 0xc1, 0x07, 0x0b, 0x7d, 0x5a,
      0xab, 0xaa, 0xe2, 0xbd, 0xa9, 0x6b, 0xf5, 0x90, 0xda, 0x48, 0x30, 0x23, 0x8b, 0x60, 0x6f, 0x24, 0xb2, 0x96, 0x26,
      0xf1, 0xbf, 0xa0, 0x0c, 0xce, 0x39, 0xf5, 0xf9, 0xbb, 0x9c, 0x1c, 0x3e, 0xad, 0x98, 0xf2, 0x05, 0x5e, 0x37, 0x3a,
      0xbf, 0x01, 0xe1, 0xfe, 0x1c, 0x81, 0x6e, 0x12, 0xe0, 0xed, 0x13, 0x79, 0x14, 0x61, 0xc4, 0x35, 0x12, 0x3d, 0xad,
      0x8c, 0xbe, 0x80, 0xe4, 0x74, 0xf7, 0x53, 0xaa, 0x9d, 0x11, 0x5a, 0x8b, 0x93, 0xc1, 0x67, 0xad, 0xce, 0xae, 0xe5,
      0xa1, 0x8c, 0xee, 0xde, 0xf8, 0x8d, 0x30, 0x74, 0x27, 0xfc, 0x49, 0x5d, 0x9e, 0x44, 0xd4, 0x26, 0x8b, 0xa8, 0x3c,
      0x4a, 0x65, 0xc4, 0x66, 0x7b, 0x7d, 0xf7, 0x9f, 0x34, 0x26, 0x39, 0xda, 0x3d, 0xdd, 0x27, 0x77, 0x92, 0x68, 0x48,
      0x85, 0x5c, 0xa0, 0x06, 0x86, 0x68, 0xef, 0xe7, 0xf2, 0x7d, 0x65, 0xf4, 0x55, 0x07, 0x4c, 0x96, 0x0b, 0xbc, 0x16,
      0x8b, 0xfb, 0x3a, 0x12, 0x25, 0xcd, 0x6f, 0x42, 0x58, 0x5d, 0xdb, 0xa6, 0xb3, 0x48, 0x4f, 0x36, 0x70, 0x75, 0x24,
      0x13, 0x3b, 0x81, 0xdd, 0x01, 0xd0, 0x62, 0x59, 0x1f, 0xec, 0x1b, 0x75, 0x67, 0x66, 0xae, 0xeb, 0xe6, 0x67, 0xbf,
      0x9e, 0x24, 0x80, 0xee, 0xbb, 0x59, 0x64, 0xbc, 0x5e, 0xaf, 0xf4, 0xb1, 0x65, 0xe1, 0x42, 0x77, 0x2c, 0xe6, 0x4b,
      0x22, 0x9a, 0x72, 0x58, 0x66, 0x7a, 0x39, 0x64, 0xf0, 0x8e, 0x06, 0xdf, 0xbf, 0xe3, 0xe3, 0xc1, 0xcf, 0x91, 0x83,
      0x95, 0xb8, 0x9c, 0x1f, 0xdb, 0x18, 0x90, 0x77, 0x11};

  ck_key_t key = {.meta.type = RSA4096, .meta.origin = KEY_ORIGIN_IMPORTED, .meta.usage = SIGN};
  key.rsa.nbits = 4096;
  memcpy(key.rsa.p, p, 256);
  memcpy(key.rsa.q, q, 256);
  memcpy(key.rsa.e, "\x00\x01\x00\x01", 4);
  assert_int_equal(write_file(PATH, &key, 0, sizeof(key), 1), 0);
  int size = ck_encode_public_key(&key, buf, false);
  assert_int_equal(size, 522);
  assert_memory_equal(buf, expected + 3, 522);
  size = ck_encode_public_key(&key, buf, true);
  assert_int_equal(size, 525);
  assert_memory_equal(buf, expected, 525);
}

static void test_encode_ecdsa(void **state) {
  (void)state;

  uint8_t buf[1024], expected[1024];

  ck_key_t key = {.meta.type = SECP256R1, .meta.origin = KEY_ORIGIN_IMPORTED, .meta.usage = SIGN};
  memcpy(key.ecc.pri,
         "\xd3\x05\x19\xbc\xae\x8d\x18\x0d\xbf\xcc\x94\xfe\x0b\x83\x83\xdc\x31\x01\x85\xb0\xbe\x97\xb4\x36\x50\x83\xeb"
         "\xce\xcc\xd7\x57\x59",
         32);
  memcpy(key.ecc.pub,
         "\x3a\xf1\xe1\xef\xa4\xd1\xe1\xad\x5c\xb9\xe3\x96\x7e\x98\xe9\x01\xda\xfc\xd3\x7c\x44\xcf\x0b\xfb\x6c\x21\x69"
         "\x97\xf5\xee\x51\xdf\xe4\xac\xac\x3e\x6f\x13\x9e\x0c\x7d\xb2\xbd\x73\x68\x24\xf5\x13\x92\xbd\xa1\x76\x96\x5a"
         "\x1c\x59\xeb\x9c\x3c\x5f\xf9\xe8\x5d\x7a",
         64);
  memcpy(expected,
         "\x43\x86\x41\x04\x3a\xf1\xe1\xef\xa4\xd1\xe1\xad\x5c\xb9\xe3\x96\x7e\x98\xe9\x01\xda\xfc\xd3\x7c\x44\xcf\x0b"
         "\xfb\x6c\x21\x69\x97\xf5\xee\x51\xdf\xe4\xac\xac\x3e\x6f\x13\x9e\x0c\x7d\xb2\xbd\x73\x68\x24\xf5\x13\x92\xbd"
         "\xa1\x76\x96\x5a\x1c\x59\xeb\x9c\x3c\x5f\xf9\xe8\x5d\x7a",
         68);
  assert_int_equal(write_file(PATH, &key, 0, sizeof(key), 1), 0);
  int size = ck_encode_public_key(&key, buf, false);
  assert_int_equal(size, 67);
  assert_memory_equal(buf, expected + 1, 67);
  size = ck_encode_public_key(&key, buf, true);
  assert_int_equal(size, 68);
  assert_memory_equal(buf, expected, 68);
}

static void test_encode_p521_length(void **state) {
  (void)state;
  ck_key_t key = {.meta.type = SECP521R1};
  uint8_t buf[138];
  for (size_t i = 0; i < 132; ++i) key.ecc.pub[i] = (uint8_t)i;
  const uint8_t header[] = {0x81, 0x88, 0x86, 0x81, 0x85, 0x04};
  assert_int_equal(ck_encode_public_key(&key, buf, true), sizeof(buf));
  assert_memory_equal(buf, header, sizeof(header));
  assert_memory_equal(buf + sizeof(header), key.ecc.pub, 132);
  assert_int_equal(ck_encode_public_key(&key, buf, false), 136);
  assert_memory_equal(buf, header + 2, sizeof(header) - 2);
  assert_memory_equal(buf + sizeof(header) - 2, key.ecc.pub, 132);
}

static void test_encode_eddsa(void **state) {
  (void)state;

  uint8_t buf[1024], expected[1024];

  ck_key_t key = {.meta.type = ED25519, .meta.origin = KEY_ORIGIN_IMPORTED, .meta.usage = SIGN};
  memcpy(key.ecc.pri,
         "\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac"
         "\x03\x1c\xae\x7f\x60",
         32);
  memcpy(key.ecc.pub,
         "\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a"
         "\x68\xf7\x07\x51\x1a",
         32);
  memcpy(expected,
         "\x22\x86\x20\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25"
         "\xaf\x02\x1a\x68\xf7\x07\x51\x1a",
         35);
  assert_int_equal(write_file(PATH, &key, 0, sizeof(key), 1), 0);
  int size = ck_encode_public_key(&key, buf, false);
  assert_int_equal(size, 34);
  assert_memory_equal(buf, expected + 1, 34);
  size = ck_encode_public_key(&key, buf, true);
  assert_int_equal(size, 35);
  assert_memory_equal(buf, expected, 35);

  key.meta.type = X25519;
  memcpy(key.ecc.pri,
         "\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb"
         "\xa5\x1d\xb9\x2c\x2a",
         32); // we store the private key in big endian
  memcpy(key.ecc.pub,
         "\x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4\xeb\xa4\xa9"
         "\x8e\xaa\x9b\x4e\x6a",
         32); // we store the public key in big endian
  memcpy(expected,
         "\x22\x86\x20\x6a\x4e\x9b\xaa\x8e\xa9\xa4\xeb\xf4\x1a\x38\x26\x0d\x3a\xbf\x0d\x5a\xf7\x3e\xb4\xdc\x7d\x8b\x74"
         "\x54\xa7\x30\x89\x09\xf0\x20\x85",
         35);
  assert_int_equal(write_file(PATH, &key, 0, sizeof(key), 1), 0);
  size = ck_encode_public_key(&key, buf, false);
  assert_int_equal(size, 34);
  assert_memory_equal(buf, expected + 1, 34);
  size = ck_encode_public_key(&key, buf, true);
  assert_int_equal(size, 35);
  assert_memory_equal(buf, expected, 35);
}

static void test_encode_mldsa(void **state) {
  (void)state;
  static const uint8_t prefix[] = {0x82, 0x07, 0xA4, 0x86, 0x82, 0x07, 0xA0};
  uint8_t expected[MLDSA_PK_BYTES];
  uint8_t guarded[MLDSA_PK_BYTES + sizeof(prefix) + 2];
  ck_key_t key = {.meta.type = MLDSA65};

  for (unsigned seed_case = 0; seed_case < 4; ++seed_case) {
    uint8_t seed[MLDSA_SEEDBYTES];
    for (size_t i = 0; i < sizeof(seed); ++i)
      seed[i] = seed_case == 0 ? 0 : seed_case == 1 ? 0xFF : (uint8_t)(i * seed_case + 1);
    memcpy(key.mldsa.seed, seed, sizeof(seed));
    assert_int_equal(ml_dsa_65_keygen(expected, NULL, NULL, seed), 0);

    for (unsigned include_length = 0; include_length <= 1; ++include_length) {
      const size_t prefix_offset = include_length ? 0 : 3;
      const size_t prefix_len = sizeof(prefix) - prefix_offset;
      const size_t expected_len = prefix_len + sizeof(expected);
      memset(guarded, 0xA5, sizeof(guarded));
      assert_int_equal(ck_encoded_public_key_length(MLDSA65, include_length), expected_len);
      assert_int_equal(ck_encode_public_key(&key, guarded + 1, include_length), expected_len);
      assert_memory_equal(guarded + 1, prefix + prefix_offset, prefix_len);
      assert_memory_equal(guarded + 1 + prefix_len, expected, sizeof(expected));
      assert_int_equal(guarded[0], 0xA5);
      for (size_t i = 1 + expected_len; i < sizeof(guarded); ++i)
        assert_int_equal(guarded[i], 0xA5);
      assert_memory_equal(key.mldsa.seed, seed, sizeof(seed));
    }
  }
}

static void test_encode_invalid_type(void **state) {
  (void)state;

  uint8_t buf[1] = {0};
  ck_key_t key = {.meta.type = KEY_TYPE_PKC_END};

  assert_int_equal(ck_encode_public_key(&key, buf, false), -1);
  key.meta.type = AES128;
  assert_int_equal(ck_encode_public_key(&key, buf, true), -1);
}

// RFC 7748 §6.1 Alice X25519 test vector, clamped per RFC 7748 §5.
//
// OpenPGP keytocard sends the X25519 private scalar as a big-endian MPI (this
// is the gpg / RFC 4880 convention, not the RFC 7748 §5 little-endian wire
// format used by PIV / NIST SP 800-78-5). gpg / libgcrypt clamps the scalar
// host-side before transmission, so the bytes the card receives are already
// canonical; mbedtls_ecp_check_privkey expects the same shape and would
// reject an unclamped scalar with all-zero output. The card stores it BE
// internally and derives the public key directly. Encoding the public for
// readback swaps back to little-endian, which is the standard X25519 public
// wire form.
//
// Alice raw private (RFC 7748 §6.1, LE): 77076d0a...1db92c2a
// After RFC 7748 §5 clamp:               70076d0a...1db92c6a
// Big-endian wire form (byte-reversed):  6a2cb91d...0a6d0770
static const uint8_t rfc7748_alice_pri_be_clamped[32] = {
    0x6a, 0x2c, 0xb9, 0x1d, 0xa5, 0xfb, 0x77, 0xb1, 0x2a, 0x99, 0xc0,
    0xeb, 0x87, 0x2f, 0x4c, 0xdf, 0x45, 0x66, 0xb2, 0x51, 0x72, 0xc1,
    0x16, 0x3c, 0x7d, 0xa5, 0x18, 0x73, 0x0a, 0x6d, 0x07, 0x70,
};
static const uint8_t rfc7748_alice_pri_le_clamped[32] = {
    0x70, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
    0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
    0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x6a,
};
static const uint8_t rfc7748_alice_pub_le[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
    0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
    0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
};

static void build_openpgp_x25519_tlv(uint8_t out[40], const uint8_t pri_be[32]) {
  out[0] = 0x7F;
  out[1] = 0x48;
  out[2] = 0x02;
  out[3] = 0x92;
  out[4] = 0x20;
  out[5] = 0x5F;
  out[6] = 0x48;
  out[7] = 0x20;
  memcpy(out + 8, pri_be, 32);
}

static void assert_x25519_alice_round_trip(const ck_key_t *key) {
  // ecc.pri stays in BE storage exactly as the wire delivered it.
  assert_memory_equal(key->ecc.pri, rfc7748_alice_pri_be_clamped, 32);
  uint8_t buf[64];
  int size = ck_encode_public_key((ck_key_t *)key, buf, false);
  assert_int_equal(size, 34);
  assert_int_equal(buf[0], 0x86);
  assert_int_equal(buf[1], 32);
  assert_memory_equal(buf + 2, rfc7748_alice_pub_le, 32);
}

static void test_parse_openpgp_x25519_streaming_rfc7748(void **state) {
  (void)state;
  uint8_t imported[40];
  build_openpgp_x25519_tlv(imported, rfc7748_alice_pri_be_clamped);

  ck_key_t key = {.meta.type = X25519, .meta.origin = KEY_ORIGIN_NOT_PRESENT, .meta.usage = ENCRYPT};
  ck_openpgp_stream_t st;
  ck_parse_openpgp_stream_init(&st, &key, sizeof(imported));

  // Feed in 7-byte chunks to exercise the streaming state machine across
  // arbitrary boundaries (template, component-len, payload).
  size_t off = 0;
  while (off < sizeof(imported)) {
    size_t chunk = sizeof(imported) - off;
    if (chunk > 7) chunk = 7;
    bool final = (off + chunk == sizeof(imported));
    int rc = ck_parse_openpgp_stream_update(&st, &key, imported + off, chunk, final);
    assert_int_equal(rc, final ? 1 : 0);
    off += chunk;
  }
  assert_x25519_alice_round_trip(&key);
}

static void test_parse_piv_x25519_streaming_rfc7748(void **state) {
  (void)state;
  // PIV X25519 import APDU body: 0x08 (priv tag) + 0x20 (len) + 32 bytes LE.
  // The streaming parser swaps LE→BE during ingest so the stored bytes
  // match the OpenPGP path's BE form and the derived public is the
  // canonical Alice pub.
  uint8_t imported[34] = {0x08, 0x20};
  memcpy(imported + 2, rfc7748_alice_pri_le_clamped, 32);

  ck_key_t key = {.meta.type = X25519, .meta.origin = KEY_ORIGIN_NOT_PRESENT, .meta.usage = KEY_AGREEMENT};
  ck_piv_stream_t st;
  ck_parse_piv_stream_init(&st, &key);

  size_t off = 0;
  while (off < sizeof(imported)) {
    size_t chunk = sizeof(imported) - off;
    if (chunk > 5) chunk = 5;
    bool final = (off + chunk == sizeof(imported));
    int rc = ck_parse_piv_stream_update(&st, &key, imported + off, chunk, final);
    assert_int_equal(rc, final ? 1 : 0);
    off += chunk;
  }
  assert_x25519_alice_round_trip(&key);
}

static void test_parse_piv_rsa_rejects_invalid_component_bounds(void **state) {
  (void)state;
  ck_key_t key = {.meta.type = RSA4096, .meta.origin = KEY_ORIGIN_NOT_PRESENT, .meta.usage = SIGN};
  ck_piv_stream_t st;
  ck_parse_piv_stream_init(&st, &key);

  const uint8_t empty_component[] = {0x01, 0x00, 0xA5};
  assert_int_equal(ck_parse_piv_stream_update(&st, &key, empty_component, sizeof(empty_component), false),
                   KEY_ERR_DATA);
  assert_int_equal(key.rsa.q[0], 0);

  ck_parse_piv_stream_init(&st, &key);
  const uint8_t one_byte_component_header[] = {0x01, 0x01};
  assert_int_equal(
      ck_parse_piv_stream_update(&st, &key, one_byte_component_header, sizeof(one_byte_component_header), false), 0);
  st.comp_off = st.comp_len;
  const uint8_t component_data = 0xA5;
  assert_int_equal(ck_parse_piv_stream_update(&st, &key, &component_data, sizeof(component_data), false), KEY_ERR_DATA);
  assert_int_equal(key.rsa.q[0], 0);
}

static void test_tlv_len_stream_feed(void **state) {
  (void)state;
  tlv_len_stream_t stream = {0};
  uint16_t length = 0;

  assert_int_equal(tlv_len_stream_feed(&stream, 0x7F, &length), 1);
  assert_int_equal(length, 0x7F);
  assert_int_equal(tlv_len_stream_feed(&stream, 0x82, &length), 0);
  assert_int_equal(tlv_len_stream_feed(&stream, 0x01, &length), 0);
  assert_int_equal(tlv_len_stream_feed(&stream, 0x02, &length), 1);
  assert_int_equal(length, 0x0102);
  assert_int_equal(tlv_len_stream_feed(&stream, 0x20, &length), 1);
  assert_int_equal(length, 0x20);

  memset(&stream, 0, sizeof(stream));
  assert_int_equal(tlv_len_stream_feed(&stream, 0x80, &length), -1);
  memset(&stream, 0, sizeof(stream));
  assert_int_equal(tlv_len_stream_feed(&stream, 0x83, &length), -1);
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

static void test_ecc_key_persists_only_ecc_material(void **state) {
  (void)state;
  ck_key_t expected;
  ck_key_init_empty(&expected, SECP521R1, SIGN, PIN_POLICY_ONCE, TOUCH_POLICY_CACHED);
  expected.meta.origin = KEY_ORIGIN_GENERATED;
  memset(expected.ecc.pri, 0x5A, sizeof(expected.ecc.pri));
  memset(expected.ecc.pub, 0xA5, sizeof(expected.ecc.pub));

  assert_int_equal(ck_write_key(PATH, &expected), 0);
  assert_int_equal(get_file_size(PATH), sizeof(ecc_key_t));

  ck_key_t actual;
  memset(&actual, 0xCC, sizeof(actual));
  assert_int_equal(ck_read_key(PATH, &actual), sizeof(ecc_key_t));
  assert_memory_equal(&actual.meta, &expected.meta, sizeof(expected.meta));
  assert_memory_equal(&actual.ecc, &expected.ecc, sizeof(expected.ecc));
}

static void test_parse_piv_policies_rejects_truncated_fields(void **state) {
  (void)state;
  static const uint8_t truncated[][2] = {
      {0xAA, 0x00},
      {0xAA, 0x01},
      {0xAB, 0x00},
      {0xAB, 0x01},
  };

  for (size_t i = 0; i < sizeof(truncated) / sizeof(truncated[0]); ++i) {
    ck_key_t key;
    ck_key_init_empty(&key, SECP256R1, SIGN, PIN_POLICY_ONCE, TOUCH_POLICY_NEVER);
    const size_t len = i % 2 == 0 ? 1 : 2;
    assert_int_equal(ck_parse_piv_policies(&key, truncated[i], len), KEY_ERR_LENGTH);
    assert_int_equal(key.meta.pin_policy, PIN_POLICY_ONCE);
    assert_int_equal(key.meta.touch_policy, TOUCH_POLICY_NEVER);
  }
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
      cmocka_unit_test(test_encode_rsa),
      cmocka_unit_test(test_encode_ecdsa),
      cmocka_unit_test(test_encode_p521_length),
      cmocka_unit_test(test_encode_eddsa),
      cmocka_unit_test(test_encode_mldsa),
      cmocka_unit_test(test_encode_invalid_type),
      cmocka_unit_test(test_parse_openpgp_x25519_streaming_rfc7748),
      cmocka_unit_test(test_parse_piv_x25519_streaming_rfc7748),
      cmocka_unit_test(test_parse_piv_rsa_rejects_invalid_component_bounds),
      cmocka_unit_test(test_tlv_len_stream_feed),
      cmocka_unit_test(test_read_key_rejects_short_material),
      cmocka_unit_test(test_read_empty_key_ignores_stale_material),
      cmocka_unit_test(test_ecc_key_persists_only_ecc_material),
      cmocka_unit_test(test_parse_piv_policies_rejects_truncated_fields),
  };

  int ret = cmocka_run_group_tests(tests, NULL, NULL);

  lfs_filebd_destroy(&cfg);

  return ret;
}
