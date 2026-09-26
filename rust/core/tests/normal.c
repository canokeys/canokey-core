/* SPDX-License-Identifier: Apache-2.0 */
#include "core.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static uint8_t buffer[258];
static uint8_t transport_owner = 1;
static int exchange(const uint8_t *in, size_t n, uint16_t sw) {
  memcpy(buffer, in, n);
  int result = ck_core_exchange(transport_owner, buffer, n, buffer, sizeof(buffer));
  assert(result >= 2);
  if (buffer[result-2] != (sw>>8) || buffer[result-1] != (sw&255))
    fprintf(stderr,"owner=%u INS=%02x len=%zu expected=%04x actual=%02x%02x\n",transport_owner,in[1],n,sw,buffer[result-2],buffer[result-1]);
  assert(buffer[result - 2] == (sw >> 8));
  assert(buffer[result - 1] == (sw & 255));
  return result - 2;
}
#define SEND(sw, ...)                                                                                                  \
  do {                                                                                                                 \
    const uint8_t request[] = {__VA_ARGS__};                                                                           \
    exchange(request, sizeof(request), sw);                                                                            \
  } while (0)
int main(void) {
  assert(ck_core_install() == 0);
#ifdef WITH_PASS
#ifdef WITH_OATH
  assert(ck_core_applet_count() ==
#ifdef WITH_OPENPGP
  3
#else
  2
#endif
#ifdef WITH_NDEF
 + 1
#endif
#ifdef WITH_PIV
  + 1
#endif
#ifdef WITH_CTAP
  + 1
#endif
);
#else
  assert(ck_core_applet_count() == 1
#ifdef WITH_NDEF
 + 1
#endif
#ifdef WITH_PIV
  + 1
#endif
#ifdef WITH_CTAP
  + 1
#endif
);
#endif
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0, 6, '1', '2', '3', '4', '5', '6');
  SEND(0x9000, 0, 0x20, 0, 0); /* Query retains the current grant. */
  /* ADMIN allows command chaining only for the (not yet enabled) FIDO certificate. */
  SEND(0x9000, 0, 0x44, 1, 0, 6, 2, 3, 'a', 'b', 'c', 1);
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0);
  SEND(0x9000, 0, 0x43, 0, 0); /* Documented read needs no explicit Le. */
  assert(buffer[0] == 2 && buffer[1] == 1 && buffer[2] == 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 4);
  assert(memcmp(buffer, "abc\r", 4) == 0);
  assert(ck_core_output_sample(0, 1501, 1) == -1);
  assert(ck_core_output_sample(1, 2100, 1) == -1);
  assert(ck_core_output_sample(0, 2200, 1) == 'a');
  assert(ck_core_output_sample(0, 2201, 0) == -1);
  assert(ck_core_output_sample(0, 2202, 1) == 'b');
  assert(ck_core_output_sample(0, 2203, 1) == 'c');
  assert(ck_core_output_sample(0, 2204, 1) == '\r');
  assert(ck_core_output_sample(0, 2205, 1) == -1);
  SEND(0x6102, 0, 0x43, 0, 0, 1);
  assert(buffer[0] == 2);
  SEND(0x9000, 0, 0xc0, 0, 0, 2);
  assert(buffer[0] == 1 && buffer[1] == 0);
  /* RFC 2202 HMAC-SHA1 vector. */
  uint8_t config[27] = {0, 0x44, 2, 0, 22, 3, 20};
  memset(config + 7, 0x0b, 20);
  exchange(config, sizeof(config), 0x9000);
  static const uint8_t expected[20] = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
                                       0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00};
  assert(ck_core_challenge(1, (const uint8_t *)"Hi There", 8, buffer) == 0);
  assert(memcmp(buffer, expected, 20) == 0);
  SEND(0x9000, 0, 0x21, 0, 0, 6, '6', '5', '4', '3', '2', '1');
  SEND(0x63c3, 0, 0x20, 0, 0);
  SEND(0x9000, 0, 0x20, 0, 0, 6, '6', '5', '4', '3', '2', '1');
  ck_core_reset();
  assert(ck_core_install() == 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 4);
  assert(memcmp(buffer, "abc\r", 4) == 0);
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
  SEND(0x6982, 0, 0x43, 0, 0); /* Reset revokes authentication. */
  SEND(0x9000, 0, 0x20, 0, 0, 6, '6', '5', '4', '3', '2', '1');
  SEND(0x9000, 0, 0x13, 0, 0);
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 0);
  /* Complete ordinary lock -> strong presence -> factory recovery workflow. */
  SEND(0x9000, 0, 0x44, 1, 0, 6, 2, 3, 'x', 'y', 'z', 0);
  SEND(0x63c2, 0, 0x20, 0, 0, 6, '0', '0', '0', '0', '0', '0');
  SEND(0x63c1, 0, 0x20, 0, 0, 6, '0', '0', '0', '0', '0', '0');
  SEND(0x6983, 0, 0x20, 0, 0, 6, '0', '0', '0', '0', '0', '0');
  SEND(0x9000, 0, 0x50, 0, 0, 5, 'R', 'E', 'S', 'E', 'T');
  SEND(0x9000, 0, 0x20, 0, 0, 6, '1', '2', '3', '4', '5', '6');
  assert(ck_core_touch(0, buffer, sizeof(buffer)) == 0);
#else
  assert(ck_core_applet_count() ==
 0
#ifdef WITH_NDEF
 + 1
#endif
#ifdef WITH_PIV
 + 1
#endif
#ifdef WITH_CTAP
 + 2 /* Independent CTAP also includes ADMIN for provisioning. */
#endif
);
#ifdef WITH_CTAP
  SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
#else
  SEND(0x6a82, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
#endif
#endif
#ifdef WITH_NDEF
  ck_core_reset();
#if defined(WITH_PASS) || defined(WITH_CTAP)
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x6982,0,0x08,1,0);
  SEND(0x6982,0,0x07,0,0);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x6a86,0,0x08,2,0);
  SEND(0x9000,0,0x08,1,0);
  SEND(0x9000,0,0xa4,4,0,7,0xd2,0x76,0,0,0x85,1,1);
  SEND(0x9000,0,0xa4,0,12,2,0,1);
  SEND(0x6982,0,0xd6,0,0,1,0);
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x9000,0,0x07,0,0);
#endif
  SEND(0x9000,0,0xa4,4,0,7,0xd2,0x76,0,0,0x85,1,1);
  SEND(0x9000,0,0xa4,0,12,2,0xe1,3);
  SEND(0x9000,0,0xb0,0,0,15);
  const uint8_t cc[]={0,15,0x20,4,0,4,0,4,6,0,1,4,0,0,0};
  assert(!memcmp(buffer,cc,sizeof(cc)));
  SEND(0x9000,0,0xa4,0,12,2,0,1);
  SEND(0x9000,0x10,0xd6,0,100,2,0xaa,0xbb);
  SEND(0x9000,0,0xd6,0,100,1,0xcc);
  SEND(0x9000,0,0xb0,0,100,3);assert(!memcmp(buffer,"\xaa\xbb\xcc",3));
  SEND(0x61ff,0,0xb0,0,0,0,4,0);
  SEND(0x61ff,0,0xc0,0,0,0);
  SEND(0x61ff,0,0xc0,0,0,0);
  SEND(0x9000,0,0xc0,0,0,0);
#endif
#if defined(WITH_PASS) || defined(WITH_CTAP)
  ck_core_reset();
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x6982,0,0x14,1,0);
  SEND(0x6982,0,0x40,6,0);
  SEND(0x6700,0,0x42,0,0,5);
  SEND(0x9000,0,0x42,0,0,6);
  assert(buffer[0]==1 && buffer[1]==0 && buffer[3]==1 && buffer[4]==1 && buffer[5]==0x3f);
  SEND(0x9000,0,0x14,0,0,1);assert(buffer[0]==1);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x6a86,0,0x40,6,0x80);
  SEND(0x9000,0,0x14,1,0);
  SEND(0x9000,0,0x40,6,0);
  SEND(0x9000,0,0x40,4,0);
  ck_core_reset();
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x9000,0,0x14,0,0,1);assert(buffer[0]==0);
  SEND(0x9000,0,0x42,0,0,6);assert(buffer[3]==0 && buffer[5]==0);
#ifdef WITH_NDEF
  SEND(0x6a82,0,0xa4,4,0,7,0xd2,0x76,0,0,0x85,1,1);
#endif
#ifdef WITH_OPENPGP
  SEND(0x6a82,0,0xa4,4,0,6,0xd2,0x76,0,1,0x24,1);
#endif
#ifdef WITH_PIV
  SEND(0x6a82,0,0xa4,4,0,5,0xa0,0,0,3,8);
#endif
#ifdef WITH_CTAP
  SEND(0x6a82,0,0xa4,4,0,8,0xa0,0,0,6,0x47,0x2f,0,1);
#endif
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x9000,0,0x14,1,1);
  SEND(0x9000,0,0x40,6,0x3f);
  SEND(0x9000,0,0x40,4,1);
#endif
#ifdef WITH_CTAP
  /* The NFC owner uses the same extended FIDO decoder and response cursor. */
  ck_core_reset();transport_owner=4;
  SEND(0x9000,0,0xa4,4,0,8,0xa0,0,0,6,0x47,0x2f,0,1);
  const uint8_t get_info[]={0x80,0x10,0,0,0,0,1,4};
  memcpy(buffer,get_info,sizeof(get_info));
  int initial=ck_core_exchange(4,buffer,sizeof(get_info),buffer,sizeof(buffer));
  assert(initial==258 && buffer[256]==0x61 && buffer[0]==0 && (buffer[1]&0xe0)==0xa0);
  unsigned chunks=0,total=256;
  for(;;) {
    const uint8_t next[]={0,0xc0,0,0,0};
    memcpy(buffer,next,sizeof(next));
    int n=ck_core_exchange(4,buffer,sizeof(next),buffer,sizeof(buffer));
    assert(n>=2 && ++chunks<=8);
    total+=(unsigned)n-2;
    if(buffer[n-2]==0x90){assert(buffer[n-1]==0);break;}
    assert(buffer[n-2]==0x61);
  }
  assert(total>256);
  ck_core_reset();transport_owner=1;
#endif
  return 0;
}
