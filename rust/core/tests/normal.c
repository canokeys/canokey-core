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
#ifdef WITH_OPENPGP
static void aliased_response_regressions(void) {
  extern int32_t ck_platform_write(uint8_t, const uint8_t *, size_t);
  uint8_t payload[600];
  for(size_t i=0;i<sizeof(payload);++i)payload[i]=(uint8_t)(i*7+1);
  assert(ck_platform_write(11,payload,sizeof(payload))==600); /* PgpCertSig */
  const size_t first_capacity[]={250,249,3,2};
  const uint8_t read[]={0,0xca,0x7f,0x21,0}, next[]={0,0xc0,0,0,0};
  for(size_t variant=0;variant<4;++variant) {
    ck_core_reset(); transport_owner=1;
    SEND(0x9000,0,0xa4,4,0,6,0xd2,0x76,0,1,0x24,1);
    size_t offset=0;
    for(unsigned round=0;offset<sizeof(payload);++round) {
      assert(round<10);
      uint8_t arena[272], before[272];
      memset(arena,0xa5,sizeof(arena));
      memcpy(arena+1,round?next:read,5);
      memcpy(before,arena,sizeof(arena));
      size_t capacity=round?(variant==2?202:258):first_capacity[variant];
      int n=ck_core_exchange(1,arena+1,5,arena+1,capacity);
      size_t count=sizeof(payload)-offset;
      if(count>capacity-2)count=capacity-2;
      assert(n==(int)count+2);
      assert(!memcmp(arena+1,payload+offset,count));
      offset+=count;
      size_t remaining=sizeof(payload)-offset;
      uint16_t expected=remaining?(uint16_t)(0x6100|(remaining>255?255:remaining)):0x9000;
      assert(arena[1+count]==(expected>>8) && arena[2+count]==(expected&255));
      assert(arena[0]==0xa5);
      assert(!memcmp(arena+1+capacity,before+1+capacity,sizeof(arena)-1-capacity));
    }
    SEND(0x6986,0,0xc0,0,0,0);
  }
  // Both zero-progress and partially consumed responses must be abandoned.
  for(uint8_t owner=1;owner<=4;owner+=3) {
    for(size_t capacity=2;capacity<=3;++capacity) {
      transport_owner=owner; ck_core_reset();
      SEND(0x9000,0,0xa4,4,0,6,0xd2,0x76,0,1,0x24,1);
      memcpy(buffer,read,sizeof(read));
      assert(ck_core_exchange(owner,buffer,sizeof(read),buffer,capacity)==(int)capacity);
      assert(buffer[capacity-2]==0x61);
      ck_core_reset();
      SEND(0x6986,0,0xc0,0,0,0);
      SEND(0x9000,0,0xa4,4,0,6,0xd2,0x76,0,1,0x24,1);
      memcpy(buffer,read,sizeof(read));
      assert(ck_core_exchange(owner,buffer,sizeof(read),buffer,capacity)==(int)capacity);
      SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
      SEND(0x9000,0,0x31,0,0,0);
      SEND(0x6986,0,0xc0,0,0,0);
    }
  }
  transport_owner=1; ck_core_reset();
}
#endif
#ifdef WITH_PIV
static void ordinary_response_cleanup_regressions(void) {
  const uint8_t version[] = {0, 0xfd, 0, 0};
  for (uint8_t owner = 1; owner <= 4; owner += 3) {
    for (size_t capacity = 2; capacity <= 3; ++capacity) {
      for (unsigned reset = 0; reset < 2; ++reset) {
        transport_owner = owner;
        ck_core_reset();
        SEND(0x9000, 0, 0xa4, 4, 0, 9, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0);
        memcpy(buffer, version, sizeof(version));
        assert(ck_core_exchange(owner, buffer, sizeof(version), buffer, capacity) == (int)capacity);
        assert(buffer[capacity - 2] == 0x61);
        assert(buffer[capacity - 1] == 5 - capacity);
        if (reset) {
          ck_core_reset();
        } else {
          SEND(0x9000, 0, 0xa4, 4, 0, 5, 0xf0, 0, 0, 0, 0);
          SEND(0x9000, 0, 0x31, 0, 0, 0);
        }
        SEND(0x6986, 0, 0xc0, 0, 0, 0);
      }
    }
  }
  transport_owner = 1;
  ck_core_reset();
}
#endif
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
  SEND(0x9000,0xff,0xee,0xff,0xee);
  assert(ck_core_output_sample(0,100,0)==-1);
  assert(ck_core_output_sample(0,101,1)==3); /* Explicit eject bypasses startup touch gate. */
  assert(ck_core_output_sample(0,102,1)==-1);
  SEND(0x9000,0xff,0xee,0xff,0xee);
  ck_core_output_cancel(0);
  assert(ck_core_output_sample(0,103,1)==-1);
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
  SEND(0x6982,0,0x40,1,0);
  SEND(0x6a86,0,0x42,1,0,6);
  SEND(0x6700,0,0x42,0,0,5);
  SEND(0x9000,0,0x42,0,0,6);
  assert(buffer[0]==1 && buffer[1]==0 && buffer[3]==1 && buffer[4]==1 && buffer[5]==0x3f);
  SEND(0x9000,0,0x14,0,0,1);assert(buffer[0]==1);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x6a86,0,0x40,6,0x80);
  SEND(0x6700,0,0x40,6,0x3f,1,0);
  SEND(0x6a86,0,0x40,0x7f,0);
  SEND(0x9000,0,0x40,1,0);
  SEND(0x9000,0,0x40,5,0);
  SEND(0x9000,0,0x14,1,0);
  SEND(0x9000,0,0x40,6,0);
  SEND(0x9000,0,0x40,4,0);
  ck_core_reset();
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x9000,0,0x14,0,0,1);assert(buffer[0]==0);
  SEND(0x9000,0,0x42,0,0,6);assert(buffer[0]==0 && buffer[3]==0 && buffer[4]==0 && buffer[5]==0);
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
  SEND(0x9000,0,0x32,0,0,4);assert(!memcmp(buffer,"\0\0\0\0",4));
  SEND(0x9000,0,0x30,0,0,4,0x12,0x34,0x56,0x78);
  SEND(0x6985,0,0x30,0,0,4,0xff,0xff,0xff,0xff);
  SEND(0x9000,0,0x32,0,0,4);assert(!memcmp(buffer,"\x12\x34\x56\x78",4));
  SEND(0x6700,0,0x32,0,0,3);
  SEND(0x6a86,0,0xff,0xff,0,1,0);
  SEND(0x6a86,0,0xff,0xfe,0,15,'D','3','5','4','9','F','a','2','d','c','b','$','2','3','n');
  SEND(0x6a86,0,0xff,0xff,2,15,'D','3','5','4','9','F','a','2','d','c','b','$','2','3','n');
  /* Host backend has no loader capability; a valid request must fail closed. */
  SEND(0x6900,0,0xff,0xff,0,15,'D','3','5','4','9','F','a','2','d','c','b','$','2','3','n');
  /* Public board information is truncated, never response-chained. */
  ck_core_reset();
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x6982,0,0xff,0xff,0,15,'D','3','5','4','9','F','a','2','d','c','b','$','2','3','n');
  /* Read-only usage retains the legacy 8-record wire format. */
  SEND(0x9000,0,0x41,0,0,2);assert(buffer[0]>=4 && buffer[1]==128);
  SEND(0x6700,0,0x41,0,0,1);
  SEND(0x6700,0,0x41,1,0,47);
  SEND(0x6a86,0,0x41,2,0,48);
  SEND(0x6a86,0,0x41,0,1,2);
  SEND(0x9000,0,0x41,1,0,48);
  for(unsigned i=0;i<7;i++) assert(buffer[i*6]==i+1);
  assert(buffer[42]==0 && buffer[43]==0 && !memcmp(buffer+44,"\0\0\x10\0",4));
  for (uint8_t kind=0;kind<3;kind++) {
    uint8_t query[]={0,0x31,kind,0,3};
    assert(exchange(query,sizeof(query),0x9000)==3);
    assert(!memcmp(buffer,"unk",3));
  }
  SEND(0x6986,0,0xc0,0,0,0);
  const uint8_t revision[]={0,0x31,2,0,0};
  assert(exchange(revision,sizeof(revision),0x9000)==7);
  assert(!memcmp(buffer,"unknown",7));
  SEND(0x6a86,0,0x31,2,1,0);
  SEND(0x6a86,0,0x31,3,0,4);
  SEND(0x6700,0,0x31,0,0,1,0);
  const uint8_t chip[]={0,0x32,1,0,13};assert(exchange(chip,sizeof(chip),0x9000)==13);
  const uint8_t chip_short[]={0,0x32,1,0,3};assert(exchange(chip_short,sizeof(chip_short),0x9000)==3);
  SEND(0x6a86,0,0x32,2,0,4);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  /* Stream a full keymap through the existing short APDU buffer. */
  SEND(0x6a88,0,0x46,0,0,1);
  SEND(0x6a86,0,0x45,1,17);
  uint8_t map_part[133]={0x10,0x45,0,17,128};
  exchange(map_part,sizeof(map_part),0x9000);
  map_part[0]=0;map_part[4]=127;
  exchange(map_part,sizeof(map_part)-1,0x6700);
  map_part[0]=0x10;map_part[4]=128;
  exchange(map_part,sizeof(map_part),0x9000);
  map_part[0]=0;map_part[7]=0x40;map_part[8]=0x1d; /* ASCII A */
  exchange(map_part,sizeof(map_part),0x9000);
  SEND(0x9000,0,0x46,0,0,1);assert(buffer[0]==17);
  SEND(0x6a86,0,0x46,0,0x7f,1);
  SEND(0x6700,0,0x46,0,1,1,0,0);
  SEND(0x6a86,0,0x47,0,1);
  SEND(0x6700,0,0x47,0,0,1,0);
  SEND(0x6700,0,0x46,0,1,255);
  SEND(0x9000,0,0x46,0,1,0);
  for(unsigned i=0;i<256;i++) assert(buffer[i]==(i==130?0x40:i==131?0x1d:0));
#ifdef WITH_PASS
  extern int32_t ck_core_keyboard_usage(uint8_t ch);
  assert(ck_core_keyboard_usage('A')==0x401d);
  assert(ck_core_keyboard_usage('B')==-1);
#endif
  ck_core_reset();
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x6982,0,0x46,0,0,1);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x9000,0,0x46,0,0,1);assert(buffer[0]==17);
  SEND(0x9000,0,0x47,0,0);
  SEND(0x6a88,0,0x46,0,0,1);
#ifdef WITH_PASS
  assert(ck_core_keyboard_usage('A')==0x0204);
#endif
  SEND(0x9000,0,0x14,1,1);
  SEND(0x9000,0,0x40,6,0x3f);
  SEND(0x9000,0,0x40,4,1);
  SEND(0x9000,0,0x40,1,1);
  SEND(0x9000,0,0x40,5,1);
#endif
#ifdef WITH_CTAP
  /* Card resets may precede FIDO without an explicit AID SELECT. */
  for (uint8_t owner=1;owner<=4;owner++) {
    if (owner==2) continue; /* HID owns its separate MSG framing entrypoint. */
    ck_core_reset();transport_owner=owner;
    SEND(0x9000,0,3,0,0,6);assert(!memcmp(buffer,"U2F_V2",6));
  }
  transport_owner=1;
  ck_core_reset();
  SEND(0x6a82,0,0x11,0,0); /* Unknown commands cannot select FIDO. */
  SEND(0x6a86,0,0xa4,4,1,1,0); /* ISO SELECT validation keeps precedence. */
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x6e00,0x80,0x10,0,0,1,4); /* Selected ADMIN is not preempted by FIDO. */
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x9000,0,0x40,6,0x1f); /* Disable WebAuthn only. */
  ck_core_reset();
  SEND(0x6a82,0,3,0,0,6);
  SEND(0x9000,0,0xa4,4,0,5,0xf0,0,0,0,0);
  SEND(0x9000,0,0x20,0,0,6,'1','2','3','4','5','6');
  SEND(0x9000,0,0x40,6,0x3f);
  /* NFC extended GetInfo also routes implicitly after reset. */
  ck_core_reset();transport_owner=4;
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
#ifdef WITH_OPENPGP
  aliased_response_regressions();
#endif
#ifdef WITH_PIV
  ordinary_response_cleanup_regressions();
#endif
  return 0;
}
