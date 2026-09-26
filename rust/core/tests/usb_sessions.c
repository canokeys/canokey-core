/* SPDX-License-Identifier: Apache-2.0 */
/* Real USB, CCID, HID, WebUSB and applets share the production Core. Only
 * controller/FIFO, clock, PKE memory and native storage/crypto are host services. */
#include "core.h"
#include "usb_io.h"
#include "ccid_io.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint32_t masked = 1, now;
static uint8_t address, ready, opened[8], halted[8], pending[4], packets[4][64];
static uint16_t lengths[4], interval;
static unsigned submissions[4];
static void (*timer)(void);
static uint8_t fail_send;
static uint8_t scratch[3072], scratch_owner;
static unsigned leases, clears;
extern void CCID_Loop(void);
extern void WebUSB_Loop(void);
extern uint8_t ck_transport_progress(void);
extern uint8_t ck_ccid_idle(void);
uint32_t ck_platform_now(void) { return now; }
uint8_t ck_platform_touched(void) { return 0; }
void ck_platform_led(uint8_t on) { (void)on; }
uint8_t ck_platform_progress(void) { ++now; return ck_transport_progress(); }
void device_delay(int ms) { assert(ms >= 0); now += (uint32_t)ms; }
static unsigned ix(uint8_t ep) { return (ep&3)*2+(ep>>7); }
uint32_t __get_PRIMASK(void) { return masked; }
void __disable_irq(void) { masked=1; }
void __enable_irq(void) { masked=0; }
uint32_t ck_usb_dcd_lock(void) { uint32_t m=masked;masked=1;return m; }
void ck_usb_dcd_unlock(uint32_t m) { masked=m; }
uint32_t device_get_tick(void) { return now; }
void device_set_timeout(void(*cb)(void),uint16_t ms) { timer=cb;interval=ms; }
void ck_usb_dcd_start(void) { assert(masked); }
void ck_usb_dcd_stop(void) { assert(masked); }
void ck_usb_dcd_open(uint8_t ep) { assert(masked);opened[ix(ep)]=1;halted[ix(ep)]=0; }
void ck_usb_dcd_close(uint8_t ep) { assert(masked);opened[ix(ep)]=0;if(ep&0x80) pending[ep&3]=0; }
void ck_usb_dcd_stall(uint8_t ep,uint8_t halt) { assert(masked);halted[ix(ep)]=halt; }
void ck_usb_dcd_address(uint8_t value) { assert(masked);address=value; }
void ck_usb_dcd_ready(uint8_t value) { assert(masked);ready=value; }
void ck_usb_dcd_receive(uint8_t ep) { assert(masked && opened[ix(ep)]); }
uint8_t ck_usb_dcd_write(uint8_t ep,const uint8_t *p,uint16_t n) {
  assert(masked && opened[ix(ep)] && (ep&0x80) && !pending[ep&3]);
  assert(n<=((ep&3)?64:16));
  if(fail_send) { fail_send=0;return 0; }
  if(n)memcpy(packets[ep&3],p,n);
  lengths[ep&3]=n;pending[ep&3]=1;submissions[ep&3]++;return 1;
}
static void complete(uint8_t ep) { assert(pending[ep&3]);pending[ep&3]=0;ck_usb_in(ep); }
static void setup(uint8_t type,uint8_t req,uint16_t value,uint16_t index,uint16_t len) {
  uint8_t b[]={type,req,(uint8_t)value,(uint8_t)(value>>8),(uint8_t)index,(uint8_t)(index>>8),(uint8_t)len,(uint8_t)(len>>8)};
  ck_usb_setup(b,8);
}
static void status(void) { assert(pending[0] && lengths[0]==0);complete(0x80); }
static size_t read_control(uint8_t *output) {
  size_t n=0;
  while(pending[0]) { assert(n+lengths[0]<=256);memcpy(output+n,packets[0],lengths[0]);n+=lengths[0];complete(0x80); }
  assert(ck_usb_out(0,NULL,0)==1);return n;
}
static void configure(void) {
  usb_device_init(); assert(masked && !address && !ready);
  setup(0,5,17,0,0);assert(address==0);status();assert(address==17);
  setup(0,9,1,0,0);assert(ready && ck_usb_configured());status();
}
size_t pke_buffer_size(void) { return sizeof(scratch); }
int pke_buffer_acquire(uint8_t owner) {
  if (!owner || scratch_owner) return -1;
  scratch_owner = owner;
  leases++;
  return 0;
}
int pke_buffer_release(uint8_t owner) {
  if (!owner || owner != scratch_owner) return -1;
  for (size_t i = 0; i < sizeof(scratch); ++i) assert(scratch[i] == 0);
  scratch_owner = 0;
  return 0;
}
int pke_buffer_clear(void) {
  assert(scratch_owner);
  memset(scratch, 0, sizeof(scratch));
  clears++;
  return 0;
}
int pke_buffer_read(size_t offset, uint8_t *out, size_t n) {
  if (!scratch_owner || offset > sizeof(scratch) || n > sizeof(scratch) - offset) return -1;
  memcpy(out, scratch + offset, n);
  return 0;
}
int pke_buffer_write(size_t offset, const uint8_t *in, size_t n) {
  if (!scratch_owner || offset > sizeof(scratch) || n > sizeof(scratch) - offset) return -1;
  memcpy(scratch + offset, in, n);
  return 0;
}


static const uint8_t select_admin[] = {0,0xa4,4,0,5,0xf0,0,0,0,0};
static const uint8_t verify[] = {0,0x20,0,0,6,'1','2','3','4','5','6'};
static const uint8_t query[] = {0,0x20,0,0};
static const uint8_t partial_config[] = {0,0x43,0,0,1};
static uint8_t sequence;
static void loops(void) { CCID_Loop(); CTAPHID_Loop(0); WebUSB_Loop(); }
static void sw(const uint8_t *b, size_t n, uint16_t expected) {
  assert(n >= 2);
  if (((uint16_t)b[n-2] << 8 | b[n-1]) != expected) {
    fprintf(stderr, "status %02x%02x, expected %04x\n", b[n-2], b[n-1], expected);
    assert(0);
  }
}
static void ccid_send(uint8_t command, const uint8_t *apdu, size_t n) {
  uint8_t packet[64] = {0};
  assert(n <= 54);
  packet[0] = command; packet[1] = (uint8_t)n; packet[6] = ++sequence;
  if(n) memcpy(packet+10, apdu, n);
  assert(ck_usb_out(3, packet, (uint16_t)(n+10)) == 0);
  CCID_Loop();
}
static size_t ccid_read(uint8_t *out) {
  size_t n=0;
  for(unsigned i=0; i<20; ++i) {
    CCID_Loop();
    if(!pending[3]) break;
    assert(n+lengths[3] <= 268);
    memcpy(out+n, packets[3], lengths[3]); n+=lengths[3]; complete(0x83);
  }
  CCID_Loop();
  assert(n >= 10 && out[6] == sequence && out[7] == 0 && out[8] == 0);
  assert(n == 10u + out[1] + ((unsigned)out[2]<<8));
  return n;
}
static void ccid_apdu(const uint8_t *apdu, size_t n, uint16_t expected) {
  uint8_t out[268]; ccid_send(0x6f, apdu, n);
  size_t count=ccid_read(out); sw(out+10,count-10,expected);
}
static void web_send(const uint8_t *apdu, size_t n) {
  assert(n<=16);
  setup(0x41,0,0,1,(uint16_t)n);
  assert(ck_usb_out(0,apdu,(uint16_t)n)==0);
  WebUSB_Loop();
  if(pending[0]) status();
}
static void web_apdu(const uint8_t *apdu, size_t n, uint16_t expected) {
  uint8_t out[256]; web_send(apdu,n);
  assert(!halted[1]);
  setup(0xc1,1,0,1,256); size_t count=read_control(out); sw(out,count,expected);
}
static void hid_send(uint32_t cid, uint8_t command, const uint8_t *body, size_t n) {
  uint8_t report[64] = {0}; assert(n<=57);
  report[0]=(uint8_t)(cid>>24); report[1]=(uint8_t)(cid>>16);
  report[2]=(uint8_t)(cid>>8); report[3]=(uint8_t)cid;
  report[4]=command; report[6]=(uint8_t)n;
  if(n)memcpy(report+7,body,n);
  assert(ck_usb_out(2,report,64)==0); CTAPHID_Loop(0);
}
static size_t hid_read(uint32_t cid, uint8_t command, uint8_t *out) {
  size_t copied=0, total=0; uint8_t seq=0;
  for(unsigned i=0; i<30; ++i) {
    CTAPHID_Loop(0);
    if(!pending[2]) { assert(!ck_hid_active()); break; }
    const uint8_t *r=packets[2]; assert(lengths[2]==64);
    assert(((uint32_t)r[0]<<24 | (uint32_t)r[1]<<16 | (uint32_t)r[2]<<8 | r[3])==cid);
    size_t offset;
    if(!copied) { assert(r[4]==command); total=(size_t)r[5]<<8 | r[6]; offset=7; }
    else { assert(r[4]==seq++); offset=5; }
    assert(total>0 && total<=1100);
    size_t n=total-copied; if(n>64-offset)n=64-offset;
    memcpy(out+copied,r+offset,n); copied+=n; complete(0x82);
  }
  assert(copied==total && !ck_hid_active()); return copied;
}
int main(void) {
  assert(ck_core_install()==0); configure(); loops();
  uint8_t out[268]; ccid_send(0x62,NULL,0); (void)ccid_read(out);
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(verify,sizeof(verify),0x9000);
  now+=2000; loops();
  ccid_apdu(query,sizeof(query),0x9000); /* Idle does not revoke same-owner grant. */
  ccid_apdu(partial_config,sizeof(partial_config),0x6101);
  now+=1999;
  web_send(select_admin,sizeof(select_admin)); assert(halted[1]);
  ccid_apdu(query,sizeof(query),0x9000); /* Refused takeover cannot revoke it. */
  now+=2000;
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(query,sizeof(query),0x63c3); /* Foreign takeover revokes CCID grant. */
  web_apdu(verify,sizeof(verify),0x9000);
  web_apdu(query,sizeof(query),0x9000);
  now+=2000; loops();
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  ccid_apdu(verify,sizeof(verify),0x9000);
  /* INIT allocates a channel independently; PING must obey the CCID lease. */
  uint8_t hid[1100], nonce[8]={1,2,3,4,5,6,7,8};
  hid_send(UINT32_MAX,0x86,nonce,8);
  assert(hid_read(UINT32_MAX,0x86,hid)==17 && !memcmp(hid,nonce,8));
  uint32_t cid=(uint32_t)hid[8]<<24 | (uint32_t)hid[9]<<16 | (uint32_t)hid[10]<<8 | hid[11];
  assert(cid && cid!=UINT32_MAX);
  ccid_apdu(partial_config,sizeof(partial_config),0x6101);
  now+=1999;
  hid_send(cid,0x81,nonce,8);
  assert(hid_read(cid,0xbf,hid)==1 && hid[0]==6);
  ccid_apdu(query,sizeof(query),0x9000);
  now+=2000;
  hid_send(cid,0x81,nonce,8);
  assert(hid_read(cid,0x81,hid)==8 && !memcmp(hid,nonce,8));
  /* A pending HID response is immutable while competing requests arrive. */
  const uint8_t get_info[]={4}; hid_send(cid,0x90,get_info,1);
  assert(pending[2]); uint8_t saved[64]; memcpy(saved,packets[2],64);
  web_send(select_admin,sizeof(select_admin)); assert(halted[1]);
  ccid_send(0x6f,select_admin,sizeof(select_admin));
  assert(!pending[3] && !memcmp(saved,packets[2],64));
  assert(hid_read(cid,0x90,hid)>256 && hid[0]==0);
  now+=1999; CCID_Loop(); assert(!pending[3]);
  now+=1; size_t count=ccid_read(out); sw(out+10,count-10,0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  ccid_apdu(verify,sizeof(verify),0x9000);
  /* Bus reset revokes authentication even when the same interface returns. */
  usb_device_deinit(); configure(); loops();
  ccid_send(0x62,NULL,0); (void)ccid_read(out);
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  now=UINT32_MAX-1000;
  ccid_apdu(verify,sizeof(verify),0x9000);
  ccid_apdu(partial_config,sizeof(partial_config),0x6101);
  now+=1999; web_send(select_admin,sizeof(select_admin)); assert(halted[1]);
  now+=1; web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(query,sizeof(query),0x63c3);
  now+=2000; loops();
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(verify,sizeof(verify),0x9000);
  ccid_send(0x6f,query,sizeof(query)); assert(pending[3]);
  uint8_t ccid_saved[64]; memcpy(ccid_saved,packets[3],lengths[3]);
  uint16_t ccid_length=lengths[3];
  web_send(select_admin,sizeof(select_admin)); assert(halted[1]);
  assert(pending[3] && lengths[3]==ccid_length && !memcmp(ccid_saved,packets[3],ccid_length));
  count=ccid_read(out); sw(out+10,count-10,0x9000);
  // A fully consumed CCID response has no continuation lease to protect.
  // Both competitors can take it immediately, without revoking a same-owner
  // grant merely because the main loop polled the admission predicate.
  loops(); ccid_apdu(query,sizeof(query),0x9000);
  uint32_t before=now;
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(query,sizeof(query),0x63c3);
  assert(now==before);
  now+=2000; loops();
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(verify,sizeof(verify),0x9000);
  before=now;
  hid_send(cid,0x81,nonce,8);
  assert(hid_read(cid,0x81,hid)==8 && !memcmp(hid,nonce,8));
  assert(now==before);
  now+=2000;
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  assert(!scratch_owner && leases==clears);
  puts("USB shared session correctness passed");
  return 0;
}
