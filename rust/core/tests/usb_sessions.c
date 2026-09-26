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
static uint8_t presence_stage;
static uint32_t presence_cid;
static void presence_progress(void);
uint8_t ck_platform_progress(void) {
  ++now;
  if(presence_stage) presence_progress();
  return ck_transport_progress();
}
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
/* Inject host traffic while the real selection command borrows Core. */
static void presence_progress(void) {
  assert(ck_hid_executing());
  if(pending[2]) complete(0x82); // Host consumes keepalive reports.
  uint8_t poll[]={0x65,0,0,0,0,0,0x37,0,0,0};
  if(presence_stage==1) {
    assert(ck_usb_out(3,poll,sizeof(poll))==0);
    presence_stage=2;
  } else if(presence_stage==2) {
    const uint8_t expected[]={0x81,0,0,0,0,0,0x37,0,0,0};
    assert(pending[3] && lengths[3]==10 && !memcmp(packets[3],expected,10));
    poll[6]=0x38; assert(ck_usb_out(3,poll,sizeof(poll))==0);
    presence_stage=3;
  } else if(presence_stage==3) {
    assert(pending[3] && packets[3][6]==0x37); // IN still owns the first reply.
    complete(0x83);
    presence_stage=4;
  } else if(presence_stage==4) {
    const uint8_t expected[]={0x81,0,0,0,0,0,0x38,0,0,0};
    assert(pending[3] && lengths[3]==10 && !memcmp(packets[3],expected,10));
    complete(0x83);
    poll[0]=0x62; poll[6]=0x39;
    assert(ck_usb_out(3,poll,sizeof(poll))==0);
    presence_stage=5;
  } else {
    assert(!pending[3]); // Power-on must not reset the borrowed Core.
    uint8_t cancel[64]={0};
    cancel[0]=(uint8_t)(presence_cid>>24); cancel[1]=(uint8_t)(presence_cid>>16);
    cancel[2]=(uint8_t)(presence_cid>>8); cancel[3]=(uint8_t)presence_cid;
    cancel[4]=0x91;
    assert(ck_usb_out(2,cancel,64)==0);
    presence_stage=0;
  }
}
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
  uint8_t request[1043] = {0};
  assert(n <= sizeof(request)-10);
  request[0] = command; request[1] = (uint8_t)n;
  request[2] = (uint8_t)(n>>8); request[6] = ++sequence;
  if(n) memcpy(request+10, apdu, n);
  for(size_t at=0;at<n+10;) {
    size_t part=n+10-at; if(part>64)part=64;
    assert(ck_usb_out(3,request+at,(uint16_t)part)==0);
    CCID_Loop(); at+=part;
  }
}
static size_t ccid_read_state(uint8_t *out, uint8_t state) {
  size_t n=0;
  for(unsigned i=0; i<20; ++i) {
    CCID_Loop();
    if(!pending[3]) break;
    assert(n+lengths[3] <= 268);
    memcpy(out+n, packets[3], lengths[3]); n+=lengths[3]; complete(0x83);
  }
  CCID_Loop();
  assert(n >= 10 && out[6] == sequence && out[7] == state && out[8] == 0);
  assert(n == 10u + out[1] + ((unsigned)out[2]<<8));
  return n;
}
static size_t ccid_read(uint8_t *out) { return ccid_read_state(out,0); }
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
  uint8_t report[64] = {0}; assert(n<=1024);
  report[0]=(uint8_t)(cid>>24); report[1]=(uint8_t)(cid>>16);
  report[2]=(uint8_t)(cid>>8); report[3]=(uint8_t)cid;
  report[4]=command; report[5]=(uint8_t)(n>>8); report[6]=(uint8_t)n;
  size_t used=n<57?n:57;
  if(used)memcpy(report+7,body,used);
  assert(ck_usb_out(2,report,64)==0); CTAPHID_Loop(0);
  for(uint8_t seq=0;used<n;++seq) {
    memset(report+4,0,60); report[4]=seq;
    size_t part=n-used; if(part>59)part=59;
    memcpy(report+5,body+used,part); used+=part;
    assert(ck_usb_out(2,report,64)==0); CTAPHID_Loop(0);
  }
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
  /* Reentrant OUT packets cannot replace a queued request or pending response.
   * The Rust mailbox defers one packet until IN completion. */
  uint8_t first_query[]={0x6f,4,0,0,0,0,++sequence,0,0,0,0,0x20,0,0};
  uint8_t next_query[]={0x6f,4,0,0,0,0,(uint8_t)(sequence+1),0,0,0,0,0xfe,0,0};
  assert(ck_usb_out(3,first_query,sizeof(first_query))==0);
  assert(ck_usb_out(3,next_query,sizeof(next_query))==0);
  CCID_Loop(); assert(pending[3]);
  assert(lengths[3]==12 && packets[3][6]==sequence);
  sw(packets[3]+10,2,0x9000);
  uint8_t ccid_saved[64]; memcpy(ccid_saved,packets[3],lengths[3]);
  uint16_t ccid_length=lengths[3];
  web_send(select_admin,sizeof(select_admin)); assert(halted[1]);
  assert(ck_usb_out(3,next_query,sizeof(next_query))==0);
  assert(ck_usb_out(3,first_query,sizeof(first_query))==0);
  CCID_Loop();
  assert(pending[3] && lengths[3]==ccid_length && !memcmp(ccid_saved,packets[3],ccid_length));
  complete(0x83); ++sequence;
  count=ccid_read(out); sw(out+10,count-10,0x6d00);
  assert(!pending[3]);
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
  // A completed WebUSB response likewise permits immediate foreign takeover.
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(verify,sizeof(verify),0x9000);
  before=now; loops(); web_apdu(query,sizeof(query),0x9000);
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  ccid_apdu(verify,sizeof(verify),0x9000);
  assert(now==before);
  now+=2000; WebUSB_Loop();
  ccid_apdu(query,sizeof(query),0x9000); // No stale WebUSB timeout cleanup.
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(verify,sizeof(verify),0x9000);
  before=now;
  hid_send(cid,0x81,nonce,8);
  assert(hid_read(cid,0x81,hid)==8 && !memcmp(hid,nonce,8));
  assert(now==before);
  now+=2000; loops();
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(verify,sizeof(verify),0x9000);
  web_apdu(partial_config,sizeof(partial_config),0x6101);
  ccid_send(0x6f,select_admin,sizeof(select_admin)); assert(!pending[3]);
  now+=1999; CCID_Loop(); assert(!pending[3]);
  const uint8_t get_response[]={0,0xc0,0,0,1};
  web_apdu(get_response,sizeof(get_response),0x9000);
  count=ccid_read(out); sw(out+10,count-10,0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  // A foreign packet cannot preempt a response still owned by EP0.
  web_send(verify,sizeof(verify));
  setup(0xc1,1,0,1,256); assert(pending[0]);
  uint8_t ep0_saved[16]; uint16_t ep0_length=lengths[0];
  memcpy(ep0_saved,packets[0],ep0_length);
  ccid_send(0x6f,select_admin,sizeof(select_admin)); assert(!pending[3]);
  assert(pending[0] && lengths[0]==ep0_length && !memcmp(ep0_saved,packets[0],ep0_length));
  sw(out,read_control(out),0x9000);
  count=ccid_read(out); sw(out+10,count-10,0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  // Discovery and cancellation are not requests to acquire an APDU session.
  const uint8_t control_commands[]={0x86,0x91};
  for(size_t i=0;i<sizeof(control_commands);++i) {
    web_apdu(select_admin,sizeof(select_admin),0x9000);
    web_apdu(verify,sizeof(verify),0x9000);
    uint8_t cmd=control_commands[i];
    hid_send(cmd==0x86?UINT32_MAX:cid,cmd,nonce,cmd==0x86?8:0);
    assert(!pending[2]);
    web_apdu(query,sizeof(query),0x9000);
    now+=2000; WebUSB_Loop(); CTAPHID_Loop(0);
    if(cmd==0x86)assert(hid_read(UINT32_MAX,0x86,hid)==17);
    else assert(!pending[2]);
  }
  const uint8_t select_fido[]={0,0xa4,4,0,8,0xa0,0,0,6,0x47,0x2f,0,1};
  const uint8_t info_short[]={0x80,0x10,0,0,1,4,1};
  const uint8_t stale_response[]={0,0xc0,0,0,1};
  ccid_apdu(select_fido,sizeof(select_fido),0x9000);
  ccid_apdu(info_short,sizeof(info_short),0x61ff);
  before=now; web_apdu(stale_response,sizeof(stale_response),0x6986);
  assert(now==before); // Large CTAP source can be abandoned without waiting.
  ccid_apdu(select_fido,sizeof(select_fido),0x9000);
  ccid_apdu(stale_response,sizeof(stale_response),0x6986);
#ifdef WITH_OPENPGP
  const uint8_t select_pgp[]={0,0xa4,4,0,6,0xd2,0x76,0,1,0x24,1};
  const uint8_t verify_pgp[]={0,0x20,0,0x83,8,'1','2','3','4','5','6','7','8'};
  const uint8_t put_cert[]={0,0xda,0x7f,0x21,3,'a','b','c'};
  const uint8_t read_cert[]={0,0xca,0x7f,0x21,1};
  ccid_apdu(select_pgp,sizeof(select_pgp),0x9000);
  ccid_apdu(verify_pgp,sizeof(verify_pgp),0x9000);
  ccid_apdu(put_cert,sizeof(put_cert),0x9000);
  ccid_apdu(read_cert,sizeof(read_cert),0x6102);
  before=now; web_apdu(stale_response,sizeof(stale_response),0x6986);
  assert(now==before); // Even a short certificate is an explicit file source.
  ccid_apdu(select_pgp,sizeof(select_pgp),0x9000);
  ccid_apdu(stale_response,sizeof(stale_response),0x6986);
  const uint8_t pgp_query[]={0,0x20,0,0x83};
  ccid_apdu(pgp_query,sizeof(pgp_query),0x63c3);
  const uint8_t verify_pw1[]={0,0x20,0,0x81,6,'1','2','3','4','5','6'};
  const uint8_t query_pw1[]={0,0x20,0,0x81};
  ccid_apdu(verify_pw1,sizeof(verify_pw1),0x9000);
  now+=2001; loops();
  ccid_apdu(select_pgp,sizeof(select_pgp),0x9000);
  ccid_apdu(query_pw1,sizeof(query_pw1),0x9000);
  now+=2001;
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(select_pgp,sizeof(select_pgp),0x9000);
  ccid_apdu(query_pw1,sizeof(query_pw1),0x63c3);
#endif
#ifdef WITH_PIV
  // Provision only an opaque test object; protocol selection/read are real.
  extern int32_t ck_platform_write(uint8_t,const uint8_t *,size_t);
  const uint8_t object[]={0x53,1,7};
  assert(ck_platform_write(42,object,sizeof(object))==3); // PivObject0, 5FC105.
  const uint8_t select_piv[]={0,0xa4,4,0,11,0xa0,0,0,3,8,0,0,0x10,0,1,0};
  const uint8_t piv_rid[]={0,0xa4,4,0,5,0xa0,0,0,3,8};
  const uint8_t verify_piv[]={0,0x20,0,0x80,8,'1','2','3','4','5','6',0xff,0xff};
  const uint8_t query_piv[]={0,0x20,0,0x80};
  ccid_apdu(select_piv,sizeof(select_piv),0x9000);
  ccid_apdu(verify_piv,sizeof(verify_piv),0x9000);
  ccid_apdu(select_piv,sizeof(select_piv),0x9000);
  ccid_apdu(query_piv,sizeof(query_piv),0x9000);
  ccid_apdu(piv_rid,sizeof(piv_rid),0x9000);
  ccid_apdu(query_piv,sizeof(query_piv),0x9000);
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(select_piv,sizeof(select_piv),0x9000);
  ccid_apdu(query_piv,sizeof(query_piv),0x63c3);
  const uint8_t read_object[]={0,0xcb,0x3f,0xff,5,0x5c,3,0x5f,0xc1,5,1};
  const uint8_t discovery[]={0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,1};
  const uint8_t rest[]={0,0xc0,0,0,0};
  ccid_apdu(select_piv,sizeof(select_piv),0x9000);
  ccid_apdu(discovery,sizeof(discovery),0x6113);
  web_send(select_admin,sizeof(select_admin)); assert(halted[1]);
  ccid_apdu(rest,sizeof(rest),0x9000); // Ordinary response survives refusal.
  ccid_apdu(read_object,sizeof(read_object),0x6102);
  before=now; web_apdu(stale_response,sizeof(stale_response),0x6986);
  assert(now==before);
  ccid_apdu(select_piv,sizeof(select_piv),0x9000);
  ccid_apdu(stale_response,sizeof(stale_response),0x6986);
#endif
  // Slot power commands can reset a completed WebUSB session immediately.
  for(uint8_t power=0x62;power<=0x63;++power) {
    web_apdu(select_admin,sizeof(select_admin),0x9000);
    web_apdu(verify,sizeof(verify),0x9000);
    before=now; ccid_send(power,NULL,0); count=ccid_read_state(out,power==0x63);
    assert(now==before && out[7]==(power==0x63));
    if(power==0x62)assert(count>10 && out[0]==0x80);
    else {
      assert(count==10 && out[0]==0x81);
      ccid_send(0x62,NULL,0); (void)ccid_read(out);
    }
    ccid_apdu(select_admin,sizeof(select_admin),0x9000);
    ccid_apdu(query,sizeof(query),0x63c3);
    ccid_apdu(verify,sizeof(verify),0x9000);
    now+=2000; WebUSB_Loop(); ccid_apdu(query,sizeof(query),0x9000);
  }
  web_apdu(select_admin,sizeof(select_admin),0x9000);
  web_apdu(verify,sizeof(verify),0x9000);
  web_apdu(partial_config,sizeof(partial_config),0x6101);
  ccid_send(0x62,NULL,0); assert(!pending[3]);
  now+=1999; CCID_Loop(); assert(!pending[3]);
  web_apdu(get_response,sizeof(get_response),0x9000);
  (void)ccid_read(out); assert(out[0]==0x80 && out[7]==0);
  ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  // A stream is abandonable only after the endpoint has finished its packet.
  ccid_apdu(select_fido,sizeof(select_fido),0x9000);
  ccid_send(0x6f,info_short,sizeof(info_short)); assert(pending[3]);
  ccid_length=lengths[3]; memcpy(ccid_saved,packets[3],ccid_length);
  hid_send(cid,0x81,nonce,8);
  assert(hid_read(cid,0xbf,hid)==1 && hid[0]==6);
  assert(pending[3] && lengths[3]==ccid_length && !memcmp(ccid_saved,packets[3],ccid_length));
  count=ccid_read(out); sw(out+10,count-10,0x61ff);
  before=now; hid_send(cid,0x81,nonce,8);
  assert(hid_read(cid,0x81,hid)==8 && !memcmp(hid,nonce,8));
  assert(now==before);
  now+=2000; ccid_apdu(stale_response,sizeof(stale_response),0x6986);
  // A fragmented HID request owns the shared session before staging RX.
  // CCID waits until resynchronization releases and wipes that lease.
  uint8_t fragmented[64] = {0};
  fragmented[0]=(uint8_t)(cid>>24); fragmented[1]=(uint8_t)(cid>>16);
  fragmented[2]=(uint8_t)(cid>>8); fragmented[3]=(uint8_t)cid;
  fragmented[4]=0x81; fragmented[6]=193;
  /* Slot commands queued during HID RX preserve its staged request and
   * survive resynchronization. No CCID dispatch may borrow active HID state. */
  const uint8_t slot_commands[]={0x63,0x62,0x65};
  for(size_t i=0;i<sizeof(slot_commands);++i) {
    assert(ck_usb_out(2,fragmented,64)==0); CTAPHID_Loop(0);
    assert(scratch_owner);
    uint8_t staged[sizeof(scratch)]; memcpy(staged,scratch,sizeof(staged));
    unsigned held_leases=leases, held_clears=clears;
    uint8_t command=slot_commands[i];
    ccid_send(command,NULL,0);
    assert(!pending[3] && scratch_owner && leases==held_leases && clears==held_clears);
    assert(!memcmp(staged,scratch,sizeof(staged)));
    hid_send(cid,0x86,nonce,8);
    assert(hid_read(cid,0x86,hid)==17 && !memcmp(hid,nonce,8));
    assert(!scratch_owner && leases==clears);
    count=ccid_read_state(out,command==0x63);
    assert(out[0]==(command==0x62?0x80:0x81));
    assert(command==0x62?count>10:count==10);
    now+=2000;
  }
  assert(ck_usb_out(2,fragmented,64)==0); CTAPHID_Loop(0);
  assert(scratch_owner);
  ccid_send(0x6f,select_admin,sizeof(select_admin));
  assert(!pending[3] && scratch_owner);
  hid_send(cid,0x86,nonce,8);
  assert(hid_read(cid,0x86,hid)==17 && !memcmp(hid,nonce,8));
  assert(!scratch_owner);
  now+=2000; // Preserve the existing idle ownership deadline.
  count=ccid_read(out); sw(out+10,count-10,0x9000);
  // Acquire the new HID session before staging bytes: prior CCID cleanup
  // must not wipe a large clientPIN request that will subsequently use crypto.
  const uint8_t pin_header[]={6,0xa3,1,1,2,2,0x18,0x7f,0x59,2,0xbc};
  uint8_t pin_request[sizeof(pin_header)+700];
  memcpy(pin_request,pin_header,sizeof(pin_header));
  memset(pin_request+sizeof(pin_header),0xa5,700);
  ccid_apdu(verify,sizeof(verify),0x9000);
  hid_send(cid,0x90,pin_request,sizeof(pin_request));
  count=hid_read(cid,0x90,hid);
  assert(count>64 && hid[0]==0);
  assert(!scratch_owner && leases==clears);
  now+=2000; ccid_apdu(select_admin,sizeof(select_admin),0x9000);
  ccid_apdu(query,sizeof(query),0x63c3);
  // Extended FIDO input is staged through CCID, consumed before key-agreement
  // crypto, then released even though the response endpoint is still pending.
  uint8_t extended[7+sizeof(pin_request)+2] = {0x80,0x10,0x80,0,0};
  extended[5]=(uint8_t)(sizeof(pin_request)>>8);
  extended[6]=(uint8_t)sizeof(pin_request);
  memcpy(extended+7,pin_request,sizeof(pin_request));
  ccid_apdu(select_fido,sizeof(select_fido),0x9000);
  ccid_send(0x6f,extended,sizeof(extended));
  assert(!scratch_owner && leases==clears);
  count=ccid_read(out); sw(out+10,count-10,0x9000);
  assert(count>76 && out[10]==0);
  uint8_t partial_ccid[64]={0x6f};
  partial_ccid[1]=(uint8_t)sizeof(extended);
  partial_ccid[2]=(uint8_t)(sizeof(extended)>>8);
  partial_ccid[6]=++sequence;
  memcpy(partial_ccid+10,extended,54);
  assert(ck_usb_out(3,partial_ccid,64)==0); CCID_Loop();
  assert(scratch_owner);
  setup(0,9,0,0,0); status(); loops();
  assert(!scratch_owner && leases==clears);
  setup(0,9,1,0,0); status(); loops();
  ccid_send(0x62,NULL,0); (void)ccid_read(out);
  ccid_apdu(select_fido,sizeof(select_fido),0x9000);
  ccid_send(0x6f,extended,sizeof(extended));
  count=ccid_read(out); sw(out+10,count-10,0x9000);
  assert(count>76 && out[10]==0);
  assert(!scratch_owner && leases==clears);
  now+=2000;
  presence_cid=cid; presence_stage=1;
  const uint8_t selection[]={0x0b};
  hid_send(cid,0x90,selection,sizeof(selection));
  assert(presence_stage==0);
  assert(hid_read(cid,0x90,hid)==1 && hid[0]==0x2d);
  sequence=0x39; count=ccid_read(out);
  assert(count>10 && out[0]==0x80);
  puts("USB shared session correctness passed");
  return 0;
}
