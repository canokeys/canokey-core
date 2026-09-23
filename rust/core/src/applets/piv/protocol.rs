// SPDX-License-Identifier: Apache-2.0
//! PIV foundation adapter. This slice owns PIN state and small standard objects;
//! key slots and GENERAL AUTHENTICATE are added only after streaming storage is wired.
use crate::{Platform, ports::{Record, StorageError}};
use crate::runtime::workspace::Workspace;
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

pub const AID: &[u8] = &[0xa0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00];
pub const CAPACITY: usize = 513;
const STATE_LEN: usize = 24;
const RETRIES: u8 = 3;
const PIN: &[u8; 8] = b"123456\xff\xff";
const PUK: &[u8; 8] = b"12345678";
const SELECT_RESPONSE: &[u8] = &[0x61,0x11,0x4f,0x06,0x00,0x00,0x10,0x00,0x01,0x00,0x79,0x09,0x4f,0x05,0xa0,0x00,0x00,0x03,0x08];

#[derive(Clone, Copy)]
struct State { pin_tries: u8, puk_tries: u8, pin_ok: bool, puk_ok: bool, pin: [u8;8], puk: [u8;8] }
impl State {
    const fn fresh() -> Self { Self { pin_tries: RETRIES, puk_tries: RETRIES, pin_ok: false, puk_ok: false, pin:*PIN, puk:*PUK } }
    fn encode(self, out: &mut [u8; STATE_LEN]) { out.fill(0); out[0]=1; out[1]=self.pin_tries; out[2]=self.puk_tries; out[3]=u8::from(self.pin_ok); out[4]=u8::from(self.puk_ok); out[8..16].copy_from_slice(&self.pin); out[16..24].copy_from_slice(&self.puk); }
    fn decode(input: &[u8; STATE_LEN]) -> Option<Self> { if input[0]!=1 || input[1]>RETRIES || input[2]>RETRIES || input[3]>1 || input[4]>1 { return None } Some(Self { pin_tries:input[1], puk_tries:input[2], pin_ok:input[3]!=0, puk_ok:input[4]!=0, pin:input[8..16].try_into().ok()?, puk:input[16..24].try_into().ok()? }) }
}

enum Request { None, Buffered }
pub struct Piv { state: State, command: [u8; CAPACITY], used: usize, response: [u8; CAPACITY], response_len: usize, request: Request }
impl Piv { pub const fn new() -> Self { Self { state:State::fresh(), command:[0;CAPACITY], used:0, response:[0;CAPACITY], response_len:0, request:Request::None } }
    pub fn install(&mut self,p:&mut Platform<'_>)->Result<(),Sw>{ let mut b=[0;STATE_LEN]; match p.storage.load(Record::PivState,&mut b){ Ok(n) if n==STATE_LEN => self.state=State::decode(&b).ok_or(Sw::UNABLE_TO_PROCESS)?, Err(StorageError::Missing)=>{ self.state=State::fresh(); self.save(p)? }, Err(_)=>return Err(Sw::UNABLE_TO_PROCESS), _=>return Err(Sw::UNABLE_TO_PROCESS) } p.memory.wipe(&mut b); Ok(()) }
    fn save(&self,p:&mut Platform<'_>)->Result<(),Sw>{ let mut b=[0;STATE_LEN]; self.state.encode(&mut b); let r=p.storage.replace(Record::PivState,&b).map_err(|_|Sw::UNABLE_TO_PROCESS); p.memory.wipe(&mut b); r }
    pub fn reset(&mut self,p:&mut Platform<'_>){ self.state.pin_ok=false; self.state.puk_ok=false; self.cancel(p); }
    pub fn select(&mut self,_p:&mut Platform<'_>)->Result<u32,Sw>{ self.response[..SELECT_RESPONSE.len()].copy_from_slice(SELECT_RESPONSE); self.response_len=SELECT_RESPONSE.len(); Ok(SELECT_RESPONSE.len() as u32) }
    pub fn limit(h:Header)->u32 { if h.ins==0x84 { 256 } else { CAPACITY as u32 } }
    pub fn cancel(&mut self,p:&mut Platform<'_>){ p.memory.wipe(&mut self.command); p.memory.wipe(&mut self.response); self.used=0; self.response_len=0; self.request=Request::None; }
    pub fn begin(&mut self,_h:Header,_p:&mut Platform<'_>)->Result<(),Sw>{ self.used=0; self.response_len=0; self.request=Request::Buffered; Ok(()) }
    pub fn consume(&mut self,b:&[u8],_p:&mut Platform<'_>)->Result<(),Sw>{ let e=self.used.checked_add(b.len()).filter(|n|*n<=CAPACITY).ok_or(Sw::WRONG_LENGTH)?; self.command[self.used..e].copy_from_slice(b); self.used=e; Ok(()) }
    pub fn finish(&mut self,h:Header,le:u32,_w:&mut Workspace,p:&mut Platform<'_>)->Result<(u32,Sw),Sw>{ let r=self.command(h,le,p); self.request=Request::None; self.used=0; r.map(|n|(n,Sw::SUCCESS)) }
    fn command(&mut self,h:Header,le:u32,p:&mut Platform<'_>)->Result<u32,Sw>{ self.response_len=0; match h.ins {
      0x20=>self.verify(h,p), 0x24=>self.change(h,p), 0x2c=>self.reset_retry(h,p),
      0xfd=>{ if h.p1!=0||h.p2!=0||self.used!=0{return Err(Sw::WRONG_P1P2)}; self.response[..3].copy_from_slice(&[6,0,0]); self.response_len=3; Ok(3) },
      0xf8=>{ if h.p1!=0||h.p2!=0||self.used!=0{return Err(Sw::WRONG_P1P2)}; p.device.serial((&mut self.response[..4]).try_into().unwrap()); self.response_len=4; Ok(4) },
      0x84=>{ if h.p1!=0||h.p2!=0||self.used!=0||le==0||le>256{return Err(Sw::WRONG_LENGTH)}; p.crypto.random(&mut self.response[..le as usize]).map_err(|_|Sw::UNABLE_TO_PROCESS)?; self.response_len=le as usize; Ok(le) },
      0xcb=>self.get_data(h,p),
      _=>Err(Sw::INS_NOT_SUPPORTED)
    }}
    fn verify(&mut self,h:Header,p:&mut Platform<'_>)->Result<u32,Sw>{ if h.p2!=0x80 || !matches!(h.p1,0|0xff){return Err(Sw::WRONG_P1P2)}; if h.p1==0xff {self.state.pin_ok=false; self.save(p)?; return Ok(0)}; if self.used!=8{return Err(Sw::WRONG_LENGTH)}; if self.state.pin_tries==0{return Err(Sw::AUTHENTICATION_BLOCKED)}; let good=self.command[..8].iter().zip(&self.state.pin).fold(0u8,|v,(a,b)|v|(a^b))==0; if !good {self.state.pin_tries-=1; self.save(p)?; return Err(if self.state.pin_tries==0{Sw::AUTHENTICATION_BLOCKED}else{Sw(0x63c0|self.state.pin_tries as u16)})} self.state.pin_ok=true; self.save(p)?; Ok(0) }
    fn change(&mut self,h:Header,p:&mut Platform<'_>)->Result<u32,Sw>{ if h.p2!=0x80||h.p1!=0||self.used!=16{return Err(Sw::WRONG_LENGTH)}; if !self.state.pin_ok{return Err(Sw::SECURITY_STATUS_NOT_SATISFIED)}; if self.command[..8]!=self.state.pin[..] {return Err(Sw::WRONG_DATA)}; self.state.pin.copy_from_slice(&self.command[8..16]); self.save(p)?; Ok(0) }
    fn reset_retry(&mut self,h:Header,p:&mut Platform<'_>)->Result<u32,Sw>{ if h.p2!=0x80||h.p1!=0||self.used!=8{return Err(Sw::WRONG_LENGTH)}; if self.state.puk_tries==0{return Err(Sw::AUTHENTICATION_BLOCKED)}; let good=self.command[..8].iter().zip(&self.state.puk).fold(0u8,|v,(a,b)|v|(a^b))==0; if !good {self.state.puk_tries-=1; self.save(p)?; return Err(if self.state.puk_tries==0{Sw::AUTHENTICATION_BLOCKED}else{Sw(0x63c0|self.state.puk_tries as u16)})} self.state.pin_tries=RETRIES; self.state.pin_ok=false; self.save(p)?; Ok(0) }
    fn get_data(&mut self,h:Header,p:&mut Platform<'_>)->Result<u32,Sw>{ if h.p1!=0x3f||h.p2!=0xff||self.used<3||self.command[0]!=0x5c{return Err(Sw::WRONG_DATA)}; let tag=if self.command[1]==1 {self.command[2] as u32}else if self.command[1]==2 {u16::from_be_bytes([self.command[2],self.command[3]]) as u32}else{return Err(Sw::WRONG_DATA)}; if tag==0x7e { let d=&[0x7e,0x12,0x4f,0x0b,0xa0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00,0x5f,0x2f,0x02,0x40,0x10]; self.response[..d.len()].copy_from_slice(d); self.response_len=d.len(); return Ok(d.len() as u32)} else if tag==0x7f61 && self.state.pin_ok { self.response[..2].copy_from_slice(&[0x7f,0x61]); self.response_len=2; return Ok(2)} let _=p; Err(Sw::FILE_NOT_FOUND) }
    pub fn read(&self,offset:usize,out:&mut[u8])->Result<usize,Sw>{ out.copy_from_slice(self.response.get(offset..offset+out.len()).ok_or(Sw::UNABLE_TO_PROCESS)?); Ok(out.len()) }
    pub fn close(&mut self,p:&mut Platform<'_>){p.memory.wipe(&mut self.response);self.response_len=0}
}
impl Default for Piv { fn default()->Self{Self::new()} }
