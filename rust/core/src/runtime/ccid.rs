// SPDX-License-Identifier: Apache-2.0
//! Main-loop CCID protocol. Endpoint/timer callbacks never borrow this state.
use canokey_protocol::ccid::*;

pub const FRAME: usize = 261;
pub const REPLY: usize = 258;
pub const TIMEOUT: u32 = 2000;
pub const EXTENSION_INTERVAL: u16 = 500;
const PREFIX: usize = HEADER + 7;

pub trait Scratch {
    fn acquire(&mut self, length: usize) -> bool;
    fn read(&mut self, offset: usize, out: &mut [u8]) -> bool;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> bool;
    /// Wipe and release, or halt. A failed wipe must never permit reuse.
    fn close(&mut self);
}

pub trait Backend: Scratch {
    fn now(&mut self) -> u32;
    fn reset(&mut self);
    fn prepare_extended(&mut self, prefix: &[u8; 7], total: usize) -> Result<u16, u16>;
    /// The backend must close staged input before executing the parsed command.
    fn exchange(&mut self, request: &mut Request, out: &mut [u8]) -> Result<usize, ()>;
    /// Copy these opaque bytes into a disjoint IRQ-owned periodic TX buffer.
    fn arm(&mut self, bytes: &[u8; HEADER], interval: u16);
    fn disarm(&mut self);
}

pub struct Request {
    bytes: [u8; HEADER + FRAME],
    received: u32,
    expected: u32,
    body: u16,
    status: u16,
    held: bool,
}
impl Request {
    const fn new() -> Self {
        Self {
            bytes: [0; HEADER + FRAME],
            received: 0,
            expected: HEADER as u32,
            body: 0,
            status: 0,
            held: false,
        }
    }
    pub fn len(&self) -> usize {
        self.expected as usize - HEADER
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn staged(&self) -> bool {
        self.held
    }
    pub fn short(&self) -> &[u8] {
        &self.bytes[HEADER..self.expected as usize]
    }
    pub fn close(&mut self, scratch: &mut impl Scratch) {
        if self.held {
            scratch.close();
            self.held = false;
        }
    }
    pub fn read(&self, mut offset: usize, mut out: &mut [u8], scratch: &mut impl Scratch) -> bool {
        if !self.held || offset > self.len() || out.len() > self.len() - offset {
            return false;
        }
        while !out.is_empty() {
            let n = if offset < 7 {
                let n = out.len().min(7 - offset);
                out[..n].copy_from_slice(&self.bytes[HEADER + offset..HEADER + offset + n]);
                n
            } else if offset < 7 + self.body as usize {
                let n = out.len().min(7 + self.body as usize - offset);
                if !scratch.read(offset - 7, &mut out[..n]) {
                    return false;
                }
                n
            } else {
                let n = out.len();
                let start = PREFIX + offset - 7 - self.body as usize;
                out.copy_from_slice(&self.bytes[start..start + n]);
                n
            };
            offset += n;
            out = &mut out[n..];
        }
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Receiving,
    Queued,
    Reply,
    InFlight,
}
pub struct Transport {
    request: Request,
    reply_len: usize,
    phase: Phase,
    error: u8,
    active: bool,
    last_received: u32,
    session_owned: bool,
    session_last: u32,
    tx_started: u32,
}
impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}
impl Transport {
    pub const fn new() -> Self {
        Self {
            request: Request::new(),
            reply_len: 0,
            phase: Phase::Idle,
            error: 0,
            active: false,
            last_received: 0,
            session_owned: false,
            session_last: 0,
            tx_started: 0,
        }
    }
    pub fn reset(&mut self, backend: &mut impl Backend) {
        backend.disarm();
        self.request.close(backend);
        backend.reset();
        self.request.bytes.fill(0);
        self.request.received = 0;
        self.request.expected = HEADER as u32;
        self.phase = Phase::Idle;
        self.active = false;
        self.session_owned = false;
    }
    pub fn scratch_busy(&self) -> bool {
        self.request.held
    }
    /// Logical completion is separate from the controller's final IN completion.
    pub fn completed_transaction(&self) -> bool {
        self.phase == Phase::Idle
    }
    pub fn idle(&self, now: u32) -> bool {
        self.phase == Phase::Idle
            && (!self.session_owned || now.wrapping_sub(self.session_last) >= TIMEOUT)
    }
    pub fn can_receive(&self) -> bool {
        matches!(self.phase, Phase::Idle | Phase::Receiving)
    }
    pub fn blocked_by_hid(&self, first_byte: Option<u8>) -> bool {
        let command = if self.phase == Phase::Idle {
            first_byte
        } else {
            Some(self.request.bytes[0])
        };
        command == Some(TRANSFER)
    }
    fn expire(&mut self, backend: &mut impl Backend) {
        self.error = BAD_LENGTH;
        self.request.close(backend);
        self.phase = if self.request.received < HEADER as u32 {
            Phase::Idle
        } else {
            Phase::Queued
        };
    }
    pub fn timeout(&mut self, now: u32, backend: &mut impl Backend) {
        if self.phase == Phase::Receiving && now.wrapping_sub(self.last_received) >= TIMEOUT {
            self.expire(backend);
        }
    }
    pub fn receive(
        &mut self,
        mut data: &[u8],
        tick: u32,
        extended: bool,
        backend: &mut impl Backend,
    ) {
        if !self.can_receive() || data.is_empty() {
            return;
        }
        if self.phase == Phase::Receiving && tick.wrapping_sub(self.last_received) >= TIMEOUT {
            self.expire(backend);
            return;
        }
        if self.phase == Phase::Idle {
            self.request.received = 0;
            self.request.expected = HEADER as u32;
            self.error = 0;
            self.request.status = 0;
            self.request.body = 0;
            self.phase = Phase::Receiving;
        }
        self.last_received = tick;
        while !data.is_empty() && self.request.received < self.request.expected {
            let r = &mut self.request;
            let at = r.received as usize;
            let mut n = data.len().min((r.expected - r.received) as usize);
            if at < HEADER {
                n = n.min(HEADER - at);
                r.bytes[at..at + n].copy_from_slice(&data[..n]);
            } else if self.error == 0 && r.expected as usize <= r.bytes.len() {
                r.bytes[at..at + n].copy_from_slice(&data[..n]);
            } else if self.error == 0 {
                if at < PREFIX {
                    n = n.min(PREFIX - at);
                    r.bytes[at..at + n].copy_from_slice(&data[..n]);
                } else if r.status == 0 {
                    if at < PREFIX + r.body as usize {
                        n = n.min(PREFIX + r.body as usize - at);
                        if !backend.write(at - PREFIX, &data[..n]) {
                            self.error = HARDWARE;
                        }
                    } else {
                        let start = PREFIX + at - PREFIX - r.body as usize;
                        r.bytes[start..start + n].copy_from_slice(&data[..n]);
                    }
                }
            }
            r.received += n as u32;
            data = &data[n..];
            if r.received == HEADER as u32 {
                let payload = payload_length(r.bytes[..HEADER].try_into().unwrap());
                r.expected = payload.saturating_add(HEADER as u32);
                let maximum = if extended { 1024 + 9 } else { FRAME as u32 };
                if payload > maximum || (payload > FRAME as u32 && r.bytes[0] != TRANSFER) {
                    self.error = BAD_LENGTH;
                }
            }
            if r.received == PREFIX as u32 && r.expected as usize > r.bytes.len() && self.error == 0
            {
                if r.bytes[5] != 0 {
                    self.error = BAD_SLOT;
                } else if !self.active {
                    self.error = MUTE;
                } else if r.bytes[8] != 0 || r.bytes[9] != 0 {
                    self.error = BAD_LENGTH;
                } else {
                    match backend
                        .prepare_extended(r.bytes[HEADER..PREFIX].try_into().unwrap(), r.len())
                    {
                        Err(sw) => r.status = sw,
                        Ok(length) => {
                            // Bound the backend contract before any PKE write or suffix copy.
                            if length == 0
                                || length > 1024
                                || ![7 + length as usize, 9 + length as usize].contains(&r.len())
                            {
                                self.error = HARDWARE;
                            } else if !backend.acquire(length as usize) {
                                self.error = HARDWARE;
                            } else {
                                r.body = length;
                                r.held = true;
                            }
                        }
                    }
                }
            }
        }
        if !data.is_empty() {
            self.error = BAD_LENGTH;
        }
        if self.error != 0 {
            self.request.close(backend);
        }
        if self.request.received == self.request.expected {
            self.phase = Phase::Queued;
        }
    }
    /// Reply storage is external: borrowing transport state must not invalidate
    /// an asynchronous USB reader's pointer into its in-flight response.
    pub fn queued(&self) -> bool {
        self.phase == Phase::Queued
    }
    /// A progress callback may retry only a slot poll's unsent response.
    pub fn presence_reply(&self) -> bool {
        self.phase == Phase::Reply && self.request.bytes[0] == SLOT_STATUS
    }
    pub fn execute(
        &mut self,
        hid_busy: bool,
        backend: &mut impl Backend,
        output: &mut [u8; HEADER + REPLY],
    ) {
        if self.phase != Phase::Queued {
            return;
        }
        let r = &mut self.request;
        let command = r.bytes[0];
        let slot = r.bytes[5];
        let seq = r.bytes[6];
        // Response family is determined by the request even when validation
        // fails before dispatch (for example an invalid slot).
        let kind = match command {
            TRANSFER | POWER_ON | 0x69 => DATA, // Secure
            GET_PARAMETERS | RESET_PARAMETERS | SET_PARAMETERS => PARAMETERS,
            0x6b => 0x83, // Escape
            _ => STATUS,
        };
        let mut error = if slot != 0 { BAD_SLOT } else { self.error };
        let specific = u8::from(kind == PARAMETERS);
        let mut unsupported = false;
        let mut length = 0;
        if error == 0 {
            match command {
                POWER_ON => {
                    if r.len() != 0 || r.bytes[8] != 0 || r.bytes[9] != 0 {
                        error = BAD_LENGTH;
                    } else if r.bytes[7] != 0 {
                        error = BAD_POWER;
                    } else {
                        self.session_owned = !hid_busy;
                        if self.session_owned {
                            backend.reset();
                        }
                        self.session_last = backend.now();
                        self.active = true;
                        output[HEADER..HEADER + ATR.len()].copy_from_slice(ATR);
                        length = ATR.len();
                    }
                }
                POWER_OFF => {
                    if r.len() != 0 {
                        error = BAD_LENGTH;
                    } else {
                        if !hid_busy {
                            backend.reset();
                        }
                        self.session_owned = false;
                        self.active = false;
                    }
                }
                SLOT_STATUS => {
                    if r.len() != 0 {
                        error = BAD_LENGTH;
                    }
                }
                TRANSFER => {
                    if !self.active {
                        error = MUTE;
                    } else if r.bytes[8] != 0 || r.bytes[9] != 0 {
                        error = BAD_LENGTH;
                    } else {
                        backend.arm(&extension(slot, seq), EXTENSION_INTERVAL);
                        let result = if r.status != 0 {
                            output[HEADER..HEADER + 2].copy_from_slice(&r.status.to_be_bytes());
                            Ok(2)
                        } else {
                            backend.exchange(r, &mut output[HEADER..])
                        };
                        backend.disarm();
                        self.session_owned = true;
                        self.session_last = backend.now();
                        match result {
                            Ok(n) if n <= REPLY => length = n,
                            _ => error = HARDWARE,
                        }
                    }
                }
                GET_PARAMETERS | RESET_PARAMETERS | SET_PARAMETERS => {
                    if command == SET_PARAMETERS && (r.bytes[7] != 1 || r.len() != T1.len()) {
                        error = BAD_POWER;
                    } else {
                        output[HEADER..HEADER + T1.len()].copy_from_slice(T1);
                        length = T1.len();
                    }
                }
                _ => {
                    unsupported = true;
                }
            }
        }
        r.close(backend);
        let status = u8::from(!self.active) | if error != 0 || unsupported { 0x40 } else { 0 };
        response(
            (&mut output[..HEADER]).try_into().unwrap(),
            kind,
            length as u32,
            slot,
            seq,
            status,
            error,
            specific,
        );
        self.reply_len = HEADER + length;
        self.phase = Phase::Reply;
        self.tx_started = backend.now();
    }
    pub fn reply<'a>(&self, output: &'a [u8; HEADER + REPLY]) -> Option<&'a [u8]> {
        (self.phase == Phase::Reply).then_some(&output[..self.reply_len])
    }
    pub fn submitted(&mut self) {
        self.phase = Phase::InFlight;
    }
    pub fn completed(&mut self) {
        if self.phase == Phase::InFlight {
            self.phase = Phase::Idle;
        }
    }
    /// Logical timeout never reuses the endpoint-owned response buffer.
    pub fn tx_timeout(&mut self, now: u32, backend: &mut impl Backend) {
        if matches!(self.phase, Phase::Reply | Phase::InFlight)
            && now.wrapping_sub(self.tx_started) >= TIMEOUT
            && self.session_owned
        {
            backend.reset();
            self.session_owned = false;
        }
    }
}
