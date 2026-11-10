// SPDX-License-Identifier: Apache-2.0
//! Main-loop HID framing. Endpoint completion owns the final source lifetime.
use canokey_protocol::ctaphid::{self as wire, Error, REPORT_SIZE, Report};
use core::marker::PhantomData;

pub const TIMEOUT_MS: u32 = 800;
pub const KEEPALIVE_INTERVAL_MS: u32 = 100;
// CanoKey keeps three report windows inline while another applet owns scratch.
pub const INLINE_CONTROL_BYTES: usize = 192;
pub fn preserves_context(command: u8, length: usize) -> bool {
    length <= INLINE_CONTROL_BYTES
        && (matches!(command, wire::PING | wire::WINK)
            || (command == wire::CBOR && length == 0)
            || (command == wire::MSG && length < canokey_protocol::apdu::EXTENDED_HEADER_BYTES))
}
const INVALID_CHANNEL: u32 = 0x0000_0000;
const FIRST_CHANNEL: u32 = 0x0000_0001;
const INTERFACE_VERSION: u8 = 0x02;
// CTAP 2.3 section 11.2.9.1 INIT payload: nonce (8 bytes), assigned
// big-endian CID (4), protocol version (1), device version (3), capabilities (1).
const ASSIGNED_CID_OFFSET: usize = 8;
const INTERFACE_VERSION_OFFSET: usize = 12;
const DEVICE_VERSION_OFFSET: usize = 13;
const CAPABILITIES_OFFSET: usize = 16;

/// Static wire policy; request capacities belong to the input owner.
pub trait Profile {
    const DEVICE_VERSION: [u8; 3];
    const CAPABILITIES: u8;
    const REGISTERED_CHANNELS: bool;
    const WRAP_CHANNELS: bool;
    const INCLUSIVE_TIMEOUT: bool;
    const CANCEL_DURING_RECEIVE: bool;
}
/// Synchronous capability over the product's existing request/response owner.
/// begin must reject foreign owners before touching scratch. finish parses and
/// releases staging before execution. read never repeats command execution.
pub trait Backend: Response + Completion {
    fn reset(&mut self);
    fn resynchronize(&mut self) {}
    fn begin(&mut self, command: u8, length: usize, cid: u32) -> Result<(), Error>;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    fn finish(&mut self, command: u8, length: usize, cid: u32) -> Result<usize, Error>;
}
/// Output-only access cannot acquire or parse a request.
pub trait Response {
    fn read(&mut self, offset: usize, output: &mut [u8]) -> Result<(), Error>;
    /// Incomplete input failure may preserve an earlier native continuation.
    fn abort(&mut self, receiving: bool);
}
/// Final endpoint acknowledgement releases only the retained response owner.
pub trait Completion {
    fn complete(&mut self, cid: u32);
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Receiving,
    Sending,
    Completing,
}
pub struct Session<P: Profile> {
    phase: Phase,
    cid: u32,
    next_cid: u32,
    command: u8,
    total: usize,
    offset: usize,
    sequence: u8,
    last_received: u32,
    profile: PhantomData<P>,
}
impl<P: Profile> Default for Session<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: Profile> Session<P> {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            cid: INVALID_CHANNEL,
            next_cid: FIRST_CHANNEL,
            command: 0x00,
            total: 0,
            offset: 0,
            sequence: 0x00,
            last_received: 0,
            profile: PhantomData,
        }
    }
    pub fn active(&self) -> bool {
        self.phase != Phase::Idle
    }
    pub fn cid(&self) -> u32 {
        self.cid
    }
    pub fn reset(&mut self, backend: &mut impl Backend) {
        backend.reset();
        self.phase = Phase::Idle;
        self.total = 0;
        self.offset = 0;
    }
    fn expired(&self, now: u32) -> bool {
        let elapsed = now.wrapping_sub(self.last_received);
        if P::INCLUSIVE_TIMEOUT {
            elapsed >= TIMEOUT_MS
        } else {
            elapsed > TIMEOUT_MS
        }
    }
    fn error(output: &mut [u8; REPORT_SIZE], cid: u32, error: Error) -> bool {
        wire::header(output, cid, wire::ERROR, 1)[0] = error as u8;
        true
    }
    fn fail(
        &mut self,
        output: &mut [u8; REPORT_SIZE],
        error: Error,
        backend: &mut impl Response,
    ) -> bool {
        backend.abort(self.phase == Phase::Receiving);
        self.phase = Phase::Idle;
        Self::error(output, self.cid, error)
    }
    pub fn completed(&mut self, backend: &mut impl Completion) {
        if self.phase == Phase::Completing {
            backend.complete(self.cid);
            self.phase = Phase::Idle;
        }
    }
    /// Packet receipt timestamps govern expiry, independently of service delay.
    pub fn receive(
        &mut self,
        bytes: &[u8; REPORT_SIZE],
        tick: u32,
        output: &mut [u8; REPORT_SIZE],
        backend: &mut impl Backend,
    ) -> bool {
        let frame = Report::decode(bytes);
        if frame.cid == INVALID_CHANNEL || (frame.cid == wire::BROADCAST && frame.tag != wire::INIT)
        {
            return Self::error(output, frame.cid, Error::Channel);
        }
        if self.active() && frame.cid != self.cid {
            return Self::error(output, frame.cid, Error::Busy);
        }
        if frame.tag == wire::INIT {
            if frame.length != Some(wire::INIT_NONCE_BYTES) {
                return Self::error(output, frame.cid, Error::Length);
            }
            if P::REGISTERED_CHANNELS && frame.cid != wire::BROADCAST && frame.cid >= self.next_cid
            {
                return Self::error(output, frame.cid, Error::Channel);
            }
            self.reset(backend);
            let assigned = if frame.cid == wire::BROADCAST {
                if !P::WRAP_CHANNELS && self.next_cid == wire::BROADCAST {
                    return Self::error(output, frame.cid, Error::Other);
                }
                let cid = self.next_cid;
                self.next_cid = if P::WRAP_CHANNELS && cid == wire::BROADCAST - 1 {
                    FIRST_CHANNEL
                } else {
                    cid + 1
                };
                cid
            } else {
                backend.resynchronize();
                frame.cid
            };
            let data = wire::header(output, frame.cid, wire::INIT, wire::INIT_RESPONSE_BYTES);
            data[..wire::INIT_NONCE_BYTES].copy_from_slice(&frame.data[..wire::INIT_NONCE_BYTES]);
            data[ASSIGNED_CID_OFFSET..INTERFACE_VERSION_OFFSET]
                .copy_from_slice(&assigned.to_be_bytes());
            data[INTERFACE_VERSION_OFFSET] = INTERFACE_VERSION;
            data[DEVICE_VERSION_OFFSET..CAPABILITIES_OFFSET].copy_from_slice(&P::DEVICE_VERSION);
            data[CAPABILITIES_OFFSET] = P::CAPABILITIES;
            return true;
        }
        if P::REGISTERED_CHANNELS && frame.cid >= self.next_cid {
            return Self::error(output, frame.cid, Error::Channel);
        }
        if frame.tag == wire::CANCEL
            && frame.length == Some(0)
            && (P::CANCEL_DURING_RECEIVE || self.phase != Phase::Receiving)
        {
            return false;
        }
        if matches!(self.phase, Phase::Sending | Phase::Completing) {
            return Self::error(output, frame.cid, Error::Busy);
        }
        if self.phase == Phase::Receiving {
            if self.expired(tick) {
                return self.fail(output, Error::Timeout, backend);
            }
            if frame.length.is_some() || frame.tag != self.sequence {
                return self.fail(output, Error::Sequence, backend);
            }
            self.sequence += 1;
        } else {
            let Some(length) = frame.length else {
                return false;
            };
            if let Err(error) = backend.begin(frame.tag, length, frame.cid) {
                return Self::error(output, frame.cid, error);
            }
            self.cid = frame.cid;
            self.command = frame.tag;
            self.total = length;
            self.offset = 0;
            self.sequence = 0x00;
            self.phase = Phase::Receiving;
        }
        self.last_received = tick;
        let length = frame.data.len().min(self.total - self.offset);
        if let Err(error) = backend.write(self.offset, &frame.data[..length]) {
            return self.fail(output, error, backend);
        }
        self.offset += length;
        if self.offset == self.total {
            match backend.finish(self.command, self.total, self.cid) {
                Ok(length) => {
                    // Seven sequence bits bound every response, independently
                    // of the product's request scratch and application limit.
                    if length > wire::MAX_MESSAGE {
                        return self.fail(output, Error::Length, backend);
                    }
                    // CANCEL consumes its input without a response.
                    if self.command == wire::CANCEL {
                        self.phase = Phase::Idle;
                    } else {
                        self.total = length;
                        self.offset = 0;
                        self.sequence = 0x00;
                        self.phase = Phase::Sending;
                    }
                }
                Err(error) => return self.fail(output, error, backend),
            }
        }
        false
    }
    pub fn timeout(
        &mut self,
        now: u32,
        output: &mut [u8; REPORT_SIZE],
        backend: &mut impl Backend,
    ) -> bool {
        if self.phase == Phase::Receiving && self.expired(now) {
            self.fail(output, Error::Timeout, backend)
        } else {
            false
        }
    }
    /// Called once per completed endpoint report; retries reuse facade storage.
    pub fn transmit(
        &mut self,
        output: &mut [u8; REPORT_SIZE],
        backend: &mut impl Response,
    ) -> bool {
        if self.phase != Phase::Sending {
            return false;
        }
        let (tag, length) = if self.offset == 0 {
            (self.command, self.total)
        } else {
            (self.sequence, 0)
        };
        let data = wire::header(output, self.cid, tag, length);
        let length = data.len().min(self.total - self.offset);
        if let Err(error) = backend.read(self.offset, &mut data[..length]) {
            return self.fail(output, error, backend);
        }
        if self.offset != 0 {
            self.sequence += 1;
        }
        self.offset += length;
        if self.offset == self.total {
            self.phase = Phase::Completing;
        }
        true
    }
}

mod execution;
pub use execution::{Execution, ExecutionPolicy, Incoming, Progress, classify_error, foreign_error};
