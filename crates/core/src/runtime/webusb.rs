// SPDX-License-Identifier: Apache-2.0
//! WebUSB APDU lifecycle. Storage and session ownership are supplied by the
//! serialized facade; this policy never allocates a second APDU workspace.
#![forbid(unsafe_code)]
use canokey_protocol::usb::Setup;

pub const COMMAND_LIMIT: usize = canokey_protocol::apdu::SHORT_FRAME_BYTES;
pub const RESPONSE_LIMIT: usize = canokey_protocol::apdu::SHORT_REPLY_BYTES;
// CanoKey vendor/interface requests: submit APDU, fetch response, read state.
pub const REQUEST_COMMAND: u8 = 0x00;
pub const REQUEST_RESPONSE: u8 = 0x01;
pub const REQUEST_STATUS: u8 = 0x02;
pub const STATUS_IDLE: u8 = 0xff;
pub const STATUS_RECEIVING: u8 = 0x03;
pub const STATUS_PROCESSING: u8 = 0x01;
pub const STATUS_RESPONSE: u8 = 0x00;
pub const STATUS_SENDING: u8 = 0x02;
pub const STATUS_HOLD: u8 = 0x04;
pub const SESSION_TIMEOUT: u32 = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Command(usize),
    Response(usize),
    Status,
}
impl Request {
    pub fn decode(s: Setup, interface: u8) -> Option<Self> {
        if s.index != u16::from(interface) || s.value != 0 {
            return None;
        }
        match (s.kind, s.request) {
            (canokey_protocol::usb::VENDOR_INTERFACE_OUT, REQUEST_COMMAND)
                if usize::from(s.length) <= COMMAND_LIMIT =>
            {
                Some(Self::Command(usize::from(s.length)))
            }
            (canokey_protocol::usb::VENDOR_INTERFACE_IN, REQUEST_RESPONSE) => {
                Some(Self::Response(usize::from(s.length)))
            }
            (canokey_protocol::usb::VENDOR_INTERFACE_IN, REQUEST_STATUS) if s.length == 1 => {
                Some(Self::Status)
            }
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Receiving,
    Queued,
    Executing,
    Discarding,
    Response,
    Sending,
    Hold,
}
/// Calls that release a transfer require EP0 to have been quiesced first.
/// IRQ code may use this state only under the same mask as main-loop callers.
/// A reset during execution keeps the workspace leased until finish().
pub struct Transport {
    phase: Phase,
    length: usize,
    received: usize,
    last_activity: u32,
}
impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}
impl Transport {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            length: 0,
            received: 0,
            last_activity: 0,
        }
    }
    pub fn status(&self) -> u8 {
        match self.phase {
            Phase::Idle => STATUS_IDLE,
            Phase::Receiving => STATUS_RECEIVING,
            Phase::Queued | Phase::Executing | Phase::Discarding => STATUS_PROCESSING,
            Phase::Response => STATUS_RESPONSE,
            Phase::Sending => STATUS_SENDING,
            Phase::Hold => STATUS_HOLD,
        }
    }
    pub fn execution_live(&self) -> Option<bool> {
        match self.phase {
            Phase::Executing => Some(true),
            Phase::Discarding => Some(false),
            _ => None,
        }
    }
    pub fn completed_transaction(&self) -> bool {
        self.phase == Phase::Hold
    }
    pub fn busy(&self) -> bool {
        self.phase != Phase::Idle
    }
    /// Reserve the channel before receiving. The facade must additionally
    /// acquire the shared byte buffer and applet session before copying input.
    /// Holding a session is not permission to reuse another TX lease.
    pub fn command(&mut self, length: usize, now: u32, admitted: bool) -> bool {
        if !admitted || length > COMMAND_LIMIT || !matches!(self.phase, Phase::Idle | Phase::Hold) {
            return false;
        }
        self.length = length;
        self.received = 0;
        self.last_activity = now;
        self.phase = if length == 0 {
            Phase::Queued
        } else {
            Phase::Receiving
        };
        true
    }
    /// Validate before copying a FIFO packet into the shared input buffer.
    /// A short packet before wLength is exhausted is malformed, not an APDU.
    pub fn receive(&mut self, length: usize, now: u32) -> Option<usize> {
        if self.phase != Phase::Receiving
            || length > canokey_protocol::usb::EP0_PACKET_BYTES
            || length == 0
            || length > self.length - self.received
            || (length < canokey_protocol::usb::EP0_PACKET_BYTES
                && length != self.length - self.received)
        {
            return None;
        }
        let offset = self.received;
        self.received += length;
        self.last_activity = now;
        if self.received == self.length {
            self.phase = Phase::Queued;
        }
        Some(offset)
    }
    /// Return a command length once; no state borrow crosses Core execution.
    pub fn execute(&mut self) -> Option<usize> {
        if self.phase != Phase::Queued {
            return None;
        }
        self.phase = Phase::Executing;
        Some(self.length)
    }
    /// Publish only after the input borrow has ended and Core has written the
    /// response. False means reset/abort invalidated this command's result.
    pub fn finish(&mut self, length: usize, now: u32) -> bool {
        if self.phase == Phase::Discarding {
            *self = Self::new();
            return false;
        }
        if self.phase != Phase::Executing {
            return false;
        }
        if !(2..=RESPONSE_LIMIT).contains(&length) {
            *self = Self::new();
            return false;
        }
        self.length = length;
        self.last_activity = now;
        self.phase = Phase::Response;
        true
    }
    pub fn response(&mut self, requested: usize, now: u32) -> Option<usize> {
        if self.phase != Phase::Response {
            return None;
        }
        self.phase = Phase::Sending;
        self.last_activity = now;
        Some(self.length.min(requested))
    }
    /// Called only on actual endpoint completion, never on elapsed time.
    pub fn completed(&mut self, now: u32) {
        if self.phase == Phase::Sending {
            self.phase = Phase::Hold;
            self.last_activity = now;
        }
    }
    pub fn keepalive(&mut self, now: u32) {
        self.last_activity = now;
    }
    /// Only an idle session expires. Receiving/executing/transmitting retain
    /// buffer ownership until explicit abort and hardware quiescence.
    pub fn expired(&self, now: u32) -> bool {
        self.phase == Phase::Hold && now.wrapping_sub(self.last_activity) >= SESSION_TIMEOUT
    }
    /// Requires hardware quiescence. The facade separately resets Core in the
    /// main loop, after any running call returns, before admitting another owner.
    pub fn reset(&mut self) {
        if matches!(self.phase, Phase::Executing | Phase::Discarding) {
            self.phase = Phase::Discarding;
        } else {
            *self = Self::new();
        }
    }
}
