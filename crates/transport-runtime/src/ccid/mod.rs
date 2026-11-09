// SPDX-License-Identifier: Apache-2.0
//! Main-loop single-slot CCID. IRQs own endpoint packets, not this state.
mod frame;
mod profile;
use canokey_protocol::{apdu, ccid::*};
use core::marker::PhantomData;
use frame::{Fragment, Frame};
pub use profile::ShortApdu;

pub const EXTENSION_INTERVAL: u16 = 500;
pub const RECEIVE_TIMEOUT_MS: u32 = 2000;
const MIN_REPLY_BYTES: usize = 2;

/// Pure product validation and card identity; no application or IO references.
pub trait Policy {
    const ATR: &'static [u8];
    const PARAMETERS: &'static [u8];
    const SUCCESS_ERROR: u8;
    const WRITE_PARAMETERS: bool;
    fn validate(header: &[u8; HEADER], receive_error: u8) -> u8;
}
/// The main loop alone calls this capability. Buffered receive asks for owner
/// admission without dispatching an application. Streaming begin/feed may parse into the existing
/// product input owner; only exchange may execute a completed command.
pub trait Backend {
    /// Called once after validating a complete bounded XfrBlock header.
    /// Admission may reserve/preempt a transport owner, but cannot execute APDUs.
    fn admit(&mut self) -> bool {
        true
    }
    fn reset(&mut self);
    /// Release an unfinished streamed input without revoking applet selection
    /// or authorization. Buffered ingress never lent application input and
    /// never invokes this hook. Full resets and slot power use reset instead.
    fn abort_input(&mut self);
    fn slot_power(&mut self) -> bool {
        self.reset();
        true
    }
    fn begin(&mut self, _total: usize) -> bool {
        false
    }
    fn feed(&mut self, _bytes: &[u8]) {}
    fn exchange(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ()>;
    fn arm(&mut self, _header: &[u8; HEADER], _interval: u16) {}
    fn disarm(&mut self) {}
}
mod sealed {
    pub trait Sealed {}
}
/// Fixed ingress strategies keep their own payload storage.
/// They are sealed so profiles cannot add another payload allocation or hook.
pub trait Input: sealed::Sealed {
    const INITIAL: Self;
    const STREAMING: bool;
    fn clear(&mut self);
    fn begin(&mut self, length: usize, backend: &mut impl Backend) -> bool;
    fn feed(&mut self, offset: usize, bytes: &[u8], backend: &mut impl Backend);
    fn bytes(&self, length: usize) -> &[u8];
    fn pending(&self) -> bool {
        false
    }
    fn finished(&mut self) {}
}
pub struct Buffered {
    bytes: [u8; apdu::SHORT_FRAME_BYTES],
}
impl sealed::Sealed for Buffered {}
impl Input for Buffered {
    const INITIAL: Self = Self {
        bytes: [0x00; apdu::SHORT_FRAME_BYTES],
    };
    const STREAMING: bool = false;
    fn clear(&mut self) {
        self.bytes.fill(0x00);
    }
    fn begin(&mut self, _length: usize, _backend: &mut impl Backend) -> bool {
        true
    }
    fn feed(&mut self, offset: usize, bytes: &[u8], _backend: &mut impl Backend) {
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    fn bytes(&self, length: usize) -> &[u8] {
        &self.bytes[..length]
    }
}
pub struct Streaming {
    begun: bool,
}
impl sealed::Sealed for Streaming {}
impl Input for Streaming {
    const INITIAL: Self = Self { begun: false };
    const STREAMING: bool = true;
    fn clear(&mut self) {
        *self = Self::INITIAL;
    }
    fn begin(&mut self, length: usize, backend: &mut impl Backend) -> bool {
        self.begun = backend.begin(length);
        self.begun
    }
    fn feed(&mut self, _offset: usize, bytes: &[u8], backend: &mut impl Backend) {
        if self.begun {
            backend.feed(bytes);
        }
    }
    fn bytes(&self, _length: usize) -> &[u8] {
        &[]
    }
    fn pending(&self) -> bool {
        self.begun
    }
    fn finished(&mut self) {
        self.begun = false;
    }
}
struct NoBackend {
    admitted: bool,
}
impl Backend for NoBackend {
    fn abort_input(&mut self) {}
    fn admit(&mut self) -> bool {
        self.admitted
    }
    fn reset(&mut self) {}
    fn exchange(&mut self, _input: &[u8], _output: &mut [u8]) -> Result<usize, ()> {
        Err(())
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
// Private volatile state: keep byte metadata before the buffered APDU so
// Thumb-1 can address it directly. This is neither a wire nor an exported ABI.
#[repr(C)]
pub struct Transport<P: Policy, I: Input> {
    frame: Frame,
    last: u32,
    reply_len: u16,
    phase: Phase,
    error: u8,
    active: bool,
    refused: bool,
    policy: PhantomData<P>,
    input: I,
}
impl<P: Policy, I: Input> Default for Transport<P, I> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: Policy, I: Input> Transport<P, I> {
    pub const fn new() -> Self {
        Self {
            frame: Frame::new(),
            last: 0,
            input: I::INITIAL,
            reply_len: 0,
            phase: Phase::Idle,
            error: 0x00,
            active: false,
            refused: false,
            policy: PhantomData,
        }
    }
    pub fn reset(&mut self, backend: &mut impl Backend) {
        if !I::STREAMING {
            backend.disarm();
        }
        backend.reset();
        self.input.clear();
        self.frame = Frame::new();
        self.phase = Phase::Idle;
        self.active = false;
    }
    pub fn completed_transaction(&self) -> bool {
        self.phase == Phase::Idle
    }
    pub fn can_receive(&self) -> bool {
        matches!(self.phase, Phase::Idle | Phase::Receiving)
    }
    pub fn receiving(&self) -> bool {
        self.phase == Phase::Receiving
    }
    pub fn queued(&self) -> bool {
        self.phase == Phase::Queued
    }
    pub fn needs_apdu_buffer(&self) -> bool {
        self.frame.header[0] == TRANSFER && !self.refused && self.error == 0x00
    }
    pub fn presence_reply(&self) -> bool {
        self.phase == Phase::Reply && self.frame.header[0] == SLOT_STATUS
    }
    /// Reassemble the envelope before asking the facade to reserve an owner.
    /// The admission callback runs once, only for a valid bounded XfrBlock;
    /// refusal remains latched while its declared body is drained. A partial
    /// header must neither preempt another transport nor claim application IO.
    pub fn receive_at(&mut self, bytes: &[u8], now: u32, backend: &mut impl Backend) {
        if bytes.is_empty() || !self.can_receive() {
            return;
        }
        if self.timeout(now, backend) {
            return;
        }
        self.last = now;
        if self.phase == Phase::Idle {
            self.frame = Frame::new();
            self.error = 0x00;
            self.refused = false;
            self.phase = Phase::Receiving;
            self.input.finished();
        }
        let error = &mut self.error;
        let input = &mut self.input;
        let refused = &mut self.refused;
        let mut store = !*refused && *error == 0x00 && self.frame.header[0] == TRANSFER;
        let trailing = self.frame.feed(bytes, |fragment| match fragment {
            Fragment::Header(header) => {
                let length = payload_length(header);
                // Streaming may claim the application input owner here, so all
                // header-only scope/RFU checks must precede begin/feed. Buffered
                // ingress only asks for owner admission; application dispatch
                // remains deferred until the declared body has completed.
                let header_error =
                    if header[0] == TRANSFER && length > apdu::SHORT_FRAME_BYTES as u32 {
                        BAD_LENGTH
                    } else {
                        0x00
                    };
                *error = P::validate(header, header_error);
                store = header[0] == TRANSFER && *error == 0x00;
                if store {
                    *refused = !backend.admit();
                    store = !*refused;
                }
                if I::STREAMING && store && *error == 0x00 {
                    if input.begin(length as usize, backend) {
                        backend.arm(
                            &extension(header[SLOT_OFFSET], header[SEQUENCE_OFFSET]),
                            EXTENSION_INTERVAL,
                        );
                    } else {
                        *error = SLOT_BUSY;
                    }
                }
            }
            Fragment::Body { offset, bytes } => {
                if store && *error == 0x00 {
                    input.feed(offset, bytes, backend);
                }
            }
        });
        if trailing != 0 {
            self.error = BAD_LENGTH;
        }
        if self.frame.complete() {
            self.phase = Phase::Queued;
        }
    }
    pub fn execute(&mut self, hid_busy: bool, backend: &mut impl Backend, output: &mut [u8]) {
        if self.phase != Phase::Queued {
            return;
        }
        assert!(
            output.len()
                >= if self.needs_apdu_buffer() {
                    HEADER + apdu::SHORT_REPLY_BYTES
                } else {
                    HEADER + P::ATR.len().max(P::PARAMETERS.len())
                }
        );
        let header = &self.frame.header;
        let command = header[0];
        let slot = header[SLOT_OFFSET];
        let sequence = header[SEQUENCE_OFFSET];
        let kind = response_type(command);
        let mut error = P::validate(header, self.error);
        let mut unsupported = false;
        let mut length = 0;
        if error == 0x00 {
            match command {
                POWER_ON | POWER_OFF => {
                    if hid_busy || !backend.slot_power() {
                        error = SLOT_BUSY;
                    } else {
                        self.active = command == POWER_ON;
                        if self.active {
                            output[HEADER..HEADER + P::ATR.len()].copy_from_slice(P::ATR);
                            length = P::ATR.len();
                        }
                    }
                }
                SLOT_STATUS => {}
                TRANSFER => {
                    if self.refused {
                        // A foreign owner keeps its workspace; no backend is entered.
                        output[HEADER..HEADER + MIN_REPLY_BYTES].copy_from_slice(&[0x64, 0x00]);
                        length = MIN_REPLY_BYTES;
                    } else {
                        let input = self.input.bytes(self.frame.length() as usize);
                        let short = I::STREAMING
                            || apdu::parse(input).is_ok_and(|command| !command.info.extended);
                        let result = if !short {
                            output[HEADER..HEADER + MIN_REPLY_BYTES].copy_from_slice(&[0x67, 0x00]);
                            Ok(MIN_REPLY_BYTES)
                        } else {
                            if !I::STREAMING {
                                backend.arm(&extension(slot, sequence), EXTENSION_INTERVAL);
                            }
                            let result = backend.exchange(input, &mut output[HEADER..]);
                            if !I::STREAMING {
                                backend.disarm();
                            }
                            result
                        };
                        self.input.finished();
                        match result {
                            Ok(reply_bytes)
                                if (MIN_REPLY_BYTES..=apdu::SHORT_REPLY_BYTES)
                                    .contains(&reply_bytes) =>
                            {
                                length = reply_bytes;
                                self.active = true;
                            }
                            _ => error = HARDWARE,
                        }
                    }
                }
                GET_PARAMETERS | RESET_PARAMETERS | SET_PARAMETERS
                    if command == GET_PARAMETERS || P::WRITE_PARAMETERS =>
                {
                    output[HEADER..HEADER + P::PARAMETERS.len()].copy_from_slice(P::PARAMETERS);
                    length = P::PARAMETERS.len();
                }
                _ => unsupported = true,
            }
        }
        if self.input.pending() {
            backend.abort_input();
            self.input.finished();
        }
        let status = if slot != 0x00 {
            ICC_ABSENT
        } else {
            u8::from(!self.active)
        } | if error != 0x00 || unsupported {
            COMMAND_FAILED
        } else {
            0x00
        };
        response(
            (&mut output[..HEADER]).try_into().unwrap(),
            kind,
            length as u32,
            slot,
            sequence,
            status,
            if error == 0x00 && !unsupported {
                P::SUCCESS_ERROR
            } else {
                error
            },
            u8::from(kind == PARAMETERS),
        );
        self.reply_len = (HEADER + length) as u16;
        self.phase = Phase::Reply;
    }
    /// In-flight bytes are owned by the facade's separate endpoint lease.
    pub fn reply<'a>(&self, output: &'a [u8]) -> Option<&'a [u8]> {
        (self.phase == Phase::Reply).then(|| &output[..usize::from(self.reply_len)])
    }
    pub fn submitted(&mut self) {
        self.phase = Phase::InFlight;
    }
    pub fn completed(&mut self) {
        if self.phase == Phase::InFlight {
            self.phase = Phase::Idle;
        }
    }
}
impl<P: Policy> Transport<P, Buffered> {
    pub fn idle(&self, _now: u32) -> bool {
        self.completed_transaction()
    }
    /// Clock-free caller: receive at tick zero. USB facades use the timestamped
    /// receive_at entry point and service timeout from their loop.
    pub fn receive(&mut self, bytes: &[u8]) {
        self.receive_admitted(bytes, true);
    }
    /// Admission is sampled when the complete header arrives. Once refused,
    /// later packets cannot publish this request into another owner's workspace.
    pub fn receive_admitted(&mut self, bytes: &[u8], admitted: bool) {
        if bytes.is_empty() || !self.can_receive() {
            return;
        }
        self.receive_at(bytes, 0, &mut NoBackend { admitted });
    }
}
impl<P: Policy> Transport<P, Streaming> {
    pub fn idle(&self) -> bool {
        self.completed_transaction()
    }
    pub fn receive(&mut self, bytes: &[u8], now: u32, backend: &mut impl Backend) {
        self.receive_at(bytes, now, backend);
    }
}
impl<P: Policy, I: Input> Transport<P, I> {
    /// Expiry revokes a live RX owner, but a known envelope must still drain
    /// its declared body before one error reply. Reinterpreting its late tail
    /// as another header could otherwise execute unauthenticated power/APDUs.
    /// Return true only when an incomplete header was discarded.
    #[inline(never)]
    pub fn timeout(&mut self, now: u32, backend: &mut impl Backend) -> bool {
        if self.receiving()
            && self.error == 0x00
            && !self.refused
            && now.wrapping_sub(self.last) >= RECEIVE_TIMEOUT_MS
        {
            if self.input.pending() {
                backend.abort_input();
            }
            self.input.clear();
            if !self.frame.has_header() {
                self.phase = Phase::Idle;
                return true;
            }
            self.error = BAD_LENGTH;
        }
        false
    }
}

// FIDO asynchronous APDU: CLA 80, INS 11, P1 00=status/11=cancel,
// P2 00, with optional short Le 00. Replies carry a CTAP reason and SW.
const POLL_INS: u8 = 0x11;
const CANCEL_P1: u8 = 0x11;
const POLL_PREFIX_BYTES: usize = 5;
const POLL_REPLY_BYTES: usize = 3;
const CANCEL_REPLY: [u8; POLL_REPLY_BYTES] = [0x2d, 0x90, 0x00];
const UP_REPLY: [u8; POLL_REPLY_BYTES] = [canokey_protocol::ctaphid::STATUS_UPNEEDED, 0x91, 0x00];
const PROCESSING_REPLY: [u8; POLL_REPLY_BYTES] =
    [canokey_protocol::ctaphid::STATUS_PROCESSING, 0x91, 0x00];
/// Transport-only status/cancel while an application owns its request/output.
/// Reuse the same envelope drain mechanism; retain only a five-byte prefix.
/// No Backend or application borrow can enter this path.
pub struct Polling<P: Policy> {
    frame: Frame,
    prefix: [u8; POLL_PREFIX_BYTES],
    last: u32,
    pub ended: bool,
    pub cancelled: bool,
    policy: PhantomData<P>,
}
impl<P: Policy> Default for Polling<P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<P: Policy> Polling<P> {
    pub const fn new() -> Self {
        Self {
            frame: Frame::new(),
            prefix: [0x00; POLL_PREFIX_BYTES],
            last: 0,
            ended: false,
            cancelled: false,
            policy: PhantomData,
        }
    }
    pub fn receiving(&self) -> bool {
        self.frame.started()
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        now: u32,
        waiting: bool,
        output: &mut [u8; HEADER + POLL_REPLY_BYTES],
    ) -> Option<usize> {
        if self.receiving() && now.wrapping_sub(self.last) >= RECEIVE_TIMEOUT_MS {
            self.frame = Frame::new();
            self.prefix.fill(0x00);
        }
        self.last = now;
        let prefix = &mut self.prefix;
        let trailing = self.frame.feed(bytes, |fragment| {
            if let Fragment::Body { offset, bytes } = fragment {
                if offset < prefix.len() {
                    let length = bytes.len().min(prefix.len() - offset);
                    prefix[offset..offset + length].copy_from_slice(&bytes[..length]);
                }
            }
        });
        if !self.frame.complete() {
            return None;
        }
        let header = &self.frame.header;
        let command = header[0];
        let length = self.frame.length();
        let slot = header[SLOT_OFFSET];
        let kind = response_type(command);
        let mut error = if slot != 0x00 { BAD_SLOT } else { SLOT_BUSY };
        let mut reply_bytes = 0;
        if trailing == 0 && slot == 0x00 {
            match command {
                POWER_OFF if length == 0 => {
                    self.ended = true;
                    error = 0x00;
                }
                SLOT_STATUS if length == 0 => {
                    error = 0x00;
                }
                TRANSFER if matches!(length, 4 | 5) && header[8..10] == [0x00, 0x00] => {
                    let apdu = &self.prefix;
                    if apdu[0] == apdu::CLA_FIDO
                        && apdu[1] == POLL_INS
                        && matches!(apdu[2], 0x00 | CANCEL_P1)
                        && apdu[3] == 0x00
                        && (length == 4 || apdu[4] == 0x00)
                    {
                        self.cancelled |= apdu[2] == CANCEL_P1;
                        error = 0x00;
                        reply_bytes = POLL_REPLY_BYTES;
                        output[HEADER..HEADER + POLL_REPLY_BYTES].copy_from_slice(
                            if self.cancelled {
                                &CANCEL_REPLY
                            } else if waiting {
                                &UP_REPLY
                            } else {
                                &PROCESSING_REPLY
                            },
                        );
                    }
                }
                _ => {}
            }
        }
        let status = if slot != 0x00 {
            ICC_ABSENT
        } else {
            u8::from(self.ended)
        } | if error != 0x00 { COMMAND_FAILED } else { 0x00 };
        response(
            (&mut output[..HEADER]).try_into().unwrap(),
            kind,
            reply_bytes as u32,
            slot,
            header[SEQUENCE_OFFSET],
            status,
            if error == 0x00 {
                P::SUCCESS_ERROR
            } else {
                error
            },
            0x00,
        );
        self.frame = Frame::new();
        self.prefix.fill(0x00);
        Some(HEADER + reply_bytes)
    }
}
