// SPDX-License-Identifier: Apache-2.0
//! Main-loop CCID protocol. Endpoint/timer callbacks never borrow this state.
use canokey_protocol::ccid::*;

pub const FRAME: usize = canokey_protocol::apdu::SHORT_FRAME_BYTES;
pub const REPLY: usize = canokey_protocol::apdu::SHORT_REPLY_BYTES;
// PowerOn has the largest reply that never needs the shared APDU workspace.
pub const CONTROL_REPLY: usize = HEADER + ATR.len();
pub const EXTENSION_INTERVAL: u16 = 500;

pub trait Backend {
    fn reset(&mut self);
    fn slot_power(&mut self) -> bool {
        self.reset();
        true
    }
    fn exchange(&mut self, request: &Request, out: &mut [u8]) -> Result<usize, ()>;
    /// Copy into the disjoint IRQ-owned processing-extension buffer.
    fn arm(&mut self, bytes: &[u8; HEADER], interval: u16);
    fn disarm(&mut self);
}
pub struct Request {
    bytes: [u8; HEADER + FRAME],
    // Wider than dwLength: even UINT32_MAX must drain without header overflow.
    received: u64,
    expected: u64,
}
impl Request {
    const fn new() -> Self {
        Self {
            bytes: [0; HEADER + FRAME],
            received: 0,
            expected: HEADER as u64,
        }
    }
    pub fn len(&self) -> usize {
        (self.expected - HEADER as u64) as usize
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn short(&self) -> &[u8] {
        &self.bytes[HEADER..HEADER + self.len()]
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
    refused: bool,
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
            refused: false,
        }
    }
    pub fn reset(&mut self, backend: &mut impl Backend) {
        backend.disarm();
        backend.reset();
        self.request.bytes.fill(0);
        self.request.received = 0;
        self.request.expected = HEADER as u64;
        self.phase = Phase::Idle;
        self.active = false;
    }
    /// Logical completion is separate from final endpoint completion.
    pub fn completed_transaction(&self) -> bool {
        self.phase == Phase::Idle
    }
    pub fn idle(&self, _now: u32) -> bool {
        self.phase == Phase::Idle
    }
    pub fn can_receive(&self) -> bool {
        matches!(self.phase, Phase::Idle | Phase::Receiving)
    }
    /// No receive-gap expiry: accepted and refused messages drain their
    /// complete declared payload until an explicit reset/disconnect.
    pub fn receive(&mut self, data: &[u8]) {
        self.receive_admitted(data, true);
    }
    /// Latch buffer admission at the first packet. A refused body drains even
    /// if the foreign owner releases its reservation before the final packet.
    pub fn receive_admitted(&mut self, mut data: &[u8], admitted: bool) {
        if !self.can_receive() || data.is_empty() {
            return;
        }
        if self.phase == Phase::Idle {
            // A new USB transfer must carry its complete CCID header. Do not
            // splice a truncated first packet into the next independent message.
            if data.len() < HEADER {
                return;
            }
            self.request.received = 0;
            self.request.expected = HEADER as u64;
            self.error = 0;
            self.refused = !admitted;
            self.phase = Phase::Receiving;
        }
        while !data.is_empty() && self.request.received < self.request.expected {
            let r = &mut self.request;
            let at = r.received as usize;
            let mut n = data.len().min((r.expected - r.received) as usize);
            if at < HEADER {
                n = n.min(HEADER - at);
                r.bytes[at..at + n].copy_from_slice(&data[..n]);
            } else if !self.refused && r.len() <= FRAME && r.bytes[0] == TRANSFER {
                r.bytes[at..at + n].copy_from_slice(&data[..n]);
            }
            r.received += n as u64;
            data = &data[n..];
            if r.received == HEADER as u64 {
                let payload = payload_length(r.bytes[..HEADER].try_into().unwrap());
                r.expected = u64::from(payload) + HEADER as u64;
                if payload > FRAME as u32 && r.bytes[0] == TRANSFER {
                    self.error = BAD_LENGTH;
                }
            }
        }
        // C truncates excess bytes in the final packet to the declared length.
        if self.request.received == self.request.expected {
            self.phase = Phase::Queued;
        }
    }
    /// Reply storage is external: borrowing transport state must not invalidate
    /// an asynchronous USB reader's pointer into its in-flight response.
    pub fn queued(&self) -> bool {
        self.phase == Phase::Queued
    }
    pub fn needs_apdu_buffer(&self) -> bool {
        self.request.bytes[0] == TRANSFER && !self.refused && self.error == 0
    }
    /// A progress callback may retry only a slot poll's unsent response.
    pub fn presence_reply(&self) -> bool {
        self.phase == Phase::Reply && self.request.bytes[0] == SLOT_STATUS
    }
    pub fn execute(&mut self, hid_busy: bool, backend: &mut impl Backend, output: &mut [u8]) {
        if self.phase != Phase::Queued {
            return;
        }
        assert!(
            output.len()
                >= if self.needs_apdu_buffer() {
                    HEADER + REPLY
                } else {
                    CONTROL_REPLY
                }
        );
        let r = &mut self.request;
        let command = r.bytes[0];
        let slot = r.bytes[SLOT_OFFSET];
        let seq = r.bytes[SEQUENCE_OFFSET];
        // Response family is determined by the request even when validation
        // fails before dispatch (for example an invalid slot).
        let kind = match command {
            TRANSFER | POWER_ON | 0x69 => DATA, // Secure
            GET_PARAMETERS | RESET_PARAMETERS | SET_PARAMETERS => PARAMETERS,
            0x6b => 0x83, // Escape
            0x73 => 0x84, // SetDataRateAndClockFrequency
            _ => STATUS,
        };
        let rfu = match command {
            POWER_ON => 2,
            POWER_OFF | SLOT_STATUS | GET_PARAMETERS => 3,
            _ => 0,
        };
        let mut error = if slot != 0 {
            BAD_SLOT
        } else if rfu != 0 && !r.is_empty() {
            BAD_LENGTH
        } else if rfu != 0 && (r.bytes[8] != 0 || r.bytes[9] != 0 || (rfu == 3 && r.bytes[7] != 0))
        {
            if rfu == 2 { BAD_RFU2 } else { BAD_POWER }
        } else {
            self.error
        };
        let specific = u8::from(kind == PARAMETERS);
        let mut unsupported = false;
        let mut length = 0;
        if error == 0 {
            match command {
                POWER_ON | POWER_OFF => {
                    if command == POWER_ON && r.bytes[SPECIFIC_OFFSET] != 0 {
                        error = BAD_POWER;
                    } else if hid_busy || !backend.slot_power() {
                        error = SLOT_BUSY;
                    } else {
                        self.active = command == POWER_ON;
                        if self.active {
                            output[HEADER..HEADER + ATR.len()].copy_from_slice(ATR);
                            length = ATR.len();
                        }
                    }
                }
                SLOT_STATUS => {}
                TRANSFER => {
                    if self.refused {
                        // C's SW_ERR_NOT_PERSIST: transport admission failed,
                        // without entering Core or touching the foreign buffer.
                        output[HEADER..HEADER + 2].copy_from_slice(&[0x64, 0]);
                        length = 2;
                    } else {
                        let input = r.short();
                        // Reject before Core routing; even a tiny Case2E returns6700
                        // without changing selection or an existing command chain.
                        let bounded_short = canokey_protocol::apdu::parse(input)
                            .is_ok_and(|command| !command.info.extended);
                        let result = if !bounded_short {
                            output[HEADER..HEADER + 2].copy_from_slice(&[0x67, 0]);
                            Ok(2)
                        } else {
                            backend.arm(&extension(slot, seq), EXTENSION_INTERVAL);
                            let result = backend.exchange(r, &mut output[HEADER..]);
                            backend.disarm();
                            result
                        };
                        match result {
                            Ok(n) if n >= 2 && n <= REPLY => {
                                length = n;
                                self.active = true;
                            }
                            _ => error = HARDWARE,
                        }
                    }
                }
                GET_PARAMETERS => {
                    output[HEADER..HEADER + T1.len()].copy_from_slice(T1);
                    length = T1.len();
                }
                _ => {
                    unsupported = true;
                }
            }
        }
        let status = if slot != 0 { 2 } else { u8::from(!self.active) }
            | if error != 0 || unsupported {
                COMMAND_FAILED
            } else {
                0
            };
        response(
            (&mut output[..HEADER]).try_into().unwrap(),
            kind,
            length as u32,
            slot,
            seq,
            status,
            if error == 0 && !unsupported {
                SUCCESS_ERROR
            } else {
                error
            },
            specific,
        );
        self.reply_len = HEADER + length;
        self.phase = Phase::Reply;
    }
    pub fn reply<'a>(&self, output: &'a [u8]) -> Option<&'a [u8]> {
        (self.phase == Phase::Reply).then(|| &output[..self.reply_len])
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
