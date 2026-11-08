// SPDX-License-Identifier: Apache-2.0
//! Main-loop CTAPHID transactions. Endpoint retries retain the C-owned report;
//! they never repeat a source read or command execution.
use canokey_protocol::ctaphid::{self as wire, Error, REPORT_SIZE, Report};

// Three HID packet windows stay inline; larger requests use PKE staging.
// Semantic parsers reuse the core session workspace, not this transport buffer.
const INLINE: usize = 192;

/// These inline messages finish without parsing into the applet workspace.
pub fn preserves_context(command: u8, length: usize) -> bool {
    length <= INLINE
        && (matches!(command, wire::PING | wire::WINK)
            || (command == wire::CBOR && length == 0)
            || (command == wire::MSG && length < canokey_protocol::apdu::EXTENDED_HEADER_BYTES))
}
const TIMEOUT_MS: u32 = 800;

/// One exclusive applet session, acquired before touching request scratch.
/// begin must reject other active transports and retain yielded card context.
/// close releases request storage, not the transport transaction. The caller
/// must exclude all other core/crypto entrypoints while Transport::active().
pub trait Scratch {
    fn webauthn_enabled(&mut self) -> bool {
        true
    }
    /// Available staging bytes; the wire message limit applies independently.
    fn capacity(&self) -> usize;
    /// Main-loop query only; a retained native response may still own PKE.
    fn continuation_pending(&mut self) -> bool {
        false
    }
    /// Inline controls and envelopes rejected before parsing preserve applet scratch.
    fn begin(&mut self, use_pke: bool, preserve_context: bool) -> Result<(), Error>;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;
    fn close(&mut self);
    /// Parser storage aliases the core's existing session workspace.
    fn begin_request(&mut self, message_length: Option<usize>);
    fn consume_request(&mut self, bytes: &[u8]);
    /// Source is closed before execution; response reads never reexecute crypto.
    fn finish_request(&mut self, cid: u32) -> usize;
    /// Trigger the indication without parsing a command over retained output.
    fn wink(&mut self, cid: u32);
    fn read_response(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error>;
    fn close_response(&mut self);
    /// Successful packet completion may retain an APDU response continuation.
    fn complete_response(&mut self) {
        self.close_response();
    }
    fn discard_continuation(&mut self) {}
    /// Header-only GET RESPONSE must not overwrite shared response backing.
    fn continue_message(&mut self, _bytes: &[u8]) -> Option<usize> {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Receiving,
    Sending,
    Completing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Storage {
    Released,
    Inline,
    Pke,
}

pub struct Transport {
    phase: Phase,
    cid: u32,
    continuation_cid: u32,
    next_cid: u32,
    command: u8,
    total: usize,
    offset: usize,
    sequence: u8,
    last_received: u32,
    storage: Storage,
    inline: [u8; INLINE],
    response: bool,
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
            cid: 0,
            continuation_cid: 0,
            next_cid: 1,
            command: 0,
            total: 0,
            offset: 0,
            sequence: 0,
            last_received: 0,
            storage: Storage::Released,
            inline: [0; INLINE],
            response: false,
        }
    }
    pub fn active(&self) -> bool {
        self.phase != Phase::Idle
    }
    #[inline(never)]
    fn close_request(&mut self, scratch: &mut impl Scratch) {
        if self.storage != Storage::Released {
            scratch.close();
            self.storage = Storage::Released;
        }
    }
    pub fn reset(&mut self, scratch: &mut impl Scratch) {
        self.close_request(scratch);
        self.phase = Phase::Idle;
        if self.response {
            scratch.close_response();
            self.response = false;
        }
        scratch.discard_continuation();
        self.continuation_cid = 0;
        self.inline.fill(0);
    }
    fn error(out: &mut [u8; REPORT_SIZE], cid: u32, error: Error) -> bool {
        wire::header(out, cid, wire::ERROR, 1)[0] = error as u8;
        true
    }
    fn fail(
        &mut self,
        out: &mut [u8; REPORT_SIZE],
        error: Error,
        scratch: &mut impl Scratch,
    ) -> bool {
        if self.phase == Phase::Receiving && !self.response {
            // Framing failure has not entered the parser or replaced an older
            // native source. Release only this incomplete request.
            self.close_request(scratch);
            self.phase = Phase::Idle;
            self.inline.fill(0);
        } else {
            self.reset(scratch);
        }
        Self::error(out, self.cid, error)
    }
    /// Called only after the preceding endpoint report has completed. Closing
    /// here keeps a PING source alive through the final USB IN completion.
    pub fn completed(&mut self, scratch: &mut impl Scratch) {
        if self.phase == Phase::Completing {
            self.close_request(scratch);
            self.phase = Phase::Idle;
            if self.response {
                scratch.complete_response();
                self.continuation_cid = if scratch.continuation_pending() {
                    self.cid
                } else {
                    0
                };
                self.response = false;
            }
            self.inline.fill(0);
        }
    }
    /// Process queued packets before checking the clock: deadlines use receipt
    /// timestamps, not the time the main loop happens to service a packet.
    pub fn receive(
        &mut self,
        bytes: &[u8; REPORT_SIZE],
        tick: u32,
        out: &mut [u8; REPORT_SIZE],
        scratch: &mut impl Scratch,
    ) -> bool {
        let frame = Report::decode(bytes);
        if frame.cid == 0 || (frame.cid == wire::BROADCAST && frame.tag != wire::INIT) {
            return Self::error(out, frame.cid, Error::Channel);
        }
        if self.active() && frame.cid != self.cid {
            return Self::error(out, frame.cid, Error::Busy);
        }
        if frame.tag == wire::INIT {
            return self.initialize(frame, out, scratch);
        }
        // Executing CANCEL is serviced by the transport-only callback. During
        // fragmented RX, a new initial report is a sequence error as in C.
        if frame.tag == wire::CANCEL && frame.length == Some(0) && self.phase != Phase::Receiving {
            return false;
        }
        if self.phase == Phase::Sending || self.phase == Phase::Completing {
            return Self::error(out, frame.cid, Error::Busy);
        }
        if self.phase == Phase::Receiving {
            if tick.wrapping_sub(self.last_received) > TIMEOUT_MS {
                return self.fail(out, Error::Timeout, scratch);
            }
            if frame.length.is_some() || frame.tag != self.sequence {
                return self.fail(out, Error::Sequence, scratch);
            }
            self.sequence += 1;
        } else {
            let Some(length) = frame.length else {
                return false;
            };
            // C bounds the entire HID message, including native MSG's APDU
            // header/trailer. Extra hardware scratch is not a wire capability.
            if length > wire::CTAP_MAX_REQUEST || (length > INLINE && length > scratch.capacity()) {
                return Self::error(out, frame.cid, Error::Length);
            }
            if frame.tag != wire::PING
                && frame.tag != wire::CBOR
                && frame.tag != wire::MSG
                && frame.tag != wire::WINK
                && frame.tag != wire::CANCEL
            {
                return Self::error(out, frame.cid, Error::Command);
            }
            let pke = length > INLINE;
            if pke && scratch.continuation_pending() {
                return Self::error(out, frame.cid, Error::Busy);
            }
            let preserve_context = preserves_context(frame.tag, length);
            if let Err(error) = scratch.begin(pke, preserve_context) {
                return Self::error(out, frame.cid, error);
            }
            self.storage = if pke { Storage::Pke } else { Storage::Inline };
            self.cid = frame.cid;
            self.command = frame.tag;
            self.total = length;
            self.offset = 0;
            self.sequence = 0;
            self.phase = Phase::Receiving;
        }
        self.last_received = tick;
        let n = frame.data.len().min(self.total - self.offset);
        if self.storage == Storage::Pke {
            if let Err(error) = scratch.write(self.offset, &frame.data[..n]) {
                return self.fail(out, error, scratch);
            }
        } else {
            self.inline[self.offset..self.offset + n].copy_from_slice(&frame.data[..n]);
        }
        self.offset += n;
        if self.offset == self.total {
            if let Err(error) = self.finish_request(scratch) {
                if matches!(self.command, wire::MSG | wire::CBOR) && !self.response {
                    // Rejection before parser entry cannot consume a retained
                    // source, including empty/disabled CBOR and invalid MSG.
                    self.close_request(scratch);
                    self.phase = Phase::Idle;
                    self.inline.fill(0);
                    return Self::error(out, self.cid, error);
                }
                return self.fail(out, error, scratch);
            }
        }
        false
    }
    fn initialize(
        &mut self,
        frame: Report<'_>,
        out: &mut [u8; REPORT_SIZE],
        scratch: &mut impl Scratch,
    ) -> bool {
        if frame.length != Some(wire::INIT_NONCE_BYTES) {
            return Self::error(out, frame.cid, Error::Length);
        }
        self.reset(scratch);
        let assigned = if frame.cid == wire::BROADCAST {
            let cid = self.next_cid;
            self.next_cid = if cid == wire::BROADCAST - 1 {
                1
            } else {
                cid + 1
            };
            cid
        } else {
            frame.cid
        };
        let data = wire::header(out, frame.cid, wire::INIT, wire::INIT_RESPONSE_BYTES);
        data[..wire::INIT_NONCE_BYTES].copy_from_slice(&frame.data[..wire::INIT_NONCE_BYTES]);
        data[8..12].copy_from_slice(&assigned.to_be_bytes());
        data[12] = 2; // CTAPHID interface version
        data[13..16].copy_from_slice(&crate::release::CTAPHID_DEVICE);
        data[16] = 0x05; // WINK and CBOR bits; MSG is supported by leaving NMSG clear.
        true
    }
    /// Finish parsing before releasing input; execute only after release.
    /// PING keeps its source until the last response report completes.
    #[inline(never)]
    fn finish_request(&mut self, scratch: &mut impl Scratch) -> Result<(), Error> {
        if self.command == wire::CANCEL {
            // Idle/late CANCEL payloads have no reply and never enter Core.
            self.close_request(scratch);
            self.inline.fill(0);
            self.phase = Phase::Idle;
            return Ok(());
        }
        if self.command == wire::WINK {
            // The C release consumes and ignores a bounded WINK payload.
            self.close_request(scratch);
            self.inline.fill(0);
            scratch.wink(self.cid);
            self.total = 0;
        }
        if self.command == wire::CBOR || self.command == wire::MSG {
            if !scratch.webauthn_enabled() {
                return Err(Error::Command);
            }
            if self.command == wire::CBOR {
                if self.total == 0 {
                    return Err(Error::Length);
                }
                if scratch.continuation_pending() {
                    return Err(Error::Busy);
                }
            }
            if self.command == wire::MSG {
                if self.total < canokey_protocol::apdu::EXTENDED_HEADER_BYTES {
                    return Err(Error::Length);
                }
                let mut header = [0; canokey_protocol::apdu::EXTENDED_HEADER_BYTES];
                if self.storage == Storage::Pke {
                    scratch.read(0, &mut header)?;
                } else {
                    header.copy_from_slice(
                        &self.inline[..canokey_protocol::apdu::EXTENDED_HEADER_BYTES],
                    );
                }
                wire::message_body_length(&header, self.total)?;
                // Refused CBOR and control traffic may change the current RX
                // CID. Only the CID that created the retained source may read
                // or replace it; last-received CID is not response ownership.
                if scratch.continuation_pending() && self.cid != self.continuation_cid {
                    return Err(Error::Busy);
                }
            }
            // The shared parser also needs cleanup when a staged read fails.
            self.response = true;
            let continued = if self.command == wire::MSG && self.storage == Storage::Inline {
                scratch.continue_message(&self.inline[..self.total])
            } else {
                None
            };
            if let Some(length) = continued {
                self.close_request(scratch);
                self.inline.fill(0);
                self.total = length;
            } else {
                scratch.begin_request((self.command == wire::MSG).then_some(self.total));
                if self.storage == Storage::Pke {
                    for offset in (0..self.total).step_by(INLINE) {
                        let n = INLINE.min(self.total - offset);
                        scratch.read(offset, &mut self.inline[..n])?;
                        scratch.consume_request(&self.inline[..n]);
                    }
                } else {
                    scratch.consume_request(&self.inline[..self.total]);
                }
                self.close_request(scratch);
                self.inline.fill(0);
                self.total = scratch.finish_request(self.cid);
            }
            self.response = true;
        }
        // Continuation tags have seven sequence bits. Reject before publishing
        // a truncated length or wrapping the final continuation into INIT.
        if self.total > wire::MAX_MESSAGE {
            return Err(Error::Length);
        }
        self.offset = 0;
        self.sequence = 0;
        self.phase = Phase::Sending;
        Ok(())
    }
    pub fn timeout(
        &mut self,
        now: u32,
        out: &mut [u8; REPORT_SIZE],
        scratch: &mut impl Scratch,
    ) -> bool {
        if self.phase == Phase::Receiving && now.wrapping_sub(self.last_received) > TIMEOUT_MS {
            self.fail(out, Error::Timeout, scratch)
        } else {
            false
        }
    }
    /// Read a source once per report, monotonically. The caller must not call
    /// again until this report is accepted AND completed, or explicitly reset.
    pub fn transmit(&mut self, out: &mut [u8; REPORT_SIZE], scratch: &mut impl Scratch) -> bool {
        if self.phase != Phase::Sending {
            return false;
        }
        let (tag, length) = if self.offset == 0 {
            (self.command, self.total)
        } else {
            (self.sequence, 0)
        };
        let payload = wire::header(out, self.cid, tag, length);
        let n = payload.len().min(self.total - self.offset);
        let dest = &mut payload[..n];
        if self.response {
            if let Err(error) = scratch.read_response(self.offset, dest) {
                return self.fail(out, error, scratch);
            }
        } else if self.storage == Storage::Pke {
            if let Err(error) = scratch.read(self.offset, dest) {
                return self.fail(out, error, scratch);
            }
        } else {
            dest.copy_from_slice(&self.inline[self.offset..self.offset + n]);
        }
        if self.offset != 0 {
            self.sequence += 1;
        }
        self.offset += n;
        if self.offset == self.total {
            self.phase = Phase::Completing;
        }
        true
    }
}
