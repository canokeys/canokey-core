// SPDX-License-Identifier: Apache-2.0
//! Main-loop CTAPHID transactions. Endpoint retries retain the C-owned report;
//! they never repeat a source read or command execution.
use crate::applets::ctap;
use canokey_protocol::ctaphid::{self as wire, Error, REPORT_SIZE, Report};

const INLINE: usize = 192;
const TIMEOUT_MS: u32 = 800;

/// One exclusive applet session, acquired before touching request scratch.
/// begin must reject other active transports and reset their idle core session.
/// close releases request storage, not the transport transaction. The caller
/// must exclude all other core/crypto entrypoints while Transport::active().
pub trait Scratch {
    fn begin(&mut self, use_pke: bool) -> Result<(), Error>;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;
    fn close(&mut self);
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
    next_cid: u32,
    command: u8,
    total: usize,
    offset: usize,
    sequence: u8,
    last_received: u32,
    storage: Storage,
    inline: [u8; INLINE],
    constant: Option<&'static [u8]>,
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
            next_cid: 1,
            command: 0,
            total: 0,
            offset: 0,
            sequence: 0,
            last_received: 0,
            storage: Storage::Released,
            inline: [0; INLINE],
            constant: None,
        }
    }
    pub fn active(&self) -> bool {
        self.phase != Phase::Idle
    }
    fn close_request(&mut self, scratch: &mut impl Scratch) {
        if self.storage != Storage::Released {
            scratch.close();
            self.storage = Storage::Released;
        }
    }
    pub fn reset(&mut self, scratch: &mut impl Scratch) {
        self.close_request(scratch);
        self.phase = Phase::Idle;
        self.constant = None;
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
        self.reset(scratch);
        Self::error(out, self.cid, error)
    }
    /// Called only after the preceding endpoint report has completed. Closing
    /// here keeps a PING source alive through the final USB IN completion.
    pub fn completed(&mut self, scratch: &mut impl Scratch) {
        if self.phase == Phase::Completing {
            self.reset(scratch);
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
        // There are no asynchronous CTAP handlers yet. CANCEL is silent when
        // no command is executing; it does not cancel fragment aggregation.
        if frame.tag == wire::CANCEL && frame.length == Some(0) {
            return false;
        }
        if self.phase == Phase::Sending || self.phase == Phase::Completing {
            return Self::error(out, frame.cid, Error::Busy);
        }
        if self.phase == Phase::Receiving {
            if tick.wrapping_sub(self.last_received) >= TIMEOUT_MS {
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
            if length > ctap::MAX_REQUEST || length > wire::MAX_MESSAGE {
                return Self::error(out, frame.cid, Error::Length);
            }
            if frame.tag != wire::PING && frame.tag != wire::CBOR {
                return Self::error(out, frame.cid, Error::Command);
            }
            let pke = length > INLINE;
            if let Err(error) = scratch.begin(pke) {
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
        if frame.length != Some(8) {
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
        let data = wire::header(out, frame.cid, wire::INIT, 17);
        data[..8].copy_from_slice(&frame.data[..8]);
        data[8..12].copy_from_slice(&assigned.to_be_bytes());
        data[12] = 2; // CTAPHID interface version
        data[16] = 0x0c; // CBOR, no MSG (U2F not migrated)
        true
    }
    /// Finish parsing before releasing input; execute only after release.
    /// PING keeps its source until the last response report completes.
    fn finish_request(&mut self, scratch: &mut impl Scratch) -> Result<(), Error> {
        if self.command == wire::CBOR {
            let mut request = ctap::Request::new();
            if self.storage == Storage::Pke {
                // Large requests leave inline storage free. Reuse it as a
                // read window instead of adding a second stack buffer.
                for offset in (0..self.total).step_by(INLINE) {
                    let n = INLINE.min(self.total - offset);
                    scratch.read(offset, &mut self.inline[..n])?;
                    request.consume(&self.inline[..n]);
                }
            } else {
                request.consume(&self.inline[..self.total]);
            }
            let command = request.finish();
            self.close_request(scratch);
            self.inline.fill(0);
            let response = ctap::execute(command);
            self.constant = Some(response);
            self.total = response.len();
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
        if self.phase == Phase::Receiving && now.wrapping_sub(self.last_received) >= TIMEOUT_MS {
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
        let tag = if self.offset == 0 {
            self.command
        } else {
            self.sequence
        };
        let payload = wire::header(out, self.cid, tag, self.total);
        let n = payload.len().min(self.total - self.offset);
        let dest = &mut payload[..n];
        if let Some(constant) = self.constant {
            dest.copy_from_slice(&constant[self.offset..self.offset + n]);
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
