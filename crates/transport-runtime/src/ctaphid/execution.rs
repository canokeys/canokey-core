// SPDX-License-Identifier: Apache-2.0
//! Transport-only execution progress; no application, scratch or endpoint IO.
use super::{INVALID_CHANNEL, KEEPALIVE_INTERVAL_MS};
use canokey_protocol::ctaphid::{self as wire, Error, REPORT_SIZE, Report};
use core::marker::PhantomData;

pub trait ExecutionPolicy {
    const MALFORMED_INIT_ERROR: Error;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Continue,
    Cancelled,
    Disconnected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incoming {
    Consume,
    Retain,
    Error(Error),
}
/// Header classification is also used while a foreign transport owns Core.
/// A continuation cannot start another command and is drained by the facade.
pub fn classify_error<P: ExecutionPolicy>(cid: u32, command: u8, executing: Option<u32>) -> Error {
    if cid == INVALID_CHANNEL || (cid == wire::BROADCAST && command != wire::INIT) {
        Error::Channel
    } else if executing == Some(cid) && command == wire::INIT {
        P::MALFORMED_INIT_ERROR
    } else {
        Error::Busy
    }
}
/// Foreign CANCEL cannot cancel the active card operation. Continuations cannot
/// start a command; both are drained silently. Other initial headers get only a
/// transport error, without parsing a body or acquiring the application owner.
#[inline]
pub fn foreign_error<P: ExecutionPolicy>(cid: u32, command: u8) -> Option<Error> {
    if command & wire::CMD_INIT_BIT != 0x00 && command != wire::CANCEL {
        Some(classify_error::<P>(cid, command, None))
    } else {
        None
    }
}
pub struct Execution<P: ExecutionPolicy> {
    cid: u32,
    epoch: u32,
    keepalive_at: u32,
    cancelled: bool,
    abandoned: bool,
    policy: PhantomData<P>,
}
impl<P: ExecutionPolicy> Execution<P> {
    /// An inactive facade retains cancellation/abandonment until its main loop
    /// has released the suppressed reply and serviced the queued INIT.
    pub const fn inactive() -> Self {
        Self::new(INVALID_CHANNEL, 0, KEEPALIVE_INTERVAL_MS)
    }
    /// Live executions use an admitted nonzero CID; zero is the inactive sentinel.
    pub const fn new(cid: u32, epoch: u32, now: u32) -> Self {
        Self {
            cid,
            epoch,
            keepalive_at: now.wrapping_sub(KEEPALIVE_INTERVAL_MS),
            cancelled: false,
            abandoned: false,
            policy: PhantomData,
        }
    }
    pub fn executing(&self) -> bool {
        self.cid != INVALID_CHANNEL
    }
    pub fn cid(&self) -> u32 {
        self.cid
    }
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }
    pub fn abandoned(&self) -> bool {
        self.abandoned
    }
    pub fn abandon(&mut self) {
        self.abandoned = true;
    }
    pub fn clear_abandonment(&mut self) {
        self.abandoned = false;
    }
    pub fn end(&mut self) {
        self.cid = INVALID_CHANNEL;
    }
    pub fn receive(&mut self, bytes: &[u8; REPORT_SIZE]) -> Incoming {
        let report = Report::decode(bytes);
        self.receive_header(report.cid, report.tag, report.length)
    }
    /// Main-loop progress may peek just the seven-byte initial header while
    /// crypto holds the applet stack. Classification cannot dispatch or reset it.
    pub fn receive_header(&mut self, cid: u32, command: u8, length: Option<usize>) -> Incoming {
        if cid == self.cid && command == wire::INIT && length == Some(wire::INIT_NONCE_BYTES) {
            self.abandoned = true;
            Incoming::Retain
        } else if cid == self.cid && command == wire::CANCEL && length == Some(0) {
            self.cancelled = true;
            Incoming::Consume
        } else if length.is_some() {
            Incoming::Error(classify_error::<P>(cid, command, Some(self.cid)))
        } else {
            Incoming::Consume
        }
    }
    pub fn progress(&self, epoch: u32, configured: bool) -> Progress {
        if self.abandoned || self.epoch != epoch || !configured {
            Progress::Disconnected
        } else if self.cancelled {
            Progress::Cancelled
        } else {
            Progress::Continue
        }
    }
    pub fn keepalive_due(&self, now: u32) -> bool {
        !self.cancelled
            && !self.abandoned
            && now.wrapping_sub(self.keepalive_at) >= KEEPALIVE_INTERVAL_MS
    }
    /// Timestamp publication belongs to the facade's send point. Facades with
    /// synchronous endpoint IO may update it after the send returns.
    pub fn keepalive_sent(&mut self, now: u32) {
        self.keepalive_at = now;
    }
    pub fn keepalive(&mut self, now: u32, waiting: bool, output: &mut [u8; REPORT_SIZE]) -> bool {
        if !self.keepalive_due(now) {
            return false;
        }
        wire::header(output, self.cid, wire::KEEPALIVE, 1)[0] = if waiting {
            wire::STATUS_UPNEEDED
        } else {
            wire::STATUS_PROCESSING
        };
        self.keepalive_sent(now);
        true
    }
}
