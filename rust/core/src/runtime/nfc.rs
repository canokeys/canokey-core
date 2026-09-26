// SPDX-License-Identifier: Apache-2.0
//! NFC block lifecycle. APDU storage belongs to the shared transport workspace;
//! this state retains only one 30-byte packet for retransmission.
#![forbid(unsafe_code)]
use canokey_protocol::nfc::{self, Block, Packet};
pub const COMMAND_LIMIT: usize = 261;
pub const MAX_RETRANSMITS: u8 = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Wire(nfc::Error),
    Busy,
    Overflow,
    Sequence,
    Retransmits,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Send(Packet),
    Execute(usize),
    NextResponse,
    Waiting(u8),
    Deselect,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Receiving,
    Executing,
    Responding,
    Ready,
    Complete,
}
pub struct Link {
    phase: Phase,
    number: u8,
    received: usize,
    cached: Option<Packet>,
    retransmits: u8,
    pending: bool,
}
impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}
impl Link {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Receiving,
            number: 1,
            received: 0,
            cached: None,
            retransmits: 0,
            pending: false,
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    pub fn dirty(&self) -> bool {
        self.received != 0
            || self.pending
            || matches!(
                self.phase,
                Phase::Executing | Phase::Responding | Phase::Ready
            )
    }
    fn retransmit(&mut self) -> Result<Event, Error> {
        if self.pending {
            return Err(Error::Busy);
        }
        let packet = self.cached.ok_or(Error::Sequence)?;
        if self.retransmits >= MAX_RETRANSMITS {
            return Err(Error::Retransmits);
        }
        self.retransmits += 1;
        Ok(Event::Send(packet))
    }
    /// Called on the main-loop side, never while Core borrows `input`.
    /// CRC/error IRQs must be checked before presenting a FIFO frame here.
    pub fn receive(&mut self, frame: &[u8], input: &mut [u8]) -> Result<Event, Error> {
        match nfc::decode(frame).map_err(Error::Wire)? {
            Block::Waiting(m) => Ok(Event::Waiting(m)),
            Block::Deselect => {
                self.reset();
                Ok(Event::Deselect)
            }
            Block::Information {
                number,
                chained,
                bytes,
            } => {
                if self.pending || matches!(self.phase, Phase::Executing | Phase::Ready) {
                    return Err(Error::Busy);
                }
                if number == self.number {
                    // Repeated command blocks must never execute/write twice.
                    return if self.received != 0 {
                        Ok(Event::Send(Packet::acknowledgement(self.number)))
                    } else {
                        self.retransmit()
                    };
                }
                if matches!(self.phase, Phase::Responding | Phase::Ready) {
                    return Err(Error::Sequence);
                }
                let end = self
                    .received
                    .checked_add(bytes.len())
                    .ok_or(Error::Overflow)?;
                if end > COMMAND_LIMIT || end > input.len() {
                    return Err(Error::Overflow);
                }
                input[self.received..end].copy_from_slice(bytes);
                self.received = end;
                self.number = number;
                self.cached = None;
                self.retransmits = 0;
                if chained {
                    self.phase = Phase::Receiving;
                    Ok(Event::Send(Packet::acknowledgement(number)))
                } else {
                    self.phase = Phase::Executing;
                    Ok(Event::Execute(end))
                }
            }
            Block::Receive { number, negative } => {
                if self.pending || matches!(self.phase, Phase::Executing | Phase::Ready) {
                    return Err(Error::Busy);
                }
                if number == self.number {
                    return self.retransmit();
                }
                if self.phase == Phase::Responding {
                    self.number = number;
                    self.phase = Phase::Ready;
                    Ok(Event::NextResponse)
                } else if negative {
                    Ok(Event::Send(Packet::acknowledgement(self.number)))
                } else {
                    Err(Error::Sequence)
                }
            }
        }
    }
    /// `remaining` is the current response chunk, not a second owned buffer.
    /// `more_chunks` means another engine GET RESPONSE chunk follows this one.
    /// Advance the caller's response cursor only after successful FIFO delivery.
    pub fn response(&mut self, remaining: &[u8], more_chunks: bool) -> Result<Packet, Error> {
        if self.pending || !matches!(self.phase, Phase::Executing | Phase::Ready) {
            return Err(Error::Busy);
        }
        let n = remaining.len().min(nfc::INF_LIMIT);
        let chained = remaining.len() > n || more_chunks;
        let packet =
            Packet::information(self.number, chained, &remaining[..n]).map_err(Error::Wire)?;
        self.cached = Some(packet);
        self.pending = true;
        Ok(packet)
    }
    /// Commit only the initial send, not a retransmission. On hardware failure
    /// reset the link and start recovery instead of committing a phantom packet.
    pub fn sent(&mut self) -> Result<usize, Error> {
        if !self.pending {
            return Err(Error::Sequence);
        }
        let bytes = self.cached.as_ref().ok_or(Error::Sequence)?.bytes();
        self.phase = if bytes[0] & 0x10 != 0 {
            Phase::Responding
        } else {
            Phase::Complete
        };
        let n = bytes.len() - 1;
        self.pending = false;
        self.received = 0;
        self.retransmits = 0;
        Ok(n)
    }
}

/// IRQ-local WTX scheduling is separate from the APDU/link borrow. A successful
/// WTX consumes the reader's turn until its matching echo arrives. Timer/field
/// events may cancel execution but cannot reset Core from IRQ context.
pub struct Execution {
    running: bool,
    live: bool,
    waiting: bool,
    last: u32,
}
impl Default for Execution {
    fn default() -> Self {
        Self::new()
    }
}
impl Execution {
    pub const fn new() -> Self {
        Self {
            running: false,
            live: false,
            waiting: false,
            last: 0,
        }
    }
    pub fn begin(&mut self, now: u32) {
        self.running = true;
        self.live = true;
        self.waiting = false;
        self.last = now;
    }
    pub fn cancel(&mut self) {
        self.live = false;
    }
    pub fn live(&self) -> bool {
        self.running && self.live
    }
    pub fn due(&self, now: u32) -> bool {
        self.live() && !self.waiting && now.wrapping_sub(self.last) >= 150
    }
    pub fn sent(&mut self, now: u32) {
        self.waiting = true;
        self.last = now;
    }
    pub fn echo(&mut self, multiplier: u8) -> bool {
        if !self.live() || !self.waiting || multiplier != 1 {
            return false;
        }
        self.waiting = false;
        true
    }
    pub fn can_reply(&self) -> bool {
        self.live() && !self.waiting
    }
    /// A completed APDU still waits for a pending WTX echo before using the
    /// RF transmit turn. Cancellation may unwind immediately without sending.
    pub fn finish(&mut self) -> Option<bool> {
        let live = self.live();
        if live && self.waiting {
            return None;
        }
        self.running = false;
        Some(live)
    }
}

pub const RECOVERY_PERIOD: u32 = 200;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareAction {
    Silence,
    Unsilence,
    ConfigureInterrupts,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryAction {
    pub operation: HardwareAction,
    generation: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryPhase {
    Active,
    SilenceRequested,
    Silenced,
    UnsilenceRequested,
}
/// Portable RF recovery policy. Hardware performs register writes and reports
/// their outcome; it never decides whether to reset a protocol session. Failed
/// silence/unsilence writes retry without admitting intervening reader traffic.
pub struct Recovery {
    phase: RecoveryPhase,
    generation: u32,
    last_activity: u32,
    configure: bool,
}
impl Recovery {
    pub const fn new(now: u32) -> Self {
        Self {
            phase: RecoveryPhase::Active,
            generation: 0,
            last_activity: now,
            configure: true,
        }
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    /// During forced recovery the IRQ must drain chip flags but must not
    /// publish a frame or let ACTIVE/HALT interrupt the silence interval.
    pub fn drain_only(&self) -> bool {
        self.phase != RecoveryPhase::Active
    }
    pub fn activity(&mut self, now: u32) {
        if !self.drain_only() {
            self.last_activity = now;
        }
    }
    pub fn activated(&mut self, now: u32) -> bool {
        if self.drain_only() {
            return false;
        }
        self.generation = self.generation.wrapping_add(1);
        self.last_activity = now;
        true
    }
    pub fn fault(&mut self) {
        if !self.drain_only() {
            // Revoke in-flight APDU/TX before touching hardware. Keeping this
            // latch through a NACK avoids resetting to a falsely clean state.
            self.generation = self.generation.wrapping_add(1);
            self.phase = RecoveryPhase::SilenceRequested;
        }
    }
    /// Main-loop only. Clean idle sessions preserve block number/retransmit
    /// state; ordinary timeout must not simulate removal of an active card.
    pub fn poll(&mut self, now: u32, dirty: bool, executing: bool) -> Option<RecoveryAction> {
        if self.phase == RecoveryPhase::Active
            && !executing
            && now.wrapping_sub(self.last_activity) >= RECOVERY_PERIOD
        {
            if dirty {
                self.fault();
            } else {
                self.last_activity = now;
            }
        }
        if self.phase == RecoveryPhase::Silenced
            && now.wrapping_sub(self.last_activity) >= RECOVERY_PERIOD
        {
            self.phase = RecoveryPhase::UnsilenceRequested;
        }
        let operation = match self.phase {
            RecoveryPhase::SilenceRequested => HardwareAction::Silence,
            RecoveryPhase::UnsilenceRequested => HardwareAction::Unsilence,
            RecoveryPhase::Active if self.configure => HardwareAction::ConfigureInterrupts,
            _ => return None,
        };
        Some(RecoveryAction {
            operation,
            generation: self.generation,
        })
    }
    /// Return false for stale completions. Masking chip interrupts after a
    /// successful silence is best effort: drain_only remains the fallback if
    /// that independent hardware write fails.
    pub fn completed(&mut self, action: RecoveryAction, success: bool, now: u32) -> bool {
        if action.generation != self.generation {
            return false;
        }
        let valid = matches!(
            (self.phase, action.operation),
            (RecoveryPhase::Active, HardwareAction::ConfigureInterrupts)
                | (RecoveryPhase::SilenceRequested, HardwareAction::Silence)
                | (RecoveryPhase::UnsilenceRequested, HardwareAction::Unsilence)
        );
        if !valid {
            return false;
        }
        if success {
            match action.operation {
                HardwareAction::ConfigureInterrupts => self.configure = false,
                HardwareAction::Silence => {
                    self.phase = RecoveryPhase::Silenced;
                    self.last_activity = now;
                }
                HardwareAction::Unsilence => {
                    self.phase = RecoveryPhase::Active;
                    self.configure = true;
                    self.last_activity = now;
                }
            }
        }
        true
    }
}

/// The adapter reads the three IRQ registers without interpreting protocol
/// policy. This priority matches the production error/overflow/halt ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Irq {
    Fault,
    Halt,
    Activity { activated: bool, received: bool },
}
pub fn irq(flags: [u8; 3]) -> Irq {
    if flags[2] & 0x78 != 0 || flags[1] & 4 != 0 {
        Irq::Fault
    } else if flags[2] & 4 != 0 {
        Irq::Halt
    } else {
        Irq::Activity {
            activated: flags[0] & 0x40 != 0,
            received: flags[0] & 0x10 != 0,
        }
    }
}
