// SPDX-License-Identifier: Apache-2.0
//! WTX execution and RF recovery without APDU or hardware ownership.
use canokey_protocol::nfc;

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
        self.live()
            && !self.waiting
            && now.wrapping_sub(self.last) >= u32::from(nfc::WTX_INTERVAL_MS)
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

/// Decode latched error/overflow/HALT priority. The product IRQ facade resolves
/// chip activation observations before applying this event to its mailbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Irq {
    Fault,
    Halt,
    Activity { activated: bool, received: bool },
}
pub fn irq(flags: [u8; nfc::FM_IRQ_BYTES]) -> Irq {
    if flags[2] & nfc::FM_AUX_ERRORS != 0x00 || flags[1] & nfc::FM_FIFO_OVERFLOW != 0x00 {
        Irq::Fault
    } else if flags[2] & nfc::FM_AUX_HALT != 0x00 {
        Irq::Halt
    } else {
        Irq::Activity {
            activated: flags[0] & nfc::FM_MAIN_ACTIVE != 0x00,
            received: flags[0] & nfc::FM_MAIN_RX_DONE != 0x00,
        }
    }
}
