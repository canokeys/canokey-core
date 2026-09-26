// SPDX-License-Identifier: Apache-2.0
//! IRQ-local NFC orchestration. The facade masks IRQs around every method;
//! this state never owns or calls the APDU engine or the shared APDU buffer.
#![forbid(unsafe_code)]
use super::nfc::{self, Execution, HardwareAction, Irq, Recovery};
use canokey_protocol::nfc::{self as wire, Block, Packet};
pub trait Chip {
    fn read(&mut self, address: u16, out: &mut [u8]) -> bool;
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool;
}
pub struct Io {
    recovery: Recovery,
    execution: Execution,
    computing: bool,
    turn: bool,
    frame: [u8; 32],
    length: u8,
}
impl Io {
    pub const fn new(now: u32) -> Self {
        Self {
            recovery: Recovery::new(now),
            execution: Execution::new(),
            computing: false,
            turn: false,
            frame: [0; 32],
            length: 0,
        }
    }
    pub fn generation(&self) -> u32 {
        self.recovery.generation()
    }
    pub fn live(&self) -> bool {
        self.execution.live()
    }
    fn discard(&mut self) {
        self.execution.cancel();
        self.turn = false;
        self.length = 0;
    }
    pub fn fault(&mut self) {
        self.discard();
        self.recovery.fault();
    }
    pub fn interrupt(&mut self, now: u32, chip: &mut impl Chip) {
        let mut flags = [0; 3];
        if !chip.read(0xfff7, &mut flags) {
            if !self.recovery.drain_only() {
                self.fault();
            }
            return;
        }
        if self.recovery.drain_only() {
            return;
        }
        match nfc::irq(flags) {
            Irq::Fault => {
                self.fault();
                return;
            }
            Irq::Halt => {
                self.discard();
                self.recovery.activated(now);
                return;
            }
            Irq::Activity {
                activated,
                received,
            } => {
                if activated {
                    self.discard();
                    self.recovery.activated(now);
                }
                if !self.computing && flags[0] & 0x3f != 0 {
                    self.recovery.activity(now);
                }
                if !received {
                    return;
                }
            }
        }
        let mut size = [0];
        if !chip.read(0xfff2, &mut size) || !(3..=32).contains(&size[0]) {
            self.fault();
            return;
        }
        // Never overwrite an unconsumed main-loop mailbox.
        if self.length != 0 {
            self.fault();
            return;
        }
        if !chip.read(0xfff0, &mut self.frame[..size[0] as usize]) {
            self.fault();
            return;
        }
        match wire::decode(&self.frame[..size[0] as usize]) {
            Ok(Block::Waiting(multiplier)) => {
                if self.execution.echo(multiplier) {
                    self.turn = true;
                } else {
                    self.fault();
                }
            }
            Ok(Block::Deselect) => {
                // Cancel the current execution but retain the request so the
                // main loop can echo deselect after its Core borrow returns.
                self.execution.cancel();
                self.length = size[0];
                self.turn = true;
            }
            Ok(_) if self.execution.live() => self.fault(),
            Ok(_) => {
                self.length = size[0];
                self.turn = true;
            }
            Err(_) => self.fault(),
        }
    }
    pub fn take(&mut self, out: &mut [u8; 32]) -> Option<usize> {
        if self.length == 0 || self.recovery.drain_only() {
            return None;
        }
        let n = self.length as usize;
        out[..n].copy_from_slice(&self.frame[..n]);
        self.length = 0;
        Some(n)
    }
    /// Copy into the chip FIFO synchronously. The bus adapter must not retain
    /// packet bytes or call Rust recursively while this method borrows state.
    pub fn send(&mut self, packet: &Packet, chip: &mut impl Chip) -> bool {
        if !self.turn || self.recovery.drain_only() {
            return false;
        }
        if !chip.write(0xfff0, packet.bytes()) || !chip.write(0xfff4, &[0x55]) {
            self.fault();
            return false;
        }
        self.turn = false;
        true
    }
    pub fn begin_execution(&mut self, now: u32) -> bool {
        if !self.turn || self.length != 0 || self.recovery.drain_only() {
            return false;
        }
        self.computing = true;
        self.execution.begin(now);
        true
    }
    pub fn tick(&mut self, now: u32, chip: &mut impl Chip) {
        if self.computing && self.turn && self.execution.due(now) {
            let packet = Packet::waiting(1).unwrap();
            if self.send(&packet, chip) {
                self.execution.sent(now);
            }
        }
    }
    /// Called after Core returns. A pending WTX echo may still own the RF turn;
    /// the main loop retries complete_execution without rerunning the APDU.
    pub fn computed(&mut self, now: u32) {
        self.computing = false;
        self.recovery.activity(now);
    }
    pub fn complete_execution(&mut self) -> Option<bool> {
        self.execution.finish()
    }
    /// Main-loop recovery. A lost WTX echo is dirty once Core has returned, so
    /// the ordinary 200 ms recovery window bounds the response wait as well.
    pub fn poll(&mut self, now: u32, link_dirty: bool, chip: &mut impl Chip) {
        let generation = self.generation();
        let dirty = link_dirty || self.length != 0 || self.turn || self.execution.live();
        let action = self.recovery.poll(now, dirty, self.computing);
        if generation != self.generation() {
            self.discard();
        }
        if let Some(action) = action {
            let ok = match action.operation {
                HardwareAction::Silence => chip.write(0xffe6, &[0x33]),
                HardwareAction::Unsilence => chip.write(0xffe6, &[0xcc]),
                HardwareAction::ConfigureInterrupts => chip.write(0xfffa, &[0x22]),
            };
            self.recovery.completed(action, ok, now);
            if ok && action.operation == HardwareAction::Silence {
                // Failed masking is covered by drain-only IRQ handling.
                let _ = chip.write(0xfffa, &[0]);
            }
        }
    }
}
