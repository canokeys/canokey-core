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
    frame: [u8; wire::FRAME_LIMIT],
    length: u8,
}
impl Io {
    pub const fn new(now: u32) -> Self {
        Self {
            recovery: Recovery::new(now),
            execution: Execution::new(),
            computing: false,
            turn: false,
            frame: [0; wire::FRAME_LIMIT],
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
        let mut flags = [0; wire::FM_IRQ_BYTES];
        if !chip.read(wire::FM_REG_MAIN_IRQ, &mut flags) {
            if !self.recovery.drain_only() {
                self.fault();
            }
            return;
        }
        if self.recovery.drain_only() {
            return;
        }
        let mut event = nfc::irq(flags);
        if event == Irq::Halt && flags[0] & wire::FM_MAIN_ACTIVE != 0 {
            // Boot can latch an old HALT together with a later activation.
            // Preserve the new RX only when live NFC_STATE has reached RATS/PPS.
            let mut status = [0];
            if !chip.read(wire::FM_REG_RF_STATUS, &mut status) {
                self.fault();
                return;
            }
            if matches!(status[0] >> 4, wire::FM_STATE_RATS | wire::FM_STATE_PPS) {
                event = Irq::Activity {
                    activated: true,
                    received: flags[0] & wire::FM_MAIN_RX_DONE != 0,
                };
            }
        }
        match event {
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
                if !self.computing && flags[0] & wire::FM_MAIN_ACTIVITY != 0 {
                    self.recovery.activity(now);
                }
                if !received {
                    return;
                }
            }
        }
        let mut size = [0];
        if !chip.read(wire::FM_REG_FIFO_WORDCNT, &mut size)
            || size[0] == 0
            || usize::from(size[0]) > wire::FRAME_LIMIT
        {
            self.fault();
            return;
        }
        let mut frame = [0; wire::FRAME_LIMIT];
        let frame = &mut frame[..usize::from(size[0])];
        if !chip.read(wire::FM_REG_FIFO_ACCESS, frame) {
            self.fault();
            return;
        }
        // The current input owns its reply turn until a response or WTX is
        // transmitted. Drain early reader traffic even while Core runs; only
        // an IRQ error/field event may revoke that turn before transmission.
        if self.turn {
            return;
        }
        match wire::decode(frame) {
            Ok(Block::Waiting(multiplier)) => {
                if self.execution.echo(multiplier) {
                    self.turn = true;
                } else {
                    self.fault();
                }
                return;
            }
            Ok(Block::Deselect) => {
                // Cancel the current execution but retain the request so the
                // main loop can echo deselect after its Core borrow returns.
                self.execution.cancel();
            }
            Ok(_) if self.execution.live() => {
                self.fault();
                return;
            }
            Ok(_) => {}
            Err(_) => {
                self.fault();
                return;
            }
        }
        self.frame[..frame.len()].copy_from_slice(frame);
        self.length = size[0];
        self.turn = true;
    }
    pub fn take(&mut self, out: &mut [u8; wire::FRAME_LIMIT]) -> Option<usize> {
        if self.length == 0 || self.recovery.drain_only() {
            return None;
        }
        let n = self.length as usize;
        out[..n].copy_from_slice(&self.frame[..n]);
        self.length = 0;
        Some(n)
    }
    /// An unsolicited ACK consumes no response bytes and needs no reply.
    /// Release its turn so subsequent reader input can become the mailbox.
    pub fn ignored(&mut self) {
        self.turn = false;
    }
    /// Copy into the chip FIFO synchronously. The bus adapter must not retain
    /// packet bytes or call Rust recursively while this method borrows state.
    pub fn send(&mut self, packet: &Packet, chip: &mut impl Chip) -> bool {
        if !self.turn || self.recovery.drain_only() {
            return false;
        }
        if !chip.write(wire::FM_REG_FIFO_ACCESS, packet.bytes())
            || !chip.write(wire::FM_REG_RF_TXEN, &[wire::FM_RF_TX_ENABLE])
        {
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
                HardwareAction::Silence => {
                    chip.write(wire::FM_REG_RESET_SILENCE, &[wire::FM_SILENCE])
                }
                HardwareAction::Unsilence => {
                    chip.write(wire::FM_REG_RESET_SILENCE, &[wire::FM_UNSILENCE])
                }
                HardwareAction::ConfigureInterrupts => {
                    chip.write(wire::FM_REG_MAIN_IRQ_MASK, &[wire::FM_MAIN_IRQ_MASK])
                }
            };
            self.recovery.completed(action, ok, now);
            if ok && action.operation == HardwareAction::Silence {
                // Failed masking is covered by drain-only IRQ handling.
                let _ = chip.write(wire::FM_REG_MAIN_IRQ_MASK, &[wire::FM_MAIN_IRQ_MASK_ALL]);
            }
        }
    }
}
