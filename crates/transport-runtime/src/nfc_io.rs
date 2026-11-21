// SPDX-License-Identifier: Apache-2.0
//! IRQ-local NFC orchestration. The facade masks IRQs around every method;
//! this state never owns or calls the APDU engine or the shared APDU buffer.
#![forbid(unsafe_code)]
use super::nfc::{self, Execution, HardwareAction, Irq, Recovery, Response};
use canokey_protocol::nfc::{self as wire, Block, Packet};
/// Implementations complete IO before returning and retain no borrowed slices.
/// They must not reenter the transport runtime while its state is borrowed.
pub trait Chip {
    fn read(&mut self, address: u16, out: &mut [u8]) -> bool;
    fn write(&mut self, address: u16, bytes: &[u8]) -> bool;
}

/// Product polling policy. Methods only inspect bounded decoded blocks and
/// update private polling state; they must not call IO, applets or shared APDU
/// owners. Io performs transmission and owns the IRQ turn and mailbox.
pub trait Polling {
    const INITIAL: Self;
    type Completion;
    fn active(&self) -> bool;
    fn begin(&mut self, number: u8) -> bool;
    fn receive(&mut self, block: Block<'_>) -> Option<Packet>;
    fn status(&mut self, waiting: bool) -> bool;
    fn finish(&mut self) -> Option<Self::Completion>;
    fn clear(&mut self);
}
/// Zero-sized policy for products that use synchronous WTX execution only.
pub struct NoPolling;
impl Polling for NoPolling {
    const INITIAL: Self = Self;
    type Completion = ();
    fn active(&self) -> bool {
        false
    }
    fn begin(&mut self, _number: u8) -> bool {
        false
    }
    fn receive(&mut self, _block: Block<'_>) -> Option<Packet> {
        None
    }
    fn status(&mut self, _waiting: bool) -> bool {
        false
    }
    fn finish(&mut self) -> Option<()> {
        None
    }
    fn clear(&mut self) {}
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tx {
    Idle,
    Inline,
    Response,
    Done,
}

/// Completed RX data. The backing stays exclusive until returned to its Io.
#[must_use = "return the frame to its Io after consuming or discarding it"]
pub struct ReceivedFrame<'a, const FSC: usize> {
    backing: &'a mut [u8; FSC],
    length: u16,
    generation: u32,
}
impl<const FSC: usize> ReceivedFrame<'_, FSC> {
    pub fn bytes(&self) -> &[u8] {
        &self.backing[..usize::from(self.length)]
    }
}

pub struct Io<'a, P: Polling = NoPolling, const FSC: usize = { wire::FRAME_LIMIT }> {
    polling: P,
    recovery: Recovery,
    execution: Execution,
    computing: bool,
    turn: bool,
    // RX partial/mailbox and TX staging are mutually exclusive RF turns.
    // None during startup without backing or while the main loop owns RX.
    frame: Option<&'a mut [u8; FSC]>,
    length: u16,
    dropping: bool,
    fsd: u16,
    tx: Tx,
    tx_loaded: u8,
    tx_length: u8,
}
impl<'a, P: Polling, const FSC: usize> Io<'a, P, FSC> {
    /// A product can provide its zero-initialized frame separately from state.
    /// Pass None only until binding backing at transport startup.
    pub const fn new(now: u32, frame: Option<&'a mut [u8; FSC]>) -> Self {
        Self {
            polling: P::INITIAL,
            recovery: Recovery::new(now),
            execution: Execution::new(),
            computing: false,
            turn: false,
            frame,
            length: 0,
            dropping: false,
            fsd: 0,
            tx: Tx::Idle,
            tx_loaded: 0,
            tx_length: 0,
        }
    }
    pub fn generation(&self) -> u32 {
        self.recovery.generation()
    }
    pub fn live(&self) -> bool {
        self.execution.live()
    }
    /// Call under the same lock as the facade's generation check. Zero means
    /// the current activation has no completed RATS observation yet.
    pub fn tx_frame_limit(&self, local: usize) -> usize {
        usize::from(self.fsd).min(local)
    }
    fn clear_frame(&mut self) {
        self.length = 0;
    }
    fn discard(&mut self) {
        self.execution.cancel();
        self.polling.clear();
        self.turn = false;
        self.clear_frame();
        self.dropping = false;
        self.fsd = 0;
        self.tx = Tx::Idle;
    }
    #[cold]
    pub fn fault(&mut self) {
        self.discard();
        self.recovery.fault();
    }
    pub fn interrupt(&mut self, now: u32, chip: &mut impl Chip) {
        let mut flags = [0x00; wire::FM_IRQ_BYTES];
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
        if event == Irq::Halt && flags[0] & wire::FM_MAIN_ACTIVE != 0x00 {
            // Boot can latch an old HALT together with a later activation.
            // Preserve the new RX only when live NFC_STATE has reached RATS/PPS.
            let mut status = [0x00];
            if !chip.read(wire::FM_REG_RF_STATUS, &mut status) {
                self.fault();
                return;
            }
            if matches!(status[0] >> 4, wire::FM_STATE_RATS | wire::FM_STATE_PPS) {
                event = Irq::Activity {
                    activated: true,
                    received: flags[0] & wire::FM_MAIN_RX_DONE != 0x00,
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
                if !self.computing && flags[0] & wire::FM_MAIN_ACTIVITY != 0x00 {
                    self.recovery.activity(now);
                }
                self.transfer(flags, received, chip);
            }
        }
    }
    fn transfer(&mut self, flags: [u8; wire::FM_IRQ_BYTES], received: bool, chip: &mut impl Chip) {
        let mut water = FSC > wire::FIFO_BYTES && flags[1] & wire::FM_FIFO_WATER != 0x00;
        if matches!(self.tx, Tx::Inline | Tx::Response) {
            let done = flags[0] & wire::FM_MAIN_TX_DONE != 0x00;
            let remaining = FSC > wire::FIFO_BYTES && self.tx_loaded < self.tx_length;
            // EMPTY can be latched before TX starts. FIFO_IRQ reports TX
            // underflow through the over/underflow flag handled by nfc::irq.
            if remaining && done {
                self.fault();
                return;
            }
            if done {
                self.tx = if self.tx == Tx::Response {
                    Tx::Done
                } else {
                    Tx::Idle
                };
                // A co-latched watermark may be the final TX watermark.
                // Service it as RX only if the next frame has reached 24 B.
                if water && !received {
                    let Some(count) = fifo_count(chip) else {
                        self.fault();
                        return;
                    };
                    water = count >= wire::RX_WATERMARK;
                }
            } else {
                if received || (water && remaining && !self.refill(chip)) {
                    self.fault();
                }
                return;
            }
        }
        if (received || water) && !self.receive_fifo(received, chip) {
            self.fault();
        }
    }
    fn receive_fifo(&mut self, done: bool, chip: &mut impl Chip) -> bool {
        // RX_DONE takes precedence over a co-latched watermark. Reading the
        // actual count once avoids consuming the same FIFO bytes twice.
        let count = if done {
            let Some(count) = fifo_count(chip) else {
                return false;
            };
            count
        } else {
            wire::RX_WATERMARK
        };
        let busy = self.turn || (FSC > wire::FIFO_BYTES && self.dropping);
        let (Some(frame), false) = (self.frame.as_deref_mut(), busy) else {
            if FSC > wire::FIFO_BYTES {
                let had_partial = self.dropping;
                self.dropping = !done;
                if count == 0 {
                    return had_partial;
                }
            }
            return count != 0 && drain_fifo(count, chip);
        };
        let start = if FSC > wire::FIFO_BYTES {
            usize::from(self.length)
        } else {
            0
        };
        let end = start + count;
        let Some(frame) = frame.get_mut(..end) else {
            return false;
        };
        let chunk = &mut frame[start..];
        if !chunk.is_empty() && !chip.read(wire::FM_REG_FIFO_ACCESS, chunk) {
            return false;
        }
        self.length = end as u16;
        if !done {
            return true;
        }
        if end < wire::FRAME_OVERHEAD {
            return false;
        }
        if self.fsd == 0 {
            let mut rats = [0x00];
            // In Level-4 mode the frontend handles RATS/ATS and PPS itself.
            // Latch FSDI only when the first post-RATS data frame completes.
            if !chip.read(wire::FM_REG_RF_RATS, &mut rats) {
                return false;
            }
            self.fsd = wire::reader_frame_size(rats[0]) as u16;
        }
        match &*frame {
            &[wire::PCB_WTX, multiplier, _, _] => {
                self.clear_frame();
                self.turn = self.execution.echo(multiplier);
                return self.turn;
            }
            [wire::PCB_DESELECT, _, _] => {
                // Cancel the current execution but retain the request so the
                // main loop can echo deselect after its Core borrow returns.
                self.execution.cancel();
            }
            frame if self.polling.active() => {
                let packet = wire::decode(frame)
                    .ok()
                    .and_then(|block| self.polling.receive(block));
                self.clear_frame();
                self.poll_response(packet, chip);
                return true;
            }
            _ if self.execution.live() => return false,
            _ => {}
        }
        self.turn = true;
        true
    }
    fn poll_response(&mut self, packet: Option<Packet>, chip: &mut impl Chip) {
        let Some(packet) = packet else {
            self.fault();
            return;
        };
        self.turn = true;
        if !self.send(&packet, chip) {
            self.fault();
        }
    }
    /// Start only after the initial pending reply has been transmitted. A
    /// reader poll queued before the IRQ lock is processed exactly once here.
    pub fn begin_polling(&mut self, now: u32, number: u8, chip: &mut impl Chip) {
        if !self.polling.begin(number) {
            self.fault();
            return;
        }
        self.computing = true;
        self.execution.begin(now);
        if self.turn && self.length != 0 {
            let length = usize::from(self.length);
            let packet = wire::decode(&self.frame.as_deref().unwrap()[..length])
                .ok()
                .and_then(|block| self.polling.receive(block));
            self.clear_frame();
            self.poll_response(packet, chip);
        }
    }
    pub fn polling_status(&mut self, waiting: bool) -> bool {
        self.polling.status(waiting)
    }
    pub fn end_polling(&mut self, now: u32) -> Option<P::Completion> {
        self.computing = false;
        let _ = self.execution.finish();
        self.recovery.activity(now);
        self.polling.finish()
    }
    /// Copy a validated mailbox for callers that supply their own frame buffer.
    pub fn take(&mut self, out: &mut [u8; FSC]) -> Option<usize> {
        let frame = self.take_frame()?;
        let n = frame.bytes().len();
        out[..n].copy_from_slice(frame.bytes());
        self.return_frame(frame);
        Some(n)
    }
    /// Transfer the validated mailbox to the main loop under the IRQ lock.
    /// Even a new activation must drain incoming FIFO data during the loan.
    pub fn take_frame(&mut self) -> Option<ReceivedFrame<'a, FSC>> {
        if !self.turn || self.length == 0 || self.recovery.drain_only() {
            return None;
        }
        let received = ReceivedFrame {
            backing: self.frame.take()?,
            length: self.length,
            generation: self.generation(),
        };
        self.clear_frame();
        Some(received)
    }
    /// Reattach to the issuing Io under the IRQ lock. A false result revokes
    /// the frame's effects: the caller must suppress its event and reset its
    /// old link/request through the regular generation-change path.
    pub fn return_frame(&mut self, frame: ReceivedFrame<'a, FSC>) -> bool {
        debug_assert!(self.frame.is_none());
        self.frame = Some(frame.backing);
        self.generation() == frame.generation
    }
    /// An unsolicited ACK consumes no response bytes and needs no reply.
    /// Release only the connection that supplied the consumed mailbox. An RF
    /// activation IRQ between take and this call may already own a new turn.
    pub fn ignored(&mut self, generation: u32) {
        if self.generation() == generation {
            self.turn = false;
        }
    }
    /// Inline packets fit in the first FIFO load.
    pub fn send(&mut self, packet: &Packet, chip: &mut impl Chip) -> bool {
        if !self.can_send() {
            return false;
        }
        if !start_fifo(packet.bytes(), chip) {
            self.fault();
            return false;
        }
        self.turn = false;
        if FSC > wire::FIFO_BYTES {
            self.tx = Tx::Inline;
            self.tx_loaded = 0;
            self.tx_length = 0;
        }
        true
    }
    /// Copy the I-block into owned staging before arming TX. IRQs never
    /// borrow APDU backing and no call waits for a future FIFO interrupt.
    pub fn send_response(&mut self, response: Response, inf: &[u8], chip: &mut impl Chip) -> bool {
        let length = inf.len() + 1;
        if !self.can_send()
            || inf.len() != usize::from(response.length)
            || length + 2 > self.tx_frame_limit(FSC)
        {
            return false;
        }
        let frame = self.frame.as_deref_mut().unwrap();
        let Some((pcb, payload)) = frame.get_mut(..length).and_then(<[u8]>::split_first_mut) else {
            return false;
        };
        *pcb = response.pcb;
        payload.copy_from_slice(inf);

        let initial = length.min(wire::FIFO_BYTES);
        if (length > wire::FIFO_BYTES && !chip.write(wire::FM_REG_FIFO_CLEAR, &[0x00]))
            || !start_fifo(&frame[..initial], chip)
        {
            self.fault();
            return false;
        }
        self.turn = false;
        self.tx = Tx::Response;
        if FSC > wire::FIFO_BYTES {
            self.tx_loaded = initial as u8;
            self.tx_length = length as u8;
        }
        true
    }
    fn can_send(&self) -> bool {
        self.turn
            && self.length == 0
            && self.frame.is_some()
            && (FSC <= wire::FIFO_BYTES || !self.dropping)
            && self.tx == Tx::Idle
    }
    fn refill(&mut self, chip: &mut impl Chip) -> bool {
        let start = usize::from(self.tx_loaded);
        let end = (start + wire::FIFO_BYTES - wire::TX_WATERMARK).min(usize::from(self.tx_length));
        if !chip.write(
            wire::FM_REG_FIFO_ACCESS,
            &self.frame.as_deref().unwrap()[start..end],
        ) {
            return false;
        }
        self.tx_loaded = end as u8;
        true
    }
    pub fn take_tx_done(&mut self) -> bool {
        if self.tx != Tx::Done {
            return false;
        }
        self.tx = Tx::Idle;
        true
    }
    pub fn begin_execution(&mut self, now: u32) -> bool {
        if !self.turn || self.length != 0 || self.frame.is_none() || self.recovery.drain_only() {
            return false;
        }
        self.computing = true;
        self.execution.begin(now);
        true
    }
    pub fn tick(&mut self, now: u32, chip: &mut impl Chip) {
        if !self.polling.active() && self.computing && self.turn && self.execution.due(now) {
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
        let dirty = link_dirty
            || self.length != 0
            || (FSC > wire::FIFO_BYTES && self.dropping)
            || self.turn
            || self.tx != Tx::Idle
            || self.execution.live();
        let action = self.recovery.poll(now, dirty, self.computing);
        if generation != self.generation() {
            self.discard();
        }
        if let Some(action) = action {
            let ok = match action.operation {
                HardwareAction::Silence => {
                    chip.write(wire::FM_REG_RESET_SILENCE, &[wire::FM_SILENCE])
                        && chip.write(wire::FM_REG_FIFO_CLEAR, &[0x00])
                }
                HardwareAction::Unsilence => {
                    chip.write(wire::FM_REG_RESET_SILENCE, &[wire::FM_UNSILENCE])
                }
                HardwareAction::ConfigureInterrupts => {
                    let fifo_mask = if FSC > wire::FIFO_BYTES {
                        wire::FM_FIFO_IRQ_MASK
                    } else {
                        wire::FM_FIFO_IRQ_MASK | wire::FM_FIFO_WATER
                    };
                    chip.write(
                        wire::FM_REG_MAIN_IRQ_MASK,
                        &[wire::FM_MAIN_IRQ_MASK, fifo_mask],
                    )
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

fn start_fifo(bytes: &[u8], chip: &mut impl Chip) -> bool {
    chip.write(wire::FM_REG_FIFO_ACCESS, bytes)
        && chip.write(wire::FM_REG_RF_TXEN, &[wire::FM_RF_TX_ENABLE])
}

fn fifo_count(chip: &mut impl Chip) -> Option<usize> {
    let mut count = [0x00];
    if !chip.read(wire::FM_REG_FIFO_WORDCNT, &mut count) {
        return None;
    }
    let count = usize::from(count[0] & wire::FM_FIFO_WORDCNT_MASK);
    (count <= wire::FIFO_BYTES).then_some(count)
}

// Early input may not overwrite a live mailbox. Keep this disjoint drain
// scratch out of the ordinary decode/polling path and its IRQ stack frame.
#[inline(never)]
fn drain_fifo(length: usize, chip: &mut impl Chip) -> bool {
    let mut discarded = [0x00; wire::FIFO_BYTES];
    chip.read(wire::FM_REG_FIFO_ACCESS, &mut discarded[..length])
}
